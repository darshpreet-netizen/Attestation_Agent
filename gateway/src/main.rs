use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Default)]
struct AppState {
    seen_nonces: Arc<Mutex<HashSet<String>>>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AttestationReport {
    pub payload: BTreeMap<String, String>,
    pub timestamp: u64,
    pub nonce_hex: String,
    pub state_sha256: String,
    pub public_key_hex: String,
    pub signature_hex: String,
    pub device_status: String,
}

#[derive(Serialize)]
pub struct GatewayResponse {
    pub status: String,
    pub session_token: Option<String>,
    pub reason: String,
}

#[tokio::main]
async fn main() {
    let state = AppState::default();

    let app = Router::new()
        .route("/api/v1/attest", post(verify_attestation))
        .with_state(state);

    println!("===========================================================");
    println!("  🛡️  VERIFICATION GATEWAY SERVER ONLINE v0.1.0");
    println!("  Listening on: http://127.0.0.1:3000/api/v1/attest");
    println!("  Awaiting Attestation Handshakes...");
    println!("===========================================================\n");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn verify_attestation(
    State(state): State<AppState>,
    Json(report): Json<AttestationReport>,
) -> impl IntoResponse {
    println!("[*] Received Attestation Handshake Request...");

    // PASS 1: Timestamp Freshness Check
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let max_drift_seconds = 30;
    if now < report.timestamp || (now - report.timestamp) > max_drift_seconds {
        println!("  ❌ PASS 1 FAILED: Timestamp expired or drift too high!");
        return (
            StatusCode::UNAUTHORIZED,
            Json(GatewayResponse {
                status: "REJECTED".into(),
                session_token: None,
                reason: "Timestamp outside valid window (possible replay attack)".into(),
            }),
        );
    }
    println!("  ✅ PASS 1 PASSED: Timestamp fresh (within 30s window).");

    // PASS 2: Anti-Replay Nonce Check
    let mut nonces = state.seen_nonces.lock().unwrap();
    if nonces.contains(&report.nonce_hex) {
        println!("  ❌ PASS 2 FAILED: Nonce already used! Replay Attack Detected!");
        return (
            StatusCode::UNAUTHORIZED,
            Json(GatewayResponse {
                status: "REJECTED".into(),
                session_token: None,
                reason: "Duplicate nonce detected! Payload replayed.".into(),
            }),
        );
    }
    nonces.insert(report.nonce_hex.clone());
    println!("  ✅ PASS 2 PASSED: Nonce unique & registered in anti-replay cache.");

    // PASS 3: State Hash Integrity Reconstruction
    let serialized_payload = match serde_json::to_string(&report.payload) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(GatewayResponse {
                    status: "REJECTED".into(),
                    session_token: None,
                    reason: "Malformed JSON payload".into(),
                }),
            )
        }
    };

    let nonce_bytes = match hex::decode(&report.nonce_hex) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(GatewayResponse {
                    status: "REJECTED".into(),
                    session_token: None,
                    reason: "Invalid nonce hex encoding".into(),
                }),
            )
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(serialized_payload.as_bytes());
    hasher.update(report.timestamp.to_be_bytes());
    hasher.update(&nonce_bytes);
    let computed_hash = hex::encode(hasher.finalize());

    if computed_hash != report.state_sha256 {
        println!("  ❌ PASS 3 FAILED: State SHA-256 hash mismatch! Payload tampered.");
        return (
            StatusCode::UNAUTHORIZED,
            Json(GatewayResponse {
                status: "REJECTED".into(),
                session_token: None,
                reason: "SHA-256 state digest does not match reconstructed payload".into(),
            }),
        );
    }
    println!("  ✅ PASS 3 PASSED: State SHA-256 hash reconstructed & verified.");

    // PASS 4: Ed25519 Cryptographic Signature Verification
    let pub_key_bytes = match hex::decode(&report.public_key_hex) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(GatewayResponse { status: "REJECTED".into(), session_token: None, reason: "Invalid public key hex".into() })),
    };
    let sig_bytes = match hex::decode(&report.signature_hex) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(GatewayResponse { status: "REJECTED".into(), session_token: None, reason: "Invalid signature hex".into() })),
    };

    let verifying_key = match VerifyingKey::try_from(pub_key_bytes.as_slice()) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(GatewayResponse { status: "REJECTED".into(), session_token: None, reason: "Malformed Ed25519 public key".into() })),
    };

    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(GatewayResponse { status: "REJECTED".into(), session_token: None, reason: "Malformed Ed25519 signature".into() })),
    };

    let hash_raw = hex::decode(&computed_hash).unwrap();
    if verifying_key.verify(&hash_raw, &signature).is_err() {
        println!("  ❌ PASS 4 FAILED: Signature invalid!");
        return (
            StatusCode::UNAUTHORIZED,
            Json(GatewayResponse {
                status: "REJECTED".into(),
                session_token: None,
                reason: "Ed25519 signature verification failed".into(),
            }),
        );
    }
    println!("  ✅ PASS 4 PASSED: Ed25519 asymmetric cryptographic signature valid.");

    // PASS 5: Hardware Health Status Check
    if report.device_status != "TRUSTED_HARDWARE_HEALTHY" {
        println!("  ❌ PASS 5 FAILED: Device posture untrusted or TPM missing!");
        return (
            StatusCode::FORBIDDEN,
            Json(GatewayResponse {
                status: "DENIED".into(),
                session_token: None,
                reason: "Device posture policy violation: TPM restricted or missing".into(),
            }),
        );
    }
    println!("  ✅ PASS 5 PASSED: Hardware health policy validated (TPM Active).\n");

    let mut session_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut session_bytes);
    let session_token = format!("zt_sess_{}", hex::encode(session_bytes));

    println!("[SUCCESS] 🚀 5/5 PASSES AUTHORIZED! Issued Token: {}", session_token);

    (
        StatusCode::OK,
        Json(GatewayResponse {
            status: "SESSION_AUTHORIZED".into(),
            session_token: Some(session_token),
            reason: "Hardware attestation and state signature verified successfully.".into(),
        }),
    )
}