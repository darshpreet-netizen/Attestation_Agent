use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use wmi::{COMLibrary, WMIConnection};

#[derive(Deserialize, Serialize, Debug)]
struct TpmInfo {
    #[serde(rename = "IsPresent_Valid")]
    pub is_present_valid: bool,

    #[serde(rename = "IsEnabled_Valid")]
    pub is_enabled_valid: bool,

    #[serde(rename = "ManufacturerId")]
    pub manufacturer_id: u32,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct ComputerSystem {
    pub name: String,
    pub manufacturer: String,
    pub model: String,
}

// Enterprise Attestation Report with Anti-Replay Protection
#[derive(Serialize, Deserialize, Debug, Clone)]
struct AttestationReport {
    payload: HashMap<String, String>,
    timestamp: u64,
    nonce_hex: String,
    state_sha256: String,
    public_key_hex: String,
    signature_hex: String,
    device_status: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Attestation Agent v0.5.0 (High-Throughput Gateway Engine) ===");
    println!("[*] Generating signed attestation payload with Anti-Replay protection...");

    let com_lib = COMLibrary::new()?;
    let mut payload = HashMap::new();

    // 1. Gather Telemetry
    if let Ok(sys_con) = WMIConnection::new(com_lib) {
        if let Ok(systems) = sys_con.raw_query::<ComputerSystem>("SELECT Name, Manufacturer, Model FROM Win32_ComputerSystem") {
            if let Some(sys) = systems.first() {
                payload.insert("DeviceName".to_string(), sys.name.clone());
                payload.insert("Manufacturer".to_string(), sys.manufacturer.clone());
                payload.insert("Model".to_string(), sys.model.clone());
            }
        }
    }

    let (tpm_present, tpm_ready) = match WMIConnection::with_namespace_path(r"root\CIMV2\Security\MicrosoftTpm", com_lib) {
        Ok(tpm_con) => {
            match tpm_con.raw_query::<TpmInfo>("SELECT IsPresent_Valid, IsEnabled_Valid, ManufacturerId FROM Win32_Tpm") {
                Ok(results) => {
                    if let Some(tpm) = results.first() {
                        payload.insert("TpmManufacturerId".to_string(), tpm.manufacturer_id.to_string());
                        (tpm.is_present_valid, tpm.is_enabled_valid)
                    } else {
                        (false, false)
                    }
                }
                Err(_) => (false, false),
            }
        }
        Err(_) => (false, false),
    };

    payload.insert("TpmPresent".to_string(), tpm_present.to_string());
    payload.insert("TpmReady".to_string(), tpm_ready.to_string());

    // 2. Generate Anti-Replay Parameters (Timestamp + 16-byte random Nonce)
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut nonce_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce_hex = hex::encode(nonce_bytes);

    // 3. Compute Cryptographic Hash incorporating Payload + Nonce + Timestamp
    let serialized_payload = serde_json::to_string(&payload)?;
    let mut hasher = Sha256::new();
    hasher.update(serialized_payload.as_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(&nonce_bytes);
    let hash_bytes = hasher.finalize();
    let state_hash = hex::encode(hash_bytes);

    // 4. Generate Ed25519 Keypair & Sign state hash
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(&hash_bytes);

    let device_status = if tpm_present && tpm_ready {
        "TRUSTED_HARDWARE_HEALTHY".to_string()
    } else {
        "UNTRUSTED_TPM_RESTRICTED_OR_MISSING".to_string()
    };

    let report = AttestationReport {
        payload,
        timestamp,
        nonce_hex,
        state_sha256: state_hash,
        public_key_hex: hex::encode(verifying_key.to_bytes()),
        signature_hex: hex::encode(signature.to_bytes()),
        device_status,
    };

    println!("\n[+] Attestation Report Generated:");
    println!("{}", serde_json::to_string_pretty(&report)?);

    // -------------------------------------------------------------------
    // 5. SERVER-SIDE VERIFICATION GATEWAY (Simulated Remote Verifier)
    // -------------------------------------------------------------------
    println!("\n[=== SIMULATING REMOTE ENTERPRISE GATEWAY VERIFICATION ===]");
    let is_valid = verify_attestation_report(&report);

    if is_valid {
        println!("[SUCCESS] Signature Valid! Hardware posture verified. Granting Session Access Token.");
    } else {
        println!("[ALERT] Signature or State Verification FAILED! Access Denied.");
    }

    Ok(())
}

// Function executed on a high-throughput server/gateway to verify incoming agent reports
fn verify_attestation_report(report: &AttestationReport) -> bool {
    // A. Parse Public Key and Signature from Hex
    let pub_key_bytes = match hex::decode(&report.public_key_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_bytes = match hex::decode(&report.signature_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let verifying_key = match VerifyingKey::try_from(pub_key_bytes.as_slice()) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signature = match Signature::try_from(sig_bytes.as_slice()) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // B. Reconstruct the Hash Server-Side
    let serialized_payload = match serde_json::to_string(&report.payload) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let nonce_bytes = match hex::decode(&report.nonce_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let mut hasher = Sha256::new();
    hasher.update(serialized_payload.as_bytes());
    hasher.update(report.timestamp.to_be_bytes());
    hasher.update(&nonce_bytes);
    let expected_hash = hasher.finalize();

    // C. Verify Mathematical Authenticity of the Signature
    verifying_key.verify(&expected_hash, &signature).is_ok()
}