use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use wmi::{COMLibrary, WMIConnection};

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct TpmInfo {
    pub manufacturer_id: u32,
    pub spec_version: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct ComputerSystem {
    pub name: String,
    pub manufacturer: String,
    pub model: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttestationReport {
    pub payload: BTreeMap<String, String>,
    pub timestamp: u64,
    pub nonce_hex: String,
    pub state_sha256: String,
    pub public_key_hex: String,
    pub signature_hex: String,
    pub device_status: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Attestation Agent v0.6.0 (Async HTTP Engine) ===");
    println!("[*] Collecting native WMI telemetry and generating cryptographic payload...");

    let com_lib = COMLibrary::new()?;
    let mut payload = BTreeMap::new();

    // 1. Gather System Info via Native COM
    if let Ok(sys_con) = WMIConnection::new(com_lib) {
        if let Ok(systems) = sys_con.raw_query::<ComputerSystem>("SELECT Name, Manufacturer, Model FROM Win32_ComputerSystem") {
            if let Some(sys) = systems.first() {
                payload.insert("DeviceName".to_string(), sys.name.clone());
                payload.insert("Manufacturer".to_string(), sys.manufacturer.clone());
                payload.insert("Model".to_string(), sys.model.clone());
            }
        }
    }

    // 2. Gather TPM Status via Native WMI Properties
    let (tpm_present, tpm_ready) = match WMIConnection::with_namespace_path(r"root\CIMV2\Security\MicrosoftTpm", com_lib) {
        Ok(tpm_con) => {
            match tpm_con.raw_query::<TpmInfo>("SELECT ManufacturerId, SpecVersion FROM Win32_Tpm") {
                Ok(results) => {
                    if let Some(tpm) = results.first() {
                        payload.insert("TpmManufacturerId".to_string(), tpm.manufacturer_id.to_string());
                        if let Some(ref ver) = tpm.spec_version {
                            payload.insert("TpmSpecVersion".to_string(), ver.clone());
                        }
                        (true, true)
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

    // 3. Generate Anti-Replay Nonce & Timestamp
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut nonce_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce_hex = hex::encode(nonce_bytes);

    // 4. Compute State Hash
    let serialized_payload = serde_json::to_string(&payload)?;
    let mut hasher = Sha256::new();
    hasher.update(serialized_payload.as_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(&nonce_bytes);
    let hash_bytes = hasher.finalize();
    let state_hash = hex::encode(hash_bytes);

    // 5. Sign Hash with Ed25519
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

    println!("\n[+] Signed Attestation Report Ready.");

    // 6. Transmit Report over HTTP POST to Local Gateway
    let gateway_url = "http://127.0.0.1:3000/api/v1/attest";
    println!("[*] Transmitting attestation payload to Gateway ({})", gateway_url);

    let client = reqwest::Client::new();
    let response = client.post(gateway_url)
        .json(&report)
        .send()
        .await?;

    if response.status().is_success() {
        let body: serde_json::Value = response.json().await?;
        println!("\n[SUCCESS] Gateway Accepted Payload!");
        println!("[+] Response: {}", serde_json::to_string_pretty(&body)?);
    } else {
        println!("\n[ERROR] Gateway rejected attestation report. Status: {}", response.status());
    }

    Ok(())
}