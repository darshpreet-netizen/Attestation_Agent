use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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

#[derive(Serialize)]
struct AttestationReport {
    payload: HashMap<String, String>,
    state_sha256: String,
    public_key_hex: String,
    signature_hex: String,
    device_status: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Attestation Agent v0.4.0 (Ed25519 Crypto Engine) ===");
    println!("[*] Querying Windows WMI and generating cryptographic signatures...");

    let com_lib = COMLibrary::new()?;
    let mut payload = HashMap::new();

    // 1. Gather System Info
    if let Ok(sys_con) = WMIConnection::new(com_lib) {
        if let Ok(systems) = sys_con.raw_query::<ComputerSystem>("SELECT Name, Manufacturer, Model FROM Win32_ComputerSystem") {
            if let Some(sys) = systems.first() {
                payload.insert("DeviceName".to_string(), sys.name.clone());
                payload.insert("Manufacturer".to_string(), sys.manufacturer.clone());
                payload.insert("Model".to_string(), sys.model.clone());
            }
        }
    }

    // 2. Gather TPM Info (Safely caught)
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

    // 3. Generate SHA-256 Digest of Payload
    let serialized_payload = serde_json::to_string(&payload)?;
    let mut hasher = Sha256::new();
    hasher.update(serialized_payload.as_bytes());
    let hash_bytes = hasher.finalize();
    let state_hash = hex::encode(hash_bytes);

    // 4. Generate Ed25519 Keypair & Sign the State Hash
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let signature = signing_key.sign(&hash_bytes);

    // 5. Evaluate Posture
    let device_status = if tpm_present && tpm_ready {
        "TRUSTED_HARDWARE_HEALTHY".to_string()
    } else {
        "UNTRUSTED_TPM_RESTRICTED_OR_MISSING".to_string()
    };

    // 6. Output Final Signed Attestation JSON
    let report = AttestationReport {
        payload,
        state_sha256: state_hash,
        public_key_hex: hex::encode(verifying_key.to_bytes()),
        signature_hex: hex::encode(signature.to_bytes()),
        device_status,
    };

    println!("\n[+] Cryptographically Signed Attestation Report:");
    println!("{}", serde_json::to_string_pretty(&report)?);

    Ok(())
}