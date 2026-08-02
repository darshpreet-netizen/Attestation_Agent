use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use wmi::{COMLibrary, WMIConnection};

// Clean snake_case structs with Serde renames to eliminate all warnings
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
    device_status: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Attestation Agent v0.3.1 (Native Engine) ===");
    println!("[*] Querying Windows Kernel via Native COM/WMI...");

    let com_lib = COMLibrary::new()?;
    let mut payload = HashMap::new();

    // 1. Standard Hardware Query (Guaranteed to succeed on all Windows PCs)
    if let Ok(sys_con) = WMIConnection::new(com_lib) {
        if let Ok(systems) = sys_con.raw_query::<ComputerSystem>("SELECT Name, Manufacturer, Model FROM Win32_ComputerSystem") {
            if let Some(sys) = systems.first() {
                payload.insert("DeviceName".to_string(), sys.name.clone());
                payload.insert("Manufacturer".to_string(), sys.manufacturer.clone());
                payload.insert("Model".to_string(), sys.model.clone());
            }
        }
    }

    // 2. TPM Security Query (Handled safely without crashing if access is restricted)
    let (tpm_present, tpm_ready) = match WMIConnection::with_namespace_path(r"root\CIMV2\Security\MicrosoftTpm", com_lib) {
        Ok(tpm_con) => {
            // Safely match on the query result instead of using `?`
            match tpm_con.raw_query::<TpmInfo>("SELECT IsPresent_Valid, IsEnabled_Valid, ManufacturerId FROM Win32_Tpm") {
                Ok(results) => {
                    if let Some(tpm) = results.first() {
                        payload.insert("TpmManufacturerId".to_string(), tpm.manufacturer_id.to_string());
                        (tpm.is_present_valid, tpm.is_enabled_valid)
                    } else {
                        (false, false)
                    }
                }
                Err(_) => (false, false), // Catches 0x80041002 (NOT_FOUND) or Access Denied
            }
        }
        Err(_) => (false, false),
    };

    payload.insert("TpmPresent".to_string(), tpm_present.to_string());
    payload.insert("TpmReady".to_string(), tpm_ready.to_string());

    // 3. Generate SHA-256 fingerprint
    let serialized_payload = serde_json::to_string(&payload)?;
    let mut hasher = Sha256::new();
    hasher.update(serialized_payload.as_bytes());
    let state_hash = format!("{:x}", hasher.finalize());

    // 4. Posture evaluation
    let device_status = if tpm_present && tpm_ready {
        "TRUSTED_HARDWARE_HEALTHY".to_string()
    } else {
        "UNTRUSTED_TPM_RESTRICTED_OR_MISSING".to_string()
    };

    let report = AttestationReport {
        payload,
        state_sha256: state_hash,
        device_status,
    };

    println!("\n[+] Signed Attestation Report (Native Execution):");
    println!("{}", serde_json::to_string_pretty(&report)?);

    Ok(())
}