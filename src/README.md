# 🛡️ Attestation Agent

> High-Performance Native Windows Hardware Attestation & Zero Trust Posture Engine

A lightweight, zero-shell-dependency system agent written in **Rust**. It queries native Windows kernel WMI interfaces, extracts TPM and system telemetry, applies cryptographically secure anti-replay bounds, signs state digests with **Ed25519 asymmetric cryptography**, and transmits payloads over async HTTP in milliseconds.

---

## 🏗️ Architecture & Handshake Model

1. **Host Device (Attestation Agent)**
   - Queries Native WMI Telemetry (System Model, Manufacturer, TPM Status)
   - Generates 16-Byte Cryptographic Nonce & UNIX Timestamp
   - Computes SHA-256 State Hash
   - Signs Hash using Ed25519 Private Key
   - Transmits Payload via Async HTTP POST

2. **Verification Gateway (Server)**
   - Reconstructs SHA-256 Hash from Payload
   - Verifies Ed25519 Signature
   - Validates Anti-Replay Nonce & Timestamp Expiration
   - Grants / Denies Network Session Access Token

---

## 🔐 Security & Threat Model

- **Replay Protection**: 128-bit Random Nonce + Timestamp bounds prevent payload reuse.
- **Payload Integrity**: Ed25519 Asymmetric Signatures invalidate any tampered telemetry.
- **Kernel Binding**: Direct Windows COM binding bypasses PowerShell / shell tampering.
- **Zero Trust Gatekeeping**: Verification routines process incoming reports in under 1ms.

---

## 🚀 Quick Start

### Prerequisites
- Windows 10 / 11
- Rust toolchain (`cargo` 1.70+)

### Commands

Run in Development Mode:
cargo run

Build Optimized Release Binary:
cargo build --release

---

## 📋 License
Distributed under the MIT License.