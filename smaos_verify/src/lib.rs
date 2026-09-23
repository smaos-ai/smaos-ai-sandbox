use wasm_bindgen::prelude::*;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use ed25519_dalek::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub message: String,
}

#[wasm_bindgen]
pub fn verify_receipt(receipt_json: &str, public_key_pem: &str) -> String {
    // 1. Parse receipt, remove signature field for hashing
    let mut payload: serde_json::Value = serde_json::from_str(receipt_json).unwrap();
    let sig_hex = payload["signature_ed25519"].as_str().unwrap_or("").replace("ed25519:", "");
    payload["signature_ed25519"] = serde_json::Value::String("".to_string());

    // 2. Verify Ed25519 Signature
    let verifying_key_res = VerifyingKey::from_public_key_pem(public_key_pem);
    if verifying_key_res.is_err() {
        return serde_json::to_string(&VerificationResult {
            valid: false,
            message: "❌ Invalid public key PEM.".to_string()
        }).unwrap();
    }
    let verifying_key = verifying_key_res.unwrap();

    let sig_bytes_res = hex::decode(&sig_hex);
    if sig_bytes_res.is_err() {
        return serde_json::to_string(&VerificationResult {
            valid: false,
            message: "❌ Invalid signature hex format.".to_string()
        }).unwrap();
    }

    let sig_bytes: [u8; 64] = match sig_bytes_res.unwrap().try_into() {
        Ok(b) => b,
        Err(_) => return serde_json::to_string(&VerificationResult {
            valid: false,
            message: "❌ Invalid signature length.".to_string()
        }).unwrap()
    };
    let signature = Signature::from_bytes(&sig_bytes);

    match verifying_key.verify(serde_json::to_string(&payload).unwrap().as_bytes(), &signature) {
        Ok(_) => serde_json::to_string(&VerificationResult {
            valid: true,
            message: "✅ Cryptographic wire-truth verified. Receipt is authentic.".to_string()
        }).unwrap(),
        Err(_) => serde_json::to_string(&VerificationResult {
            valid: false,
            message: "❌ Signature mismatch. Receipt may be tampered with.".to_string()
        }).unwrap(),
    }
}
