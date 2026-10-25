use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pbkdf2::pbkdf2_hmac;
use serde_json::{json, Value};
use sha2::Sha256;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

const ITERATIONS: u32 = 250_000;

#[wasm_bindgen]
pub fn encrypt(plaintext: &str, passphrase: &str) -> Result<String, JsValue> {
    if passphrase.len() < 12 { return Err(JsValue::from_str("passphrase must contain at least 12 bytes")); }
    if plaintext.len() > 1024*1024 { return Err(JsValue::from_str("document exceeds 1 MiB")); }
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut salt).map_err(|_| JsValue::from_str("secure randomness unavailable"))?;
    getrandom::getrandom(&mut nonce).map_err(|_| JsValue::from_str("secure randomness unavailable"))?;
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, ITERATIONS, &mut key);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_|JsValue::from_str("invalid key"))?;
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|_|JsValue::from_str("encryption failed"))?;
    key.zeroize();
    Ok(json!({"version":1,"cipher":"AES-256-GCM","kdf":"PBKDF2-SHA256","iterations":ITERATIONS,
        "salt":URL_SAFE_NO_PAD.encode(salt),"nonce":URL_SAFE_NO_PAD.encode(nonce),
        "ciphertext":URL_SAFE_NO_PAD.encode(ciphertext)}).to_string())
}

#[wasm_bindgen]
pub fn decrypt(envelope_json: &str, passphrase: &str) -> Result<String, JsValue> {
    let parsed: Value = serde_json::from_str(envelope_json).map_err(|_|JsValue::from_str("invalid envelope"))?;
    if parsed["version"] != 1 || parsed["cipher"] != "AES-256-GCM" || parsed["kdf"] != "PBKDF2-SHA256" || parsed["iterations"] != ITERATIONS {
        return Err(JsValue::from_str("unsupported encryption format"));
    }
    let field = |key: &str| -> Result<Vec<u8>, JsValue> {
        URL_SAFE_NO_PAD.decode(parsed[key].as_str().ok_or_else(||JsValue::from_str("invalid field"))?)
            .map_err(|_|JsValue::from_str("invalid base64"))
    };
    let salt = field("salt")?;let nonce=field("nonce")?;let ciphertext=field("ciphertext")?;
    if salt.len()!=16 || nonce.len()!=12 || ciphertext.len()>1024*1024+16 {return Err(JsValue::from_str("invalid envelope dimensions"));}
    let mut key = [0u8;32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, ITERATIONS, &mut key);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_|JsValue::from_str("invalid key"))?;
    let result = cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_|JsValue::from_str("incorrect password or corrupted data"))?;
    key.zeroize();
    String::from_utf8(result).map_err(|_|JsValue::from_str("invalid UTF-8 content"))
}
