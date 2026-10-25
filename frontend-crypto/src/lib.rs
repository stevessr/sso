use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::Sha256;
use wasm_bindgen::prelude::*;

fn derive(password: &str, salt: &[u8]) -> Aes256Gcm {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 200_000, &mut key);
    let result = Aes256Gcm::new_from_slice(&key).expect("AES-256 key length is 32");
    key.fill(0);
    result
}
#[wasm_bindgen]
pub fn encrypt_text(plaintext: &str, passphrase: &str) -> Result<String, JsValue> {
    if passphrase.len() < 12 { return Err(JsValue::from_str("passphrase must have at least 12 characters")); }
    if plaintext.len() > 1024*1024 { return Err(JsValue::from_str("draft exceeds 1 MiB")); }
    let mut salt=[0u8; 16];
    let mut iv=[0u8; 12];
    getrandom::getrandom(&mut salt).map_err(|_|JsValue::from_str("entropy unavailable"))?;
    getrandom::getrandom(&mut iv).map_err(|_|JsValue::from_str("entropy unavailable"))?;
    let encrypted=derive(passphrase, &salt).encrypt(Nonce::from_slice(&iv),plaintext.as_bytes())
        .map_err(|_|JsValue::from_str("encryption failed"))?;
    let mut payload=Vec::with_capacity(28+encrypted.len());
    payload.extend_from_slice(&salt);payload.extend_from_slice(&iv);payload.extend_from_slice(&encrypted);
    Ok(URL_SAFE_NO_PAD.encode(payload))
}
#[wasm_bindgen]
pub fn decrypt_text(encoded: &str, passphrase: &str) -> Result<String, JsValue> {
    let payload=URL_SAFE_NO_PAD.decode(encoded).map_err(|_|JsValue::from_str("invalid base64"))?;
    if payload.len()<44 || payload.len()>1024*1024+44 { return Err(JsValue::from_str("invalid payload length")); }
    let (salt,rest)=payload.split_at(16);
    let (iv,data)=rest.split_at(12);
    let bytes=derive(passphrase,salt).decrypt(Nonce::from_slice(iv),data)
        .map_err(|_|JsValue::from_str("wrong passphrase or corrupted ciphertext"))?;
    String::from_utf8(bytes).map_err(|_|JsValue::from_str("plaintext is not UTF-8"))
}
