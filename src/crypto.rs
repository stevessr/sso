use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn digest(value: &str) -> String { hex::encode(Sha256::digest(value.as_bytes())) }
pub fn secure_eq_hex(a: &str, b: &str) -> bool {
    let (Ok(a), Ok(b)) = (hex::decode(a), hex::decode(b)) else { return false; };
    a.len() == 32 && b.len() == 32 && a.ct_eq(&b).into()
}
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}
pub fn valid_pkce(s: &str) -> bool {
    (43..=128).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"-._~".contains(&c))
}
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn pkce_rfc7636_vector() {
        assert_eq!(pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }
    #[test] fn token_hash_compare() {
        assert!(secure_eq_hex(&digest("hello"), &digest("hello")));
        assert!(!secure_eq_hex(&digest("hello"), &digest("world")));
    }
}
