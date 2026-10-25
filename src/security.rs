use axum::http::{header, HeaderMap};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub fn now() -> i64 { Utc::now().timestamp() }
pub fn random() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn sha256(value: &str) -> String { hex::encode(Sha256::digest(value.as_bytes())) }
pub fn pkce(verifier: &str) -> String { URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) }
pub fn secret_eq(a: &str, b: &str) -> bool { a.as_bytes().ct_eq(b.as_bytes()).into() }

pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")
}
pub fn cookie(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::COOKIE)?.to_str().ok()?.split(';').find_map(|part| part.trim().strip_prefix("sso_session="))
}
pub fn session_cookie(token: &str, secure: bool) -> String {
    format!("sso_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1209600{}", if secure { "; Secure" } else { "" })
}
pub fn clear_cookie(secure: bool) -> String {
    format!("sso_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}", if secure { "; Secure" } else { "" })
}
pub fn id_token(signing: &SigningKey, issuer: &str, client: &str, user: &str, nonce: Option<&str>, profile: Value) -> String {
    let head = json!({"typ":"JWT", "alg":"EdDSA", "kid":"sso-ed25519-1"});
    let mut claims = json!({"iss":issuer,"aud":client,"sub":user,"iat":now(),"exp":now()+300,"auth_time":now()});
    if let Some(n) = nonce { claims["nonce"] = json!(n); }
    if let (Some(dst), Some(src)) = (claims.as_object_mut(), profile.as_object()) {
        for (key, value) in src {
            if matches!(key.as_str(), "name" | "preferred_username" | "picture" | "email" | "email_verified") { dst.insert(key.clone(), value.clone()); }
        }
    }
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&head).expect("JSON"));
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("JSON"));
    let input = format!("{header}.{payload}");
    let sig = signing.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}
pub fn jwks(signing: &SigningKey) -> Value {
    json!({"keys":[{"kty":"OKP", "crv":"Ed25519", "x":URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes()),
         "use":"sig", "kid":"sso-ed25519-1", "alg":"EdDSA"}]})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn pkce_s256_rfc7636() {
        assert_eq!(pkce("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }
    #[test] fn secrets_are_compared_exactly() {
        assert!(secret_eq("123456", "123456"));
        assert!(!secret_eq("123456", "12345"));
    }
}
