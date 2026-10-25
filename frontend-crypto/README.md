# Optional WASM AES-256-GCM frontend draft encryption

Install wasm-pack and run (from repository root):

    wasm-pack build frontend-crypto --target web --out-dir ../web/wasm --release

The resulting JS/WASM bundle is served at /wasm. It encrypts only local mapping-editor drafts, with PBKDF2-HMAC-SHA256 (200,000 rounds), 128-bit random salt and AES-256-GCM with random 96-bit nonce. This is not a substitute for TLS, server-held secret protection, or identity protocol verification.

The output web/wasm is ignored and must be generated during application packaging.
