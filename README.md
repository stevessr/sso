# SSO — Rust Identity Gateway

Rust OAuth2 identity broker with a Chinese MD3-inspired management interface.

> Development branch / pre-production. Do not use for sensitive production SSO until CI, provider integration tests, abuse controls and an independent security review are complete.

## Features

- Upstream Google and Telegram OIDC with signed ID token and issuer/audience/nonce validation; X OAuth2/PKCE using authenticated users/me; custom OIDC/OAuth2-userinfo provider configuration.
- Downstream OAuth2 Authorization Code + PKCE S256, one-time authorization codes, opaque bearer access tokens, userinfo and revocation.
- SQLite default; PostgreSQL and MySQL through SQLx runtime AnyPool.
- Self-service OAuth client registration with admin or initial-registration bearer token, fixed redirect URI allowlists, user account binding and unbinding.
- Cross-app policy on token exchange: permanent revoke, timed suspension (expires automatically), resume.
- Field flow graph and server-side bounded QuickJS data transformation. Provider/subject cannot be overwritten.
- Background image upload with Material Color Utilities image quantization, HCT tonal palettes and browser-responsive light/dark schemes.
- Optional locally built WASM AES-GCM for encrypting local configuration drafts, not for concealing OAuth credentials.
- Optional port fallback restricted to loopback interface.

## Local run

1. Copy .env.example to .env.
2. Generate independent strong SSO_ADMIN_TOKEN and SSO_REGISTRATION_TOKEN values.
3. Set at least one provider ID/secret pair, and register its callback URL with that provider. Example: http://localhost:3000/auth/callback/google.
4. Source environment variables and execute: cargo run --release
5. Open http://localhost:3000 and enter the administrator bearer token. Register a client and immediately save its client_secret (only shown once).

For deployed environments set SSO_PUBLIC_URL to a **HTTPS origin**, use a TLS reverse proxy, and register the exact upstream callback URI for each provider.

## Downstream OAuth2 flow

1. Browser redirects to GET /oauth/authorize with response_type=code, client_id, exact redirect_uri, state, code_challenge, code_challenge_method=S256, and optional provider=google|telegram|x.
2. Server authenticates user with an upstream provider, verifies identity, redirects with a short-lived one-time authorization code and original state.
3. Client POSTs to /oauth/token with grant_type=authorization_code, code, redirect_uri, code_verifier and client credentials (Basic auth or form client_id/client_secret).
4. Call GET /oauth/userinfo with Authorization: Bearer ACCESS_TOKEN. Revoke with POST /oauth/revoke.

POST /connect/register requires Authorization: Bearer SSO_REGISTRATION_TOKEN (or SSO_ADMIN_TOKEN). Public clients still need PKCE; anonymous open registration is intentionally disabled.

OAuth2 authorization server metadata: /.well-known/oauth-authorization-server. This service is NOT YET a downstream OpenID Connect issuer; it does not mint signed downstream ID tokens or publish downstream JWKS.

## Configuration

Default: DATABASE_URL=sqlite://sso.db

PostgreSQL: DATABASE_URL=postgres://user:pass@localhost:5432/sso

MySQL: DATABASE_URL=mysql://user:pass@localhost:3306/sso

Configure GOOGLE_CLIENT_ID/SECRET, TELEGRAM_CLIENT_ID/SECRET and X_CLIENT_ID/SECRET. For Telegram, add the OAuth callback URL in BotFather. For custom providers supply SSO_PROVIDERS_JSON containing objects with id, label, kind (oidc or oauth_userinfo), client_id, client_secret, authorize_url, token_url, scopes, token_auth_basic, issuer, jwks_url or userinfo_url as appropriate. Remote endpoints require HTTPS.

SSO_AUTO_PORT=true tries the next 20 TCP ports only for a loopback bind, rewriting the localhost public URL when necessary. Do not use auto-port selection for public callbacks.

## Security boundaries

- Only the verified upstream subject is used for account identity; custom JS may map name/email/avatar but cannot change the subject.
- Access tokens, authorization codes and sessions are SHA-256 hashed at rest, and codes/states are single-use.
- Linked-app rules operate on SSO-issued tokens, not the provider's own sessions or tokens. Suspended tokens resume only when unexpired and not revoked.
- A downstream app must check token validity through the gateway whenever revocation matters; simply caching a user profile cannot enforce timely revocation.
- Admin bearer token is kept in the browser page memory, not persisted. Never reveal it to downstream apps.
- The image upload now generates Material Color Utilities HCT scheme JSON at GET /theme; an average RGB fallback remains when theme loading fails.
- WASM only protects local encrypted drafts (with a user passphrase), not server-held credentials, browser code or authentication sessions.

## Release checklist

Still required before production: automated OAuth callback fixture tests, dynamic registration rate limits, complete session CSRF policy, consent UI, audit retention, versioned DB migrations, account race hardening, refresh token rotation, token introspection and downstream OIDC/JWKS support, Material Color Utilities integration, security headers and administrator RBAC.
