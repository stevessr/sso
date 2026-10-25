# SSO — Rust Identity Gateway

Rust OAuth2 identity broker with a Chinese MD3-inspired management interface.

> Development branch / pre-production. Do not use for sensitive production SSO until CI, provider integration tests, abuse controls and an independent security review are complete.

## Features

- Upstream Google and Telegram OIDC with signed ID token and issuer/audience/nonce validation; X OAuth2/PKCE using authenticated users/me; custom OIDC/OAuth2-userinfo provider configuration.
- Downstream OAuth2 Authorization Code + PKCE S256, explicit user consent (allow/deny), one-time authorization codes, opaque bearer access tokens, scope-restricted userinfo, RFC7662 introspection and revocation. Optional explicit `offline_access` consent enables a 30-day absolute-lifetime, one-time-use rotating refresh-token family. Reuse or grant revocation invalidates the whole family and its linked access tokens.
- SQLite default; PostgreSQL and MySQL through SQLx runtime AnyPool.
- Gated machine dynamic client registration (admin or initialization bearer token), plus signed-in user self-service client registration (10 per account, isolated ownership, lifecycle enable/disable and confidential-secret rotation). Strict redirect allowlists, user-managed application access/revocation and third-party account binding/unbinding; admin disable/enable, rotate client secrets and remove linked-app policies.
- Cross-app token-exchange policies: permanent revoke, durable timed suspension that survives fresh logins, and resume. Active status is evaluated at every userinfo/introspection request.
- Field flow graph and server-side bounded QuickJS data transformation. Provider/subject cannot be overwritten.
- Background image upload with Material Color Utilities image quantization, HCT tonal palettes and browser-responsive light/dark schemes.
- Optional locally built WASM AES-GCM for encrypting local configuration drafts, not for concealing OAuth credentials.
- Optional port fallback restricted to loopback interface.
- Bounded, in-process per-TCP-peer IP and endpoint-group rate limits on login, authorization, callback, token, registration, consent, account and admin APIs; `Retry-After` on HTTP 429. Incoming `X-Forwarded-For` is intentionally never trusted.

## Local run

1. Copy .env.example to .env.
2. Generate independent strong SSO_ADMIN_TOKEN and SSO_REGISTRATION_TOKEN values.
3. Set at least one provider ID/secret pair, and register its callback URL with that provider. Example: http://localhost:3000/auth/callback/google.
4. Source environment variables and execute: cargo run --release
5. Open http://localhost:3000 and enter the administrator bearer token. Register a client and immediately save its client_secret (only shown once).

For deployed environments set SSO_PUBLIC_URL to a **HTTPS origin**, use a TLS reverse proxy, and register the exact upstream callback URI for each provider.

## Container deployment and WASM browser module

Local container smoke setup (the compose port binds **only** to the host loopback address):

```bash
cp .env.example .env
# Replace the two sample admin/registration values with INDEPENDENT strong secrets,
# e.g. generate each with: openssl rand -base64 48
docker compose up --build -d
curl -fsS http://127.0.0.1:3000/healthz
```

The multi-stage `Dockerfile` builds both the Rust gateway and `frontend-crypto` with `wasm-pack` and runs as an unprivileged user. SQLite data and uploaded backgrounds persist in the `sso-data` volume. The optional browser AES-GCM mapping-draft encryption then works without manually copying a WASM bundle. For a non-container deployment, run `bash scripts/build-wasm.sh` after installing `wasm-pack`, then `cargo run --release`.

For a public deployment set `SSO_PUBLIC_URL` to the **exact HTTPS origin** served by a trusted TLS proxy and update upstream provider callback allowlists. Add a real-client-aware edge rate limiter and keep the SSO listener private. Do not use the development `localhost` origin for production.

## Downstream OAuth2 flow

1. Browser redirects to GET /oauth/authorize with response_type=code, client_id, exact redirect_uri, state, code_challenge, code_challenge_method=S256, and optional provider=google|telegram|x.
2. Server authenticates user with an upstream provider, verifies upstream identity, and displays a first-party consent screen explaining the client and requested permissions. Declining sends access_denied; approving issues a short-lived one-time authorization code with the original state.
3. Client POSTs to /oauth/token with grant_type=authorization_code, code, redirect_uri, code_verifier and client credentials (Basic auth or form client_id/client_secret). Request `scope=profile email offline_access` during authorization **only if** offline refresh is needed; the consent page explicitly discloses it.
4. Call GET /oauth/userinfo with Authorization: Bearer ACCESS_TOKEN. Only granted profile/email scopes are returned. If `offline_access` was approved, POST `grant_type=refresh_token&refresh_token=...&client_id=...` to `/oauth/token` (plus client secret for confidential clients), **atomically replace** the stored refresh token after each response, and treat `invalid_grant` as a requirement to sign in again. Refreshing does not extend the original absolute 30-day grant expiry. Revoke access or refresh tokens with POST /oauth/revoke. Confidential OAuth clients can POST to /oauth/introspect (token, client_id, client_secret) to verify only their own access tokens; public PKCE clients cannot introspect.

POST /connect/register requires Authorization: Bearer SSO_REGISTRATION_TOKEN (or SSO_ADMIN_TOKEN). Public clients still need PKCE; anonymous open registration is intentionally disabled.

### Self-service OAuth client registration (signed-in users)

Log in through `/login/{provider}`, then use the **使用当前登录账户注册** button in the WebUI, or submit a same-origin authenticated POST with JSON `{"client_name":"...","redirect_uris":["https://app.example/callback"],"public_client":false}` to `/me/clients`. The response contains the client secret only once. `GET /me/clients` lists only the current user's clients. The following POST endpoints check ownership and same-origin request context:

- `/me/clients/{client}/disable` — permanently revokes all existing access and refresh tokens; re-enabling does not revive them.
- `/me/clients/{client}/enable` — enables future logins for this client.
- `/me/clients/{client}/rotate` — rotates its confidential secret, revoking all existing tokens; public PKCE clients have no secret.

Personal clients are limited to 10 per user in this iteration. This is NOT anonymous RFC 7591 open registration; public signup controls, external app ownership verification and advanced policy delegation are still future work.

OAuth2 authorization server metadata: /.well-known/oauth-authorization-server. This service is NOT YET a downstream OpenID Connect issuer; it does not mint signed downstream ID tokens or publish downstream JWKS.

## Configuration

Default: DATABASE_URL=sqlite://sso.db

PostgreSQL: DATABASE_URL=postgres://user:pass@localhost:5432/sso

MySQL: DATABASE_URL=mysql://user:pass@localhost:3306/sso

Configure GOOGLE_CLIENT_ID/SECRET, TELEGRAM_CLIENT_ID/SECRET and X_CLIENT_ID/SECRET. For Telegram, add the OAuth callback URL in BotFather. For custom providers supply SSO_PROVIDERS_JSON containing objects with id, label, kind (oidc or oauth_userinfo), client_id, client_secret, authorize_url, token_url, scopes, token_auth_basic, issuer, jwks_url or userinfo_url as appropriate. Remote endpoints require HTTPS.

SSO_AUTO_PORT=true tries the next 20 TCP ports only for a loopback bind, rewriting the localhost public URL when necessary. Do not use auto-port selection for public callbacks.

## Authentication endpoint limits

The gateway has in-memory fixed-window per-peer-IP limits (5-minute windows for most sensitive actions, one hour for registration). They do not coordinate between replicas and cannot distinguish users sharing one reverse proxy connection. Put a **trusted reverse proxy / edge WAF per-real-client rate limiter** in front of deployments; do not forward an unvalidated user-supplied X-Forwarded-For as proof of identity. Distributed production installations should use a shared limit store, such as Redis.

## Security boundaries

- Only the verified upstream subject is used for account identity; custom JS may map name/email/avatar but cannot change the subject.
- Access tokens, authorization codes and sessions are SHA-256 hashed at rest, and codes/states/consent requests are single-use. A host-only HttpOnly flow cookie and current SSO session check protect browser callback linking; account linking requires a same-origin POST.
- Linked-app rules operate on SSO-issued tokens, not the provider's own sessions or tokens. Suspended tokens resume only when unexpired and not revoked.
- Refresh tokens are stored only as SHA-256 digests; rotating tokens are never returned twice. A replayed refresh token revokes its family and all linked access tokens. Client disable, secret rotation, user app revocation and cross-app revoke also invalidate refresh grants.
- Client apps can call RFC7662 introspection to enforce revocation and persistent timed app blocks. Client-scoped introspection is intentionally limited to confidential clients; resource server integration and caching policy still need to be reviewed before production.
- Admin bearer token is kept in the browser page memory, not persisted. Never reveal it to downstream apps. CSP, no-store, no-referrer, nosniff and anti-framing headers are set; HTML uses external JS and CSS.
- The image upload now generates Material Color Utilities HCT scheme JSON at GET /theme; an average RGB fallback remains when theme loading fails.
- WASM only protects local encrypted drafts (with a user passphrase), not server-held credentials, browser code or authentication sessions.

## Release checklist

Still required before production: real upstream-provider integration fixtures, **shared edge/distributed rate limiting** and bot detection, broader CSRF/replay threat-model review, audit logging and retention, versioned migrations, PostgreSQL/MySQL and high-concurrency tests, account race hardening, optional signed downstream OIDC ID tokens/JWKS, administrator RBAC, client-specific scope allowlists/consent history and real TLS reverse-proxy validation.
