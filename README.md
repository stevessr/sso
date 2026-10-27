# SSO — Rust Identity Gateway

Rust OAuth2 identity broker with a Chinese MD3-inspired management interface.

> Development branch / pre-production. Do not use for sensitive production SSO until CI, provider integration tests, abuse controls and an independent security review are complete.

## Development status

This is an active development implementation. Merging the initial gateway to `main` does NOT mean it has passed an independent authentication security audit. Do not expose it as a production identity authority until credential recovery, provider fixtures, origin/TLS setup and migration/operational reviews have been completed.

## Features

- Upstream Google and Telegram OIDC with signed ID token and issuer/audience/nonce validation; X, GitHub and Discord OAuth2/PKCE using authenticated userinfo; custom OIDC/OAuth2-userinfo provider configuration.
- Downstream OAuth2 Authorization Code + PKCE S256, explicit user consent (allow/deny), one-time authorization codes, opaque bearer access tokens, scope-restricted userinfo, RFC7662 introspection and revocation. Optional explicit `offline_access` consent enables a 30-day absolute-lifetime, one-time-use rotating refresh-token family. Reuse or grant revocation invalidates the whole family and its linked access tokens.
- SQLite default; PostgreSQL and MySQL through SQLx runtime AnyPool.
- Gated machine dynamic client registration (admin or initialization bearer token), plus signed-in user self-service client registration (10 per account, isolated ownership, lifecycle enable/disable and confidential-secret rotation). Strict redirect allowlists, user-managed application access/revocation and third-party account binding/unbinding; admin disable/enable, rotate client secrets and remove linked-app policies.
- Cross-app token-exchange policies: permanent revoke, durable timed suspension that survives fresh logins, and resume. Active status is evaluated at every userinfo/introspection request.
- Field flow graph and server-side bounded QuickJS data transformation. Provider/subject cannot be overwritten.
- Background image upload with Material Color Utilities image quantization, HCT tonal palettes and browser-responsive light/dark schemes.
- Optional locally built WASM AES-GCM for encrypting local configuration drafts, not for concealing OAuth credentials.
- Optional port fallback restricted to loopback interface.
- Bounded, in-process per-TCP-peer IP and endpoint-group rate limits on login, authorization, callback, token, registration, consent, account and admin APIs; `Retry-After` on HTTP 429. Incoming `X-Forwarded-For` is intentionally never trusted.

## 登录会话与审计日志

- `GET /me/sessions`：查看当前账户未过期的浏览器会话，包括当前设备、User-Agent、登录方式、认证因子、到期时间；旧会话的部分元数据可能为空。
- `DELETE /me/sessions/{id}`：撤销指定浏览器会话；`POST /me/sessions/others/revoke`：退出其他浏览器设备。所有写操作均检查同源 Origin、当前登录及最近十分钟内的认证保证，并清理相关会话因子记录。
- `GET /admin/audit?limit=50`：管理员可查看最多 200 条近期安全事件。设备授权批准/拒绝、会话撤销等事件写入审计表，页面内亦可阅读。不会记录访问 Token 或设备验证码。
- 新登录会话会记录截断后的 User-Agent 和登录方式，不信任来自客户端的转发 IP 头。会话撤销不会自动吊销已发行的下游 OAuth 令牌；使用已连接应用中的撤销功能处理下游授权。
- 上线前仍需版本化迁移、自动数据保留期限、集中化审计日志导出和高并发测试。

## OAuth 2.0 Device Authorization Grant (RFC 8628)

Headless CLI clients, set-top boxes, routers and other browserless devices can use the OAuth 2.0 device flow without extracting browser cookies or asking users to enter passwords on the device.

1. `POST /oauth/device_authorization` with form fields `client_id`, optional `client_secret` (for confidential clients) and optional `scope` (`profile`, `email`, `offline_access`). HTTP Basic client authentication is also supported.
2. Response includes `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in` (600) and `interval` (5 seconds). Display the short code and URL to the user.
3. The user visits `/device`, authenticates through an upstream provider (and any required 2FA/Passkey step-up), verifies the client name and scopes, and explicitly approves or denies the device.
4. Device polls `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code`, `client_id` and its client secret if required. Handle `authorization_pending`, `slow_down`, `access_denied`, and `expired_token` without prompting the user again. Success returns the normal access token and optional rotating refresh grant.

Both device and user codes are generated with a CSPRNG and **only SHA-256 hashes are stored in the database**. User codes have 40 bits of entropy, the code-entry endpoint is rate-limited, authorization is one-time and bound to the client, and polling is throttled server-side. User approval requires a CSRF-protected first-party session with MFA assurance. Users must compare the application name/scopes with the requesting device before approval. Device grants are short lived and cannot be reused after token issuance.

**Before production:** add distributed (Redis/edge) throttling, expired-grant cleanup/retention, real-device E2E coverage, and account-login recovery ergonomics. Public device clients remain limited to their registered identity and the configured scopes.

## Passkeys, second factor and account assurance

- **WebAuthn Passkey (beta)**: register while signed in via `POST /passkeys/register/start` and `/finish`, with browser `navigator.credentials.create`; sign in using account UUID via `/passkeys/login/start` and `/finish` and `navigator.credentials.get`. Registration/login challenges are stored **server-side**, expire in 5 minutes, are atomically one-use, bind registration to the user's current session and bind login to an HttpOnly SameSite Strict flow cookie. Creating/removing passkeys and starting TOTP enrollment require an authentication assurance no older than ten minutes; OAuth and WebAuthn login both record an assurance timestamp. Credential IDs are globally unique, and counters/backup metadata are updated after successful verification. Security settings are exposed in the MD3 WebUI.
- **TOTP 2FA**: `POST /mfa/enroll/start` creates a sealed 20-byte secret with a 10-minute enrollment window. `POST /mfa/enroll/confirm` verifies a 6-digit code before enabling MFA and issues ten one-time, randomly generated recovery codes (shown only once). Verification accepts an authenticator code or an unused recovery code through `POST /mfa/verify`; TOTP steps cannot be reused. A registered Passkey can instead perform `POST /passkeys/stepup/start` and `/finish` from the MFA page, binding its signed assertion to the current pending session. Only after step-up is OAuth consent resumed. Disable requires a second-factor proof and revokes all sessions.
- **Session policy**: accounts with enabled TOTP cannot use sessions obtained from Google/Telegram/X to approve OAuth consent, view account details, bind identities, or manage OAuth clients until the second factor is satisfied. WebAuthn Passkey authentication counts as a phishing-resistant verified session. Existing authenticated sessions can enter downstream OAuth consent without restarting an upstream OAuth login.
- **Secret key**: set `SSO_MFA_ENCRYPTION_KEY` to the output of `openssl rand -hex 32` **before** enrolling TOTP. Never use an admin or client token as this key. Protect/back up this key; losing it makes stored TOTP secrets unreadable. Secrets use AES-256-GCM with the user ID as associated authenticated data. This secret is never shipped to the browser and should be held in a secrets manager in production.
- **Limitations**: Passkey sign-in currently requires the stable account UUID from `/me` (account-discovery UI is not yet complete). This implementation does not provide passwords, SMS OTP, email magic links, admin-assisted recovery, resident-key conditional UI, per-factor administrative policies or full OIDC downstream issuance. A lost passkey with no other upstream identity can lock out an account. TOTP without independent backup cannot be recovered. Further required: browser-based and platform authenticator integration tests; second-factor credential recovery policies; origin/reverse-proxy validation; audited recovery and account-lockout UX. Browser credentials and reverse-proxy origins require real-device and end-to-end tests.

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

1. Browser redirects to GET /oauth/authorize with response_type=code, client_id, exact redirect_uri, state, code_challenge, code_challenge_method=S256. Without a `provider` parameter, the gateway now shows a first-party method chooser (Passkey, Google, Telegram, X, GitHub, Discord and configured custom providers); choosing Passkey signs into the gateway and returns to the **same validated authorization request** for consent. Clients can also request a specific configured upstream provider using `provider=google|telegram|x|github|discord|<custom-id>`.
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

Configure GOOGLE_CLIENT_ID/SECRET, TELEGRAM_CLIENT_ID/SECRET, X_CLIENT_ID/SECRET, GITHUB_CLIENT_ID/SECRET and DISCORD_CLIENT_ID/SECRET. For Telegram, add the OAuth callback URL in BotFather. For custom providers supply SSO_PROVIDERS_JSON containing objects with id, label, kind (oidc or oauth_userinfo), client_id, client_secret, authorize_url, token_url, scopes, token_auth_basic, issuer, jwks_url or userinfo_url as appropriate. Remote endpoints require HTTPS.

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
