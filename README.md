# SSO · Rust 身份代理与 OAuth 2.0 / OIDC 网关

自托管身份中间件：上游支持 **Google OIDC、Telegram OIDC、X OAuth2 PKCE** 和自定义 OIDC/OAuth2 配置；下游提供统一的 **OAuth 2.0 Authorization Code + PKCE / OpenID Connect** 接口。内置账户绑定、应用策略联动、JS 字段映射预览、管理员与用户 Web UI、动态客户端注册和 Material 3 风格界面。

> **阶段：v0.1 开发版。** 尚未经过第三方安全审计或真实提供商端到端验证，不应直接作为公共生产身份系统。详见下方限制。

## 组件

```mermaid
flowchart LR
    Google[Google OIDC] --> Broker[SSO Identity Broker]
    Telegram[Telegram OIDC] --> Broker
    X[X OAuth2 PKCE] --> Broker
    Custom[自定义 OIDC / OAuth2] --> Broker
    Broker --> Identity[(用户与绑定关系)]
    Identity --> Mapper[字段规则 + JS 映射]
    Mapper --> Core[授权码 / JWT ID Token / opaque access token]
    Core --> AppA[应用 A]
    Core --> AppB[应用 B]
    Core --> Policy[联动策略引擎]
    Policy --> AppB
    Store[(SQLite / PostgreSQL)] --- Broker
    Store --- Core
    Admin[MD3 管理页面] --> Mapper
    Admin --> Policy
```

## 运行

需要 Rust stable（edition 2021）；纯前端静态文件已随项目提供。默认使用 SQLite，也支持 PostgreSQL。

```bash
cp .env.example .env
# 分别生成，粘贴到 .env：
openssl rand -hex 32  # SSO_SIGNING_KEY_HEX，重启不能改变，否则旧 ID token 验签失败
openssl rand -base64 48  # SSO_ADMIN_TOKEN
openssl rand -base64 48  # SSO_REGISTRATION_TOKEN
cargo run --release
```

服务默认监听 `127.0.0.1:8080`，访问 `http://127.0.0.1:8080/login`、`/account` 和 `/admin`。使用 `SSO_BIND=127.0.0.1:0` 时操作系统自动分配本地端口，服务日志打印实际端口并相应调整本地 issuer；客户端可通过 `/.well-known/openid-configuration` 和 `/.well-known/sso-configuration` 发现实际服务接口。生产必须固定稳定的 **HTTPS issuer** 并在反向代理终止 TLS。

PostgreSQL 可通过 `SSO_DATABASE_URL=postgres://username:password@localhost:5432/sso` 启用；表结构由应用初始化。对于 SQLite，建议备份 db、wal、shm 并使用单实例部署。SQLx Any 适配两种数据库，暂无自动迁移版本管理或分布式锁。

### 上游回调注册

各提供商回调分别为：

| 提供商 | 精确回调 URL | 说明 |
|---|---|---|
| Google | `https://sso.example.com/auth/google/callback` | OIDC ID Token 验签、issuer/audience/exp/nonce |
| Telegram | `https://sso.example.com/auth/telegram/callback` | BotFather Login Widget 配置 Client ID/Secret 和允许的回调 URL；使用 Telegram 新 OIDC 接口 |
| X | `https://sso.example.com/auth/x/callback` | OAuth2 PKCE + `GET /2/users/me`，需要账号所在 API 计划开放访问 |

设置相应的 `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`，`TELEGRAM_CLIENT_ID` / `TELEGRAM_CLIENT_SECRET`，`X_CLIENT_ID` / `X_CLIENT_SECRET`。只有凭据完整的提供商才会显示。新提供商可使用 `SSO_PROVIDERS_JSON` 配置数组，字段和示例参见 `src/config.rs` 的 `Provider` 类型；OIDC 必须配置可信 HTTPS `issuer` / `jwks_url`。自定义 OAuth2 需要 `userinfo_url` 和稳定唯一的 `id`/`sub`，不自动信任电子邮箱。

### 下游客户端动态注册

遵循 RFC 7591 的核心注册字段，**默认必须携带初始化注册令牌**。不会公开允许陌生客户端无限注册。

```bash
curl -X POST https://sso.example.com/connect/register \
  -H "Authorization: Bearer $SSO_REGISTRATION_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"My App","redirect_uris":["https://app.example.com/oauth/callback"],"token_endpoint_auth_method":"client_secret_basic"}'
```

输出的 `client_id` 可公开；`client_secret` **只展示一次**，服务端仅存储 SHA-256 哈希。支持 `client_secret_basic`、`client_secret_post` 与 `none`（公共客户端）。只有已登记的 **完全相同** `redirect_uri` 才能进入授权。禁止带 fragment 的重定向和非本机明文 HTTP。所有授权码必须使用 `S256` PKCE，授权码仅使用一次、有效期 120 秒。

OIDC Discovery：`/.well-known/openid-configuration`；授权：`/oauth/authorize`；令牌：`/oauth/token`；用户资料：`/oauth/userinfo`；JWKS：`/oauth/jwks`；撤销：`/oauth/revoke`；内省：`/oauth/introspect`。下游 ID Token 使用 Ed25519/EdDSA 签名及公开 JWKS；Access Token 是数据库保存 SHA-256 摘要的随机不透明令牌，默认 1 小时。OIDC ID Token 有效期 5 分钟；不支持 Refresh Token 和 SAML（待扩展）。

### 应用联动

管理员在 `/admin` 设置触发客户端、目标客户端与操作：

- `revoke`：登录应用 A 时立即标记应用 B 的现有 Access Token 为 revoked。
- `suspend`：登录 A 后，暂停 B 访问固定秒数，或一直暂停直到管理员处理；期限结束后回归基础策略。
- `restore_for`：临时覆盖 B 的基础禁用策略，过期后自动回归原本基础访问状态。

这些规则在 **下游应用使用授权码换取令牌** 时触发，不是在查看登录按钮时触发。UserInfo、introspection 和后续授权请求会重新计算权限。管理员基础禁用、联动临时覆盖和用户自行禁用是不同层级；用户自行禁用的优先级最高。

示例基础策略 API：

```bash
curl -X POST https://sso.example.com/admin/api/policies \
  -H "Authorization: Bearer $SSO_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"user_id":"USER_ID","client_id":"CLIENT_ID","enabled":false}'
```

**注意**：离线验证的已签发 JWT 无法被服务器即时收回；依赖方应对敏感操作使用 Access Token + introspection，或校验短有效期 ID Token。`revoke` 不会撤销上游 Google/Telegram/X 的令牌，SSO 不存储上游 access/refresh token。

### 字段可视化与 JS 转换

`/admin` 的字段流显示 `from → to`，支持映射 JSON 与 JavaScript 编辑器，预览使用 `POST /admin/api/mappings/preview`，保存至数据库后在签发 ID Token 与 UserInfo 时应用 **provider + client** 的规则。

```json
[
  { "from": "preferred_username", "to": "preferred_username" },
  { "from": "name", "to": "name" }
]
```

```javascript
claims.name = claims.name?.trim();
claims.preferred_username = claims.preferred_username?.toLowerCase();
```

JS 使用 Rust Boa 引擎，默认没有 DOM、文件、网络 API，设置循环次数、递归/栈限额和输入/输出限制。**仅管理员可以保存和执行代码**；该进程内沙箱没有独立的内存/CPU 硬限额，不能当作对抗性多租户 JS 隔离。保留的 OIDC 声明不能被映射，只有当前 scope 允许的 profile/email 字段会进入下游。

### MD3 / Monet / WASM

页面默认即为 Material 3 风格，背景支持 JPG/PNG/WebP（最大 5 MiB）。不构建主题依赖也能从图片中提取主色并采用近似色相主题；**完整 Material Color Utilities HCT/Monet 算法需要额外打包**：

```bash
cd web && npm install && npm run build:monet && cd ..
```

账户页的“WASM 加密导出”使用客户端 PBKDF2-SHA256（250k 次）派生的 AES-256-GCM，导出密文 JSON；需先编译 WASM 组件：

```bash
cargo install wasm-pack --locked
wasm-pack build crypto-wasm --target web --out-dir pkg
```

解密函数 `decrypt()` 同样由 WASM 导出。加密仅用于**用户手动导出的文件**；上游 OAuth 握手和服务端签名密钥不在 WASM 中，WASM 本身不能保证前端免受 XSS 侵害。

## API 简表

| API | 用途 |
|---|---|
| `GET /api/meta` | 前端可见的提供商列表，不泄露 Client Secret |
| `GET /api/me` / `GET /api/me/identities` | 当前会话资料和已绑定身份 |
| `GET /api/me/apps` | 已授权应用和访问状态 |
| `POST /api/me/apps/{client}/block` | 用户自行暂停/恢复应用访问 |
| `POST /api/me/apps/{client}/revoke` | 用户撤销指定应用的下游令牌 |
| `DELETE /api/me/identities/{id}` | 解绑身份（不允许解绑最后一个） |
| `POST /api/me/logout` | 删除当前会话 |
| `GET /admin/api/clients` | 已注册应用 |
| `GET/POST /admin/api/rules`、`DELETE /admin/api/rules/{id}` | 联动规则管理 |
| `POST /admin/api/policies` | 管理基础访问策略 |
| `GET/POST /admin/api/mappings` | 配置字段映射 |
| `POST /admin/api/mappings/preview` | 执行映射预览 |
| `POST /admin/api/branding` | 上传主题背景 |

## 安全约束与限制

1. 本项目还没有第三方安全审计和真实 Google/Telegram/X 端到端测试；建议先在独立域名和测试账户环境验证。
2. 管理员令牌 / 注册令牌必须来自安全的环境变量，不能提交到代码仓库；管理后台在 JS 内存中短暂使用 token，不提供持久浏览器存储。
3. 认证要求 HTTPS（loopback 开发例外）；鉴权令牌仅通过后端交换，上游 bearer token 不返回下游。服务不保存上游 access token。
4. 浏览器登录使用服务端一次性 state + PKCE + nonce + 同浏览器 flow cookie。仅已验证的 provider+subject 才能登录或显式绑定；不按 email 自动合并账户。
5. 动态注册是需初始化令牌的 RFC 7591 **子集**，不是完整 OIDC Certification 实现。暂未实现 RFC 7592 客户端配置管理、Refresh Token、RP-Initiated Logout、Back-channel Logout、SAML、SCIM、MFA、密钥轮换和租户隔离。
6. Admin JS 只是受限解释器，不是 OS 级沙箱；生产应将它迁移到独立受限进程或 WASM/WASI 沙箱并限制内存与 CPU 时间。
7. 图片上传仅校验 magic bytes、大小和媒体类型；高安全部署建议再做解码重编码、恶意文件扫描和隔离对象存储。
8. 默认仅提供开发原型级操作审计，尚未提供请求限速、防爆破、统一事务事件/outbox、备份恢复或高可用切换。代码对应的自动化测试与编译状态以 GitHub Actions 为准。

## 后续发展方向

- Provider 插件接口、SAML 2.0 ↔ OIDC、CAS、LDAP、WebAuthn/Passkey
- 完整的 OAuth 2.1 / FAPI、Refresh Token 轮换、会话回传注销、Token Exchange RFC 8693
- 独立脚本沙箱、可视化拖拽字段映射图、条件策略和策略模拟器
- 自动端口探测 + mDNS SRV 公告，HTTPS 服务发现和应用联邦配置
- 图形化应用注册/轮换、双人审批、审计导出与数据库迁移管理

MIT License
