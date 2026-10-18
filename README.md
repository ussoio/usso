# USSO

Multi-tenant SSO and identity service built with FastAPI, MongoDB and Redis.

**Base path:** `/api/sso/v1`  
**OIDC discovery / JWKS:** `/.well-known/openid-configuration`, `/.well-known/jwks.json`

## Features

### Authentication

- Password, OTP (SMS/email/Bale/…), and magic link
- OAuth2 social login (`/auth/oauth/{provider}/…`) including Telegram OIDC
- Passkeys (WebAuthn)
- QR login
- Telegram Login JS SDK (`POST /auth/telegram` with `id_token`)
- Secure step-up token (`POST /auth/secure-token`) for sensitive credential ops
- Captcha-gated login attempts (Altcha / image captcha)
- Dual transport: `Authorization` header or HTTP-only cookies

### Authorization & tenancy

- Multi-tenant isolation with per-tenant auth/registration/branding config
- Workspaces (hierarchy via `parent_id` / `ancestor_ids`, personal + management workspaces)
- Roles and scopes; `scope-catalog` for admin UI (not runtime authz)
- Impersonation (admin on `sso/usso/user`; read-only / full / OTP-consent modes)
- Service accounts: agents and API keys bound to `user_id` and/or `workspace_id`

### Identity & compliance

- KYC, legal documents + acceptances (`subject_scope`: user / workspace)
- Referrals (invite-only registration, webhooks)
- Profiles, sessions, device-code OAuth grant
- OIDC provider: authorize, token, userinfo, clients, device authorization

## Project layout

```
app/
├── apps/
│   ├── identity/
│   │   ├── auth/          # login flows, tokens, passkey/QR/Telegram/OAuth
│   │   ├── user/          # users, identifiers, credentials, impersonation
│   │   ├── agent/         # service-account agents
│   │   ├── api_key/       # API keys
│   │   ├── session/
│   │   ├── profile/
│   │   ├── referral/
│   │   ├── kyc/
│   │   └── legal/
│   ├── access_control/    # roles, workspaces, organizations
│   ├── tenant/            # tenants, messaging, OIDC integration, scope-catalog
│   ├── captcha/
│   └── setup/
├── server/                # FastAPI app, config, lifespan
└── tests/
```

Modules typically expose `models.py`, `schemas.py`, `routes.py`, `services.py`.

## API overview

All paths below are under `/api/sso/v1` unless noted.

### Auth (`/auth`)

| Method | Path | Notes |
|--------|------|--------|
| POST | `/auth/login-attempts` | Resolve next step / OTP delivery |
| POST | `/auth/login` | Login (captcha) |
| POST | `/auth/refresh` | Refresh tokens |
| POST | `/auth/workspace-login` | Switch workspace |
| POST | `/auth/logout` | End session |
| POST | `/auth/request-otp` | Send OTP |
| POST | `/auth/request-magic-link` | Send magic link |
| GET | `/auth/magic-link` | Consume magic link |
| GET/POST | `/auth/passkey` | WebAuthn challenge / assertion |
| GET/POST | `/auth/qr` | QR session + approve |
| GET | `/auth/qr/status` | Poll QR status |
| POST | `/auth/telegram` | Telegram OIDC `id_token` (JS SDK) |
| POST | `/auth/secure-token` | Step-up secure session |
| POST | `/auth/password` | Set/change password (secure-token) |
| GET | `/auth/oauth/{provider}/authorize` | Social OAuth start |
| GET | `/auth/oauth/{provider}/callback` | Social OAuth callback |
| POST | `/auth/verify-token` | Verify token payload |
| GET | `/auth/me` | Current access payload |

### Telegram Login (OIDC)

Telegram Login uses [OpenID Connect](https://core.telegram.org/widgets/login) at
`https://oauth.telegram.org` (legacy HMAC Login Widget is not supported).

1. In @BotFather → Bot Settings → Web Login: register Allowed URLs and copy
   **Client ID** + **Client Secret**.
2. Configure tenant secrets:

```json
{
  "oauth_secrets": {
    "telegram": {
      "client_id": "<client_id from BotFather>",
      "client_secret": "<client_secret>",
      "discovery_url": "https://oauth.telegram.org/.well-known/openid-configuration",
      "scopes": ["openid", "profile"]
    }
  }
}
```

(`discovery_url` / scopes default for provider `telegram` if omitted. PKCE +
`client_secret_basic` are applied automatically.)

3. Public config exposes `telegram_client_id` for the Login JS SDK.
4. Flows:
   - Redirect: `GET /auth/oauth/telegram/authorize` → callback exchanges code
   - JS SDK: `POST /auth/telegram` with `{ "id_token": "..." }` (JWT verified via JWKS)

Ensure `telegram_id` / `telegram_token` are allowed in the tenant `auth.login_flow`
(included in the default `PASSWORD_OR_OTP` flow).

### Other collections (CRUD via resource routers)

- `/users`, `/identifiers`, `/credentials`
- `/workspaces`, `/invitations`, `/roles`
- `/agents`, `/api-keys`, `/sessions`, `/referrals`, `/profiles`
- `/kyc`, `/legal/documents`, `/acceptances`
- `/tenants` (+ `/config`), `/scope-catalog`, `/captcha`, `/setup`
- OIDC: `/api/sso/v1/oauth/*` (authorize, token, userinfo, clients, device_authorization, …)

Exact OpenAPI: `{base}/docs` when the app is running.

## Stack

- FastAPI, Beanie/MongoDB, Redis (sessions, rate limits, QR claim, caches)
- JWT (Ed25519 by default; HS/RS/ES/PS supported per tenant keys)
- Docker / docker-compose for local runs

## Getting started

```bash
cp sample.env .env   # if present; otherwise configure env for Mongo/Redis
docker compose up -d
```

- API docs: `http://localhost:8000/api/sso/v1/docs` (port may differ behind the gateway)

## Tests

Run tests inside Docker on the authorized test server. The OAuth lifecycle
regression uses isolated MongoDB/Redis testcontainers and the suite's test login;
it does not use a production account. It covers public registration, approval
and denial, PKCE, code reuse, refresh rotation, and token revocation.

```bash
cd app
uv run pytest tests/unit -q
uv run pytest --no-cov tests/integration/test_mcp_oauth_lifecycle.py -q
uv run ruff check .
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
