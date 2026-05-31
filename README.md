<p align="center">
  <h1 align="center">🔐 SimpleAuth</h1>
  <p align="center">
    <strong>Enterprise authentication that fits in a single 10&nbsp;MB binary.</strong><br>
    Active Directory · Kerberos SSO · a standard OIDC provider · signed JWTs — running in <strong>3 commands</strong>.
  </p>
  <p align="center">
    <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-22c55e.svg">
    <img alt="Made with Go" src="https://img.shields.io/badge/built%20with-Go-00ADD8.svg">
    <img alt="Single binary" src="https://img.shields.io/badge/deploy-single%20binary-6366f1.svg">
    <img alt="No dependencies" src="https://img.shields.io/badge/dependencies-0-orange.svg">
    <img alt="Security audited" src="https://img.shields.io/badge/security-self--audited-ef4444.svg">
  </p>
  <p align="center">
    <a href="docs/QUICKSTART.md">Quick Start</a> ·
    <a href="docs/API.md">API Reference</a> ·
    <a href="docs/ACTIVE-DIRECTORY.md">AD&nbsp;+&nbsp;Kerberos</a> ·
    <a href="docs/SDK-GUIDE.md">SDKs</a> ·
    <a href="SECURITY-AUDIT.md">Security Audit Log</a> ·
    <a href="#-contributing">Contributing</a>
  </p>
</p>

---

Setting up authentication shouldn't mean standing up a Java cluster, a database, a cache, and a weekend. **SimpleAuth is the whole identity layer — Active Directory login, transparent Windows SSO, a standards-compliant OIDC provider, and RS256 JWTs — in one Go binary you can `scp` to a box and run.**

No Java. No mandatory database. No config files after first run. Everything is managed from a built-in admin UI, and a domain-joined machine gets you to **two-click Kerberos SSO**. Drop it in, point your app at it, ship.

```bash
docker run -d -p 8080:8080 \
  -e AUTH_HOSTNAME=auth.example.com \
  -e AUTH_ADMIN_KEY=change-me \
  -e AUTH_REDIRECT_URIS="https://myapp.example.com/*" \
  -v simpleauth-data:/data \
  simpleauth
# → admin UI at https://auth.example.com/sauth/admin. That's it.
```

## ✨ Why you'll like it

**It's powerful.** Everything a real identity provider needs, nothing watered down:

- 🪪 **Active Directory & LDAP** — bind login, attribute sync, group membership, auto-discovery.
- 🎫 **Transparent Kerberos / SPNEGO SSO** — users on the domain are logged in *without typing anything*. SSO setup is a downloadable PowerShell script and one paste-back — no `ktpass`, no keytab files, no hand-edited LDAP.
- 🌐 **A standard OIDC provider** — discovery, authorization-code flow with **PKCE**, token, userinfo, JWKS, introspection, end-session. Works with any OIDC client library, in any language.
- 🔑 **RS256 JWTs** — auto-generated RSA-2048 keys, a JWKS endpoint for offline verification, single-use **refresh-token rotation** with family replay detection.
- 👥 **Roles, permissions & groups** — resolved into the token your app already trusts.

**It's simple.** The kind of simple you feel in the first five minutes:

- 📦 **One ~10 MB binary.** No runtime, no JVM, no sidecars. BoltDB is embedded — **zero external dependencies** to start.
- 🖥️ **A real admin UI** (dark mode included) — users, roles, LDAP, audit log, settings, database, all on a page. No XML, no `kcadm.sh`.
- ⚡ **3 commands to running**, and users are auto-created on first login from any provider — no import, no sync, no migration job.
- 🧩 **Embeddable** — `import "simpleauth/pkg/server"` and your Go app *is* the auth server.
- 📚 **Official SDKs** for JavaScript/TypeScript, Go, Python, and .NET, each with framework middleware.

## SimpleAuth vs. the usual suspects

| | Keycloak | ADFS | **SimpleAuth** |
|---|---|---|---|
| **Setup** | Hours (Java + Postgres + cache) | Hours + Windows Server | **3 commands** |
| **Footprint** | ~500 MB+ | A domain controller | **~10 MB binary** |
| **External deps** | Database + cache required | Windows infra | **None** (optional Postgres) |
| **Kerberos SSO** | Manual, fiddly | Built-in but rigid | **Two-click auto-config** |
| **OIDC provider** | Full | Claims-based | **Full** |
| **Admin experience** | Steep | Windows-only MMC | **One web page** |
| **REST API** | Sprawling | None | **Clean JSON + JWTs** |

## 🚀 Quick start

**Docker:**

```bash
docker run -d -p 8080:8080 \
  -e AUTH_HOSTNAME=auth.example.com \
  -e AUTH_ADMIN_KEY=my-secret-admin-key \
  -e AUTH_REDIRECT_URIS="https://myapp.example.com/callback,https://myapp.example.com/*" \
  -e AUTH_CORS_ORIGINS="https://myapp.example.com" \
  -v simpleauth-data:/data \
  simpleauth
```

**Binary:**

```bash
./simpleauth init-config     # generates simpleauth.yaml
vim simpleauth.yaml          # set hostname, redirect URIs, admin key
./simpleauth                 # running
```

Open the admin UI at `https://<hostname>/sauth/admin` and sign in with your admin key. (Omit `AUTH_ADMIN_KEY` and one is generated on first run and printed to the logs.)

> **For any real deployment, set three things:** `AUTH_HOSTNAME`, `AUTH_ADMIN_KEY`, and `AUTH_REDIRECT_URIS`. Without an allowlist, every login redirect is rejected — by design.

New to OAuth/OIDC? The [Quick Start](docs/QUICKSTART.md) walks you from zero to a logged-in user, and the [Integration Guide](docs/API.md) explains every term (JWT, redirect URI, CORS, the `/sauth` base path) in plain language.

## 🔌 Add it to your app

Pick whichever fits — you can mix them:

**1. Direct REST** — best for mobile, SPAs with a backend, and server-to-server.

```bash
curl -X POST https://auth.example.com/sauth/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret123"}'
# → { "access_token": "eyJ…", "refresh_token": "eyJ…", "expires_in": 900 }
```

**2. Hosted login page** — best for web apps that don't want to build a login form. Redirect to `…/sauth/login?redirect_uri=https://myapp/callback`; SimpleAuth (or Kerberos SSO) authenticates the user and hands the tokens back on the callback.

**3. Standard OIDC** — best when you already use an OIDC client library or need an `id_token`. Point your library at the discovery URL and you're done:

```
https://auth.example.com/sauth/.well-known/openid-configuration
```

Then verify tokens **offline** against the JWKS endpoint (no network call per request), or call `/sauth/api/auth/userinfo` to introspect. Full walkthrough with every flow: [docs/API.md](docs/API.md).

### Use an SDK instead of raw HTTP

| Language | Package | Install |
|---|---|---|
| **JavaScript / TypeScript** | `@simpleauth/js` | `npm install @simpleauth/js` |
| **Go** | `github.com/bodaay/simpleauth-go` | `go get github.com/bodaay/simpleauth-go` |
| **Python** | `simpleauth` | `pip install simpleauth` |
| **.NET** | `SimpleAuth` | reference the project |

Every SDK does login/refresh/userinfo, **offline JWT verification with cached JWKS**, role/permission helpers (`HasRole`, `HasPermission`, `HasAnyRole`), and ships middleware for Express, `net/http`, FastAPI/Flask/Django, and ASP.NET Core. See [examples/](examples/).

## 🧰 What's in the box

<table>
<tr><td valign="top" width="50%">

**Authentication**
- Kerberos/SPNEGO transparent Windows SSO
- Optional shared SSO session cookie (log in once, skip the login page across apps)
- Auto-SSO with a countdown + cancel
- LDAP bind login for non-domain users
- Local passwords (bcrypt, policy, history)
- Account lockout after repeated failures
- Hosted login page + standard OIDC
- Admin impersonation (fully audited)

</td><td valign="top" width="50%">

**Tokens & authorization**
- RS256 JWTs, auto-generated RSA-2048 keys
- JWKS endpoint for offline verification
- Refresh-token rotation + family replay detection + revocation
- Roles, permissions, and role→permission mapping
- Default roles auto-assigned on first login
- AD/LDAP groups surfaced in the token

</td></tr>
<tr><td valign="top">

**Admin UI** (dark mode, one page)
- Users: CRUD, disable, merge, unlock, force reset
- Roles & permissions
- LDAP providers + AD setup script + Kerberos
- Identity mappings & audit log
- Runtime settings (redirects, CORS, policy, rate limits)
- Database stats, migration, backend switching, restart

</td><td valign="top">

**Ops & storage**
- **BoltDB** embedded by default — zero config
- **PostgreSQL** optional (`AUTH_POSTGRES_URL`), migrate either way from the UI, auto-fallback if it's unreachable
- Per-IP rate limiting with trusted-proxy support
- CSRF protection on login forms; strict redirect allowlist
- Live backup/restore via the API
- Linux SSO setup script (krb5.conf + every major browser)

</td></tr>
</table>

## 🛡️ Security is the whole point

SimpleAuth guards the front door, so security isn't a feature — it's the product. A few things we do differently:

- **A public, living audit trail.** [`SECURITY-AUDIT.md`](SECURITY-AUDIT.md) logs every security review, finding, and fix — dated, with stable IDs, by **different AI models and humans** over time. Nothing is swept under the rug; even `WONTFIX` decisions are written down with rationale. It's unusual to publish your own audit log. We think a project that protects logins should.
- **Sane defaults that fail closed.** Redirect URIs are a strict allowlist (empty = reject all). The confidential OIDC grants (`password`, `client_credentials`) and token introspection are **disabled unless you set `AUTH_CLIENT_SECRET`**. Trusted proxies default to *trust none*.
- **Modern token hygiene.** RS256 only (no alg-confusion), JWKS with a stable key id, single-use refresh tokens with replay detection, an access-revocation kill switch, and authenticator-verified Kerberos with a replay cache and clock-skew enforcement.
- **Defense in depth.** bcrypt password hashing with a configurable policy and history, account lockout, per-IP rate limiting, CSRF tokens, and security headers across responses.

Found something? Please **open a security advisory** (or a private report) rather than a public issue — see [Contributing](#-contributing). Then add it to the audit log; that's exactly what it's for.

## 🤝 Contributing

**This project is public on purpose.** SimpleAuth protects authentication, and security software gets better with more eyes on it. If you've ever wanted to work on an auth server that's small enough to actually read end-to-end in an afternoon — this is that codebase.

**Especially valuable:**

- 🔍 **Security review.** Read [`SECURITY-AUDIT.md`](SECURITY-AUDIT.md), then audit a flow (login, refresh rotation, Kerberos, OIDC grants, the store layer) and send what you find — a PR, an issue, or a new audit pass appended to the log. The file even contains the prompt we hand to each reviewer.
- 🧩 **More SDKs & framework middleware.** Rust, Java, PHP, Ruby — or deeper middleware for the four we already ship.
- 📖 **Docs & examples.** A clearer explanation, a new framework example in [examples/](examples/), a fixed typo — all welcome.
- 🐛 **Bugs & papercuts.** Edge cases in LDAP/Kerberos against real directories are gold.

**Get going in a minute:**

```bash
git clone <your-fork>
cd SimpleAuth
go build ./...        # builds the single binary
go test ./...         # full suite (no external services needed)
go vet ./...
```

Open a PR with a focused change and a test, and keep the trio in sync — **code, docs, and the SDKs/examples** for any surface you touch. New features ship with all of it. First time here? Open an issue describing what you'd like to do and we'll point you at the right file.

## 📚 Reference

<details>
<summary><strong>OIDC endpoints</strong></summary>

Discovery: `GET /.well-known/openid-configuration`

| Endpoint | Method | Path |
|---|---|---|
| Authorization | `GET` | `/realms/{issuer}/protocol/openid-connect/auth` |
| Token | `POST` | `/realms/{issuer}/protocol/openid-connect/token` |
| UserInfo | `GET/POST` | `/realms/{issuer}/protocol/openid-connect/userinfo` |
| JWKS | `GET` | `/realms/{issuer}/protocol/openid-connect/certs` |
| Introspection | `POST` | `/realms/{issuer}/protocol/openid-connect/token/introspect` |
| End Session | `GET/POST` | `/realms/{issuer}/protocol/openid-connect/logout` |

`authorization_code` and `refresh_token` are public flows (auth-code supports PKCE/S256). `password`, `client_credentials`, and introspection are confidential — disabled unless `AUTH_CLIENT_SECRET` is set, then require that secret.

</details>

<details>
<summary><strong>Direct API</strong></summary>

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Login, get JWT tokens |
| `POST` | `/api/auth/refresh` | Rotate refresh token |
| `GET` | `/api/auth/userinfo` | Current user from the JWT |
| `GET` | `/api/auth/negotiate` | Kerberos/SPNEGO SSO |
| `POST` | `/api/auth/impersonate` | Token as another user (admin) |
| `POST` | `/api/auth/reset-password` | Change password (authenticated) |
| `GET` | `/login` · `/logout` · `/account` | Hosted pages |
| `GET` | `/.well-known/jwks.json` | JWKS public keys |
| `GET` | `/health` | Health check |

</details>

<details>
<summary><strong>Admin API</strong> (all require <code>Authorization: Bearer &lt;admin-key&gt;</code>)</summary>

| Category | Endpoints |
|---|---|
| **Bootstrap** | `POST /api/admin/bootstrap` — idempotent: define roles, permissions, ensure users |
| **Users** | CRUD `/api/admin/users`, merge/unmerge, disable, unlock, sessions |
| **Roles & Permissions** | `/api/admin/roles`, `/api/admin/permissions`, `/api/admin/role-permissions` |
| **LDAP** | CRUD `/api/admin/ldap`, auto-discover, import/export, test |
| **AD / Kerberos** | `GET /api/admin/setup-script`, `/api/admin/ldap/:id/setup-kerberos` |
| **Linux SSO** | `GET /api/admin/linux-setup-script` |
| **Settings / DB / Ops** | runtime settings, migrate/switch backends, backup, restore, audit, restart |

Full reference with request/response examples: [docs/API.md](docs/API.md).

</details>

<details>
<summary><strong>Essential configuration</strong></summary>

| Variable | Default | Description |
|---|---|---|
| `AUTH_HOSTNAME` | OS hostname | FQDN for TLS cert and Kerberos SPN |
| `AUTH_ADMIN_KEY` | auto-generated | Admin API key |
| `AUTH_BASE_PATH` | `/sauth` | URL path prefix (every URL starts here) |
| `AUTH_REDIRECT_URIS` | | Allowed redirect URIs, comma-separated (`*` wildcards) |
| `AUTH_CORS_ORIGINS` | | Browser origins allowed to call SimpleAuth |
| `AUTH_POSTGRES_URL` | | Enables the Postgres backend |
| `AUTH_TLS_DISABLED` | `false` | Disable TLS (reverse-proxy mode) |
| `AUTH_TRUSTED_PROXIES` | | Trusted proxy CIDRs (default: trust none) |
| `AUTH_CLIENT_SECRET` | | Enables confidential OIDC grants + introspection |
| `AUTH_JWT_ACCESS_TTL` | `15m` | Access token lifetime |
| `AUTH_JWT_REFRESH_TTL` | `720h` | Refresh token lifetime |
| `AUTH_ENABLE_SESSION_SSO` | `false` | Shared SSO session cookie across apps |
| `AUTH_AUTO_SSO` | `false` | Auto-attempt Kerberos SSO on the login page |

Everything else — password policy, lockout, rate limiting, audit retention — is in [docs/CONFIGURATION.md](docs/CONFIGURATION.md). Behind nginx/Traefik/Caddy/HAProxy? See [docs/REVERSE-PROXY.md](docs/REVERSE-PROXY.md) (and mind the Kerberos header buffers).

</details>

## 🪟 Active Directory in two clicks

1. **Admin UI → LDAP Providers → AD Setup Script.** Enter a service-account name, download the PowerShell script.
2. **Run it** on any domain-joined machine — it creates the account, registers SPNs, and exports a config file. No `ktpass`.
3. **Paste the config back** in the UI. SimpleAuth builds the keytab in memory and enables SSO immediately.

Full guide + troubleshooting: [docs/ACTIVE-DIRECTORY.md](docs/ACTIVE-DIRECTORY.md).

## 🧱 Embed it in your Go app

```go
cfg := server.Defaults()
cfg.Hostname = "myapp.example.com"
cfg.AdminKey = "my-secret-key"
cfg.DataDir  = "./auth-data"
cfg.BasePath = "/auth"

sa, err := server.New(cfg, ui.FS())  // pass nil UI for API-only
if err != nil { log.Fatal(err) }
defer sa.Close()

mux := http.NewServeMux()
mux.Handle("/auth/", http.StripPrefix("/auth", sa.Handler()))
// your app handles everything else
http.ListenAndServe(":8080", mux)
```

Your app and its auth server, one process, one deploy. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## 📖 Documentation

| Document | What's inside |
|---|---|
| [Quick Start](docs/QUICKSTART.md) | Zero to a logged-in user in 5 minutes |
| [API Reference](docs/API.md) | Every endpoint, every term, with examples |
| [Configuration](docs/CONFIGURATION.md) | All config options |
| [Architecture](docs/ARCHITECTURE.md) | How it works under the hood |
| [Active Directory](docs/ACTIVE-DIRECTORY.md) | AD, Kerberos, troubleshooting |
| [Reverse Proxy](docs/REVERSE-PROXY.md) | nginx, Traefik, Caddy, HAProxy |
| [SDK Guide](docs/SDK-GUIDE.md) | Client SDK usage |
| [Security Audit Log](SECURITY-AUDIT.md) | Every review, finding, and fix |

## License

MIT — see [LICENSE](LICENSE). Build something with it, and if it makes your auth simpler, ⭐ the repo so the next person finds it.
