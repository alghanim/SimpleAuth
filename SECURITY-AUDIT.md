# SimpleAuth Security Audit Log

A living, append-only security audit trail. SimpleAuth is an authentication
server, so security is the top priority: bugs here are security bugs.

This file is audited repeatedly over time, by **different AI models and humans**.
Each pass appends a dated section; the **Status Summary** table is the single
source of truth for what is currently open vs. fixed.

## Conventions

- **Stable IDs.** Every finding gets a permanent ID: `C#` critical, `H#` high,
  `M#` medium, `L#` low, `I#` informational. **Never renumber or reuse an ID.**
  A new audit that rediscovers an existing issue references the existing ID.
- **Status.** `OPEN` → `FIXED` (with date + commit/branch) / `WONTFIX` (with
  rationale) / `REGRESSED` (reopened — link the regressing change).
- **Dates** are ISO `YYYY-MM-DD`. **Breaking changes are acceptable** when they
  close a real security hole — this project favors security over compatibility
  (operators can pin a previous commit). Each fix notes its blast radius anyway.
- **Append, don't rewrite.** Add a new "Audit Pass" section per run. Correct an
  earlier finding by adding a note, not by deleting it.

## How to run an audit (prompt for the next model)

> Review the whole repo as a security audit of an auth server. Read
> `SECURITY-AUDIT.md` first. For each existing OPEN finding, verify it is still
> present (or mark REGRESSED/FIXED). Then hunt for NEW issues across: auth flows
> (login, refresh rotation, Kerberos/SPNEGO, OIDC grants, impersonation),
> token handling (JWT alg/iss/aud/exp, JWKS, revocation), the store layer
> (atomicity, injection, migration), admin/authz, secret handling, and the SDKs.
> Append a new Audit Pass section with dated findings using stable IDs, and
> update the Status Summary table.

---

## Status Summary (current)

| ID | Title | Severity | Status | Fixed (date / commit) |
|----|-------|----------|--------|-----------------------|
| C1 | Kerberos AP-REQ decrypted but never verified → replay | CRITICAL | FIXED | 2026-05-30 (branch `security-hardening-2026-05-30`) |
| C2 | OIDC token endpoint: no client auth; `password`/`client_credentials` open | CRITICAL | FIXED | 2026-05-30 |
| C3 | OIDC token introspection unauthenticated | CRITICAL | FIXED | 2026-05-30 |
| H1 | Unthrottled brute-force surfaces; `/test-negotiate` LDAP-bind oracle | HIGH | FIXED | 2026-05-30 |
| H2 | Refresh-token rotation TOCTOU (non-atomic check-then-mark) | HIGH | FIXED | 2026-05-30 |
| H3 | Backend migration drops sessions + revocation blacklist | HIGH | FIXED | 2026-05-30 |
| H4 | LDAP bind password stored in plaintext at rest | HIGH | FIXED | 2026-05-30 |
| M1 | OIDC id_token `aud` empty on default install | MEDIUM | FIXED | 2026-05-30 |
| M2 | JWT `kid` regenerated every restart (JWKS kid churn) | MEDIUM | FIXED | 2026-05-30 |
| M3 | Refresh path ignores the `IsUserAccessRevoked` kill-switch | MEDIUM | FIXED | 2026-05-30 |
| M4 | Nil-deref: refresh token re-validated with ignored error | MEDIUM | FIXED | 2026-05-30 |
| M5 | `Retry-After` header emits garbage for values ≥ 10s | LOW | FIXED | 2026-05-30 |
| M6 | OIDC authorization-code flow has no PKCE | MEDIUM | FIXED | 2026-05-30 |
| M7 | Login user-enumeration via distinct disabled/locked responses | LOW | FIXED | 2026-05-30 |
| M8 | Security headers only on admin UI, not login/API responses | LOW | FIXED | 2026-05-30 |
| M9 | Reflected XSS via unescaped `error`/`state`/`nonce`/`scope` on login pages | MEDIUM | FIXED | 2026-05-30 |
| S1 | Python SDK was unimplemented (README/examples referenced missing code) | MEDIUM | FIXED | 2026-05-30 |
| S2 | JS/.NET SDK `iss` check hardcoded to base URL (always fails login tokens) | MEDIUM | OPEN | |
| S3 | Go SDK accepts refresh tokens as access tokens; skips `exp` when absent | MEDIUM | OPEN | |
| I1 | Single static admin key = entire authz model; actions audited as "admin" | INFO | WONTFIX | by design (documented) |
| I2 | No tests for `internal/auth` / `internal/config` | INFO | PARTIAL | 2026-05-30 (added auth + crypto + PKCE + consume tests) |

---

## Audit Pass 1 — 2026-05-30 — Claude Opus 4.8 (`claude-opus-4-8`)

Scope: full codebase (server `internal/`, `pkg/`, SDKs, examples, docs, deploy).
Method: full first-hand read of the auth, OIDC, store, config, and Kerberos code
paths, cross-checked by parallel sub-agent analysis. `go build`/`go vet` clean;
`internal/handler` and `internal/store` tests pass; `internal/auth` and
`internal/config` have no tests (see I2).

### C1 — Kerberos AP-REQ is decrypted but never verified (replayable) — CRITICAL
**Where:** `internal/handler/auth.go` — `handleNegotiate` (~:793), `handleNegotiateTest`
(~:930/:980), `extractKerberosUsername` (~:1208/:1224).
**Mechanism:** every SPNEGO path calls `apReq.Ticket.DecryptEncPart(kt, nil)` and
then trusts `DecryptedEncPart.CName`. There is **no `APReq.Verify`/authenticator
decryption, no replay cache, and no clock-skew check.** Decrypting the ticket only
proves it was issued for this SPN — not that the presenter holds the client session
key or that the request is fresh. A captured `Authorization: Negotiate …` header
replays indefinitely to mint a full token pair as the victim (token-minting paths:
`GET /api/auth/negotiate`, `GET /login/sso`). `patchKeytabKVNO` compounds it by
trusting the client's claimed kvno.
**Fix:** use gokrb5 `service.VerifyAPREQ` (decrypts + verifies authenticator,
enforces clock skew, consults the replay cache).
**Breaking:** **highest-risk fix.** Real verification enforces clock sync (NTP, ~5m
skew) and a correct keytab; setups that "worked" only because verification was
skipped may start rejecting logins. Validate against real AD in staging.

### C2 — OIDC token endpoint has no client auth; `password`/`client_credentials` open — CRITICAL
**Where:** `internal/handler/oidc.go` — `authenticateOIDCClient` (:96, `return nil`),
`handleOIDCTokenPassword` (:350), `handleOIDCTokenClientCredentials` (:399).
**Mechanism:** client authentication is a no-op, so an anonymous network caller can
(a) use the `password` grant as a credential-stuffing oracle and (b) mint signed
service tokens via `client_credentials` with an arbitrary `scope`.
**Fix:** require a configured client secret (constant-time) for confidential grants;
disable `password` and `client_credentials` unless a secret is configured. Keep
`authorization_code`/`refresh_token` as public flows (hardened by PKCE — see M6).
Update discovery to advertise only enabled grants and real auth methods.
**Breaking:** removes two grants by default. The documented browser/OIDC flows and
the direct `/api/auth/login` API don't use them; the service-to-service examples that
"used" `client_credentials` were already broken. Low real-world impact.

### C3 — OIDC token introspection is unauthenticated — CRITICAL
**Where:** `internal/handler/oidc.go` — `handleOIDCIntrospect` (:687 calls the no-op).
**Mechanism:** anyone can introspect any token and read `sub`/`email`/`name`/scope/
expiry — a PII + token-validity oracle (violates RFC 7662 "protected resource").
**Fix:** require confidential client auth (client secret) or the admin key.
**Breaking:** anonymous introspection callers must present a credential. Rare in a
single-app deploy (RPs verify locally via JWKS). Low.

### H1 — Unthrottled brute-force surfaces; `/test-negotiate` LDAP-bind oracle — HIGH
**Where:** `internal/handler/auth.go` — `handleNegotiateTestForm` (:1313, no rate
limit, full LDAP bind + renders user attributes on success), `handleNegotiate`
(:741), `handleSSOLogin` (:1013); lockout only accrues for users with a local
mapping (:175).
**Mechanism:** `POST /test-negotiate` is an unauthenticated, unthrottled AD password
oracle; the Kerberos endpoints have no per-IP limit; AD users not yet provisioned in
SimpleAuth have no account-level lockout.
**Fix:** add the per-IP limiter to the Kerberos/SSO endpoints; gate the diagnostic
`/test-negotiate` endpoints behind a config flag (default off).
**Breaking:** rate-limiting is invisible to legit users; disabling test endpoints in
prod could surprise anyone misusing them as a login page. Low.

### H2 — Refresh-token rotation TOCTOU — HIGH
**Where:** `internal/handler/auth.go` `handleRefresh` (:436 check / :453 mark);
`internal/handler/oidc.go` `handleOIDCTokenRefresh` (:457/:463); Postgres
`MarkRefreshTokenUsed` is itself non-atomic (Get-then-Save).
**Mechanism:** the `Used` check and the mark are separate store calls with no row
lock, so two concurrent refreshes with the same token both succeed — defeating
single-use rotation and the replay detector.
**Fix:** add an atomic `ConsumeRefreshToken` (Bolt single txn; Postgres
`SELECT … FOR UPDATE` then conditional update) that returns a reuse sentinel; treat
reuse as the family-revocation trigger.
**Breaking:** internal only. None.

### H3 — Backend migration drops sessions + revocation blacklist — HIGH
**Where:** `internal/store/migrate.go` (bucket/table lists omit `sessions`,
`revoked_tokens`, `revoked_users`; PG→Bolt reports success on count mismatch).
**Mechanism:** after a Bolt↔Postgres switch, **revoked access tokens become valid
again** and all SSO sessions drop.
**Fix:** migrate those buckets in both directions; fail (not warn) on mismatch.
**Breaking:** strictly positive (preserves more data). None.

### H4 — LDAP bind password stored in plaintext at rest — HIGH
**Where:** `internal/handler/secrets.go` (no-op shim), `internal/store/types.go`
`LDAPConfig.BindPassword`; exposed wholesale by `GET /api/admin/backup`.
**Mechanism:** the AD service-account password is stored in cleartext in the DB and
included verbatim in raw DB backups.
**Fix:** encrypt the bind password at rest with an AES-GCM data key kept in a
`0600` key file in the data dir (outside the DB, so backups don't carry the key).
Transparently migrate existing plaintext on next read/save.
**Breaking:** key file becomes required to decrypt the bind password; back it up with
(but stored separately from) the DB. Existing plaintext auto-migrates.

### M1 — OIDC id_token `aud` empty on default install — MEDIUM
**Where:** `internal/handler/oidc.go` `issueOIDCTokens` (:557 uses `cfg.ClientID`,
which has no default) vs `oidcClientID()` = `"simpleauth"` used everywhere else.
**Fix:** use `oidcClientID()` for the id_token audience. **Breaking:** positive.

### M2 — JWT `kid` regenerated every restart — MEDIUM
**Where:** `internal/auth/jwt.go` (:72 `uuid.New().String()[:8]`).
**Mechanism:** the key is stable on disk but the published `kid` changes each boot,
so strict clients that match by `kid` reject tokens issued before the last restart.
**Fix:** derive `kid` deterministically from the public key (SHA-256 thumbprint).
**Breaking:** clients refetch JWKS once. None (single key).

### M3 — Refresh path ignores the access-revocation kill-switch — MEDIUM
**Where:** `internal/handler/auth.go` `handleRefresh` (:421) / OIDC refresh — only
`Disabled` is rechecked; `IsUserAccessRevoked` is not.
**Fix:** consult `IsUserAccessRevoked` on refresh too.
**Breaking:** admin "revoke all sessions" now also stops refresh (intended). None.

### M4 — Nil-deref on re-validated refresh token — MEDIUM
**Where:** `internal/handler/auth.go` `issueTokenPair` (:350 `rtClaims, _ := …` then
deref); mirrored in `oidc.go`.
**Fix:** return `familyID` directly from `IssueRefreshToken` and drop the re-parse.
**Breaking:** internal signature change. None.

### M5 — `Retry-After` header emits garbage ≥ 10s — LOW
**Where:** `internal/handler/auth.go` (:27 `string(rune(n+'0'))`).
**Fix:** `strconv.Itoa`. **Breaking:** none.

### M6 — OIDC authorization-code flow has no PKCE — MEDIUM
**Where:** `internal/handler/oidc.go` (no `code_challenge`/`code_verifier` anywhere).
**Mechanism:** with codes not bound to a confidential client, an intercepted code can
be redeemed by anyone. Important now that the code grant stays public (C2).
**Fix:** support S256 PKCE — capture `code_challenge` at authorize, require a
matching `code_verifier` at token exchange when a challenge was set.
**Breaking:** optional (only enforced if a challenge was sent). None for existing
clients; SDKs/clients can opt in.

### M7 — Login user-enumeration via distinct responses — LOW
**Where:** `internal/handler/auth.go` (:52–:55 distinct 403 for disabled/locked).
**Fix:** generic failure message to unauthenticated callers (keep detail in audit log
+ admin UI). **Breaking:** less descriptive client errors.

### M8 — Security headers only on the admin UI — LOW
**Where:** `internal/handler/handler.go` (:258 `setAdminHeaders` only).
**Fix:** baseline headers (`X-Content-Type-Options`, `Referrer-Policy`,
`X-Frame-Options` where appropriate) on all responses.
**Breaking:** low.

### S1 — Python SDK was unimplemented — MEDIUM — FIXED 2026-05-30
`sdk/python/` shipped only `pyproject.toml` + `README.md`; every Python example
imported a package that did not exist. **Fixed:** full package implemented
(`client`, `middleware`, `models`, `jwks`, `errors`) with correct RS256/JWKS
verification (alg-pinned, `exp` fail-closed, configurable `iss`/`aud`). All five
examples resolve.

### S2 — JS/.NET SDK issuer check hardcoded to base URL — MEDIUM — OPEN
`sdk/js/index.ts` (~:486) and `sdk/dotnet/SimpleAuthClient.cs` (~:118) validate
`iss == base URL`, but direct login/refresh tokens are signed `iss="simpleauth"`, so
`verify()` always throws for login tokens. Also both skip the check when `iss` is
absent. **Fix (pending):** make issuer configurable (default off / accept the server
value), fail closed on absent `exp`.

### S3 — Go SDK accepts refresh tokens; skips `exp` when absent — MEDIUM — OPEN
`sdk/go/simpleauth.go` `Verify` (~:412) checks neither `iss` nor token type, so an
RS256-signed refresh token authenticates as a user; `exp` is only enforced when
present. **Fix (pending):** enforce `exp`, and reject non-access tokens (check a
token-type/`typ` claim or issuer).

### I1 — Single static admin key is the entire authz model — INFO — WONTFIX
The master admin key is the sole admin trust boundary; all admin actions are audited
as the literal actor `"admin"` (no per-admin attribution). Deliberate simplicity
trade-off for a single-app server; documented. Revisit if multi-admin is added.

### I2 — No tests for `internal/auth` / `internal/config` — INFO — PARTIAL
The most security-critical packages had no unit tests. **Partially addressed**:
added `internal/auth/jwt_test.go` (stable kid, alg-confusion rejection, refresh
family id), `internal/handler/security_fixes_test.go` (PKCE S256/plain, secret
encrypt/decrypt round-trip), and `internal/store/consume_test.go` (atomic
single-use refresh). Still missing: LDAP filter-escaping tests, config/TLS tests,
and an end-to-end Kerberos verify test (needs a fixture keytab).

### M9 — Reflected XSS on the login pages — MEDIUM — FIXED 2026-05-30
**Where:** `internal/handler/oidc.go` `showOIDCLoginPage` and
`internal/handler/hosted_login.go` `handleHostedLoginPage`.
**Mechanism:** the `error` query param (and `state`/`nonce`/`scope`/`redirect_uri`
on the OIDC page) were interpolated into the HTML response via `fmt.Fprintf`
without escaping, enabling reflected XSS on an unauthenticated page.
**Fix:** HTML-escape all reflected values with `html.EscapeString` before
rendering; URL components of the SSO link remain `url.QueryEscape`d.
**Breaking:** none.

---

## Remediation Log — Audit Pass 1 (2026-05-30, Claude Opus 4.8)

All changes on branch `security-hardening-2026-05-30`. Build, `go vet`, and the
test suite are green. Pre-existing non-gofmt formatting was left untouched to keep
the diff scoped to security.

| ID | Files | Approach |
|----|-------|----------|
| C1 | `internal/handler/auth.go` | Replaced decrypt-only paths with `service.VerifyAPREQ` (authenticator + 5-min clock skew + replay cache, PAC decoding disabled) via new `parseAPReqToken`/`verifyAPReq` helpers used by `handleNegotiate`, `handleSSOLogin`, and the diagnostic path. |
| C2 | `internal/handler/oidc.go` | `requireConfidentialClient` (constant-time secret check) gates `password` + `client_credentials`; disabled unless `AUTH_CLIENT_SECRET` is set. Discovery advertises only enabled grants/auth methods. `authorization_code`/`refresh_token` stay public (hardened by PKCE). |
| C3 | `internal/handler/oidc.go` | Introspection now requires `requireConfidentialClient`. |
| H1 | `internal/handler/auth.go`, `handler.go`, `internal/config/config.go` | Per-IP limiter added to `handleNegotiate`/`handleSSOLogin`/`handleNegotiateTestForm`; `/test-negotiate` routes gated behind new `EnableTestEndpoints` (default off, `AUTH_ENABLE_TEST_ENDPOINTS`). |
| H2 | `internal/store/{interface,bolt,postgres}.go`, `auth.go`, `oidc.go` | New atomic `ConsumeRefreshToken` (Bolt single txn; Postgres `SELECT … FOR UPDATE`) with `ErrRefreshTokenReused`/`ErrRefreshTokenNotFound`; both refresh handlers use it. |
| H3 | `internal/store/migrate.go` | Migrate `sessions`/`revoked_tokens`/`revoked_users` both directions; PG→Bolt now hard-fails on count mismatch. |
| H4 | `internal/handler/secrets.go`, `handler.go` | AES-256-GCM at-rest encryption of the LDAP bind password with a `0600` `secret.key` in the data dir (not in the DB, so backups don't carry the key); legacy plaintext auto-migrates on next save. |
| M1 | `internal/handler/oidc.go` | id_token `aud` uses `oidcClientID()`. |
| M2 | `internal/auth/jwt.go` | `kid` = SHA-256 thumbprint of the public key (stable across restarts). |
| M3 | `auth.go`, `oidc.go` | Both refresh paths consult `IsUserAccessRevoked`. |
| M4 | `internal/auth/jwt.go` (+ callers) | `IssueRefreshToken` returns `familyID`; removed the ignored-error re-parse + nil-deref. Also persists refresh rows before returning the pair. |
| M5 | `internal/handler/auth.go` | `Retry-After` via `strconv.Itoa`. |
| M6 | `internal/handler/oidc.go`, `internal/store/types.go`, `auth.go` | Optional S256/plain PKCE: challenge captured at authorize (incl. SSO link + hidden form fields), verified at token exchange. |
| M7 | `internal/handler/auth.go` | Uniform `invalid credentials` on login failure; real reason stays in the audit log. |
| M8 | `internal/handler/handler.go` | Global `X-Content-Type-Options: nosniff` + `Referrer-Policy: no-referrer`. |
| M9 | `oidc.go`, `hosted_login.go` | HTML-escape reflected values on both login pages. |

### Operator notes (behavior changes shipped in this pass)
- **Kerberos now requires NTP** (server/KDC/client within 5 minutes) and a correct
  keytab. Validate SSO in staging before production. (C1)
- **OIDC `password` and `client_credentials` grants are disabled** unless
  `AUTH_CLIENT_SECRET` is set; when set, callers must present that secret. (C2)
- **Token introspection requires the client secret.** (C3)
- **`/test-negotiate` is gone unless `AUTH_ENABLE_TEST_ENDPOINTS=true`.** (H1)
- **`secret.key` is now a critical file** in the data dir — back it up alongside
  (but stored separately from) the database. (H4)

### Still open (recommended next pass)
- **S2** (JS/.NET SDK issuer validation) and **S3** (Go SDK accepts refresh tokens,
  skips absent `exp`) — client-side hardening.
- **I2** remainder — LDAP escaping + config tests + Kerberos verify fixture.
- Not yet done: per-admin attribution (I1, by design), refresh-token/OIDC-code
  pruning, and `X-Forwarded-Proto` trusted-proxy gating in `oidcBaseURL`.
</content>
