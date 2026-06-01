# SimpleAuth v1.1.0 → v2 — App Migration Guide

> **Audience:** an AI coding assistant updating an app's SimpleAuth integration, and the human developer reviewing the change.
> **Scope:** what an *integrating app* must do. Server/operator setup (registering apps) is referenced where the app depends on it.

---

## 1. TL;DR

The changes that actually matter for an app:

1. **Tokens are now per-app (`aud`).** Every access token is stamped `aud = <your app's audience>` (defaults to `app_id`). **Set the SDK `Audience` option to your `app_id` and enforce it** — otherwise you accept tokens minted for *other* apps (the cross-app confused-deputy v2 exists to stop).
2. **Upgrade the SDK.** v2 SDK `verify()` rejects non-access token classes (refresh `family_id`, OIDC id `typ=ID`, new app-mgmt `typ=app-mgmt`) and requires `exp`. The v1 SDK only rejected refresh tokens.
3. **Roles/permissions are now per-app.** They are resolved at token issuance from your app's user/group assignments — not from one global set. Same user can be `admin` in app A and nothing in app B.
4. **Login can be app-scoped.** Pass your `app_id` (direct login) or `client_id = app_id` (OIDC) so the token gets *your* `aud` and *your* roles. Omit it → you get the default-app token (`aud = "simpleauth"` or your `AUTH_CLIENT_ID`).
5. **Nothing is forced.** A v1 app that changes nothing keeps working as the auto-created **default app**. Migration is incremental.

---

## 2. What stayed the same / back-compat

**Existing v1 single-client deployments need zero changes to keep working.**

- **Same endpoints.** Every login/SSO/OIDC/JWKS/discovery URL is unchanged — `GET /login`, `GET /login/sso`, `GET /logout`, the OIDC routes under `/realms/{realm}/protocol/openid-connect/*`, `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `POST /api/auth/login`, `POST /api/auth/refresh`. None were renamed, moved, or removed.
- **The auto "default app."** On first v2 start, `ensureDefaultApp` (`main.go:250`) wraps your v1 config into a default app: `app_id = AUTH_CLIENT_ID` (or `"simpleauth"`), `audience` = same, `redirect_uris` = your existing allowlist, `require_assignment = false`, `allow_local_users = false`, and `AUTH_CLIENT_SECRET` folded in as the app secret hash. `resolveApp` (`internal/handler/apps.go:25`) maps any request with **no** `client_id`/`app_id` to this default app.
- **Global roles still flow.** `resolveTokenRoles` falls back to the v1 **global** roles whenever an app has **no per-app authz defined AND `require_assignment` is false** (`apps.go:123-129`). So a default-app user keeps getting their old global roles in every token.
- **Tokens still verify.** A v1 app pointed at the same URLs keeps logging in and verifying tokens with `aud = "simpleauth"` exactly as before.

**Migration is incremental.** Each piece (set `Audience`, register a dedicated app, add per-app roles, enable SSO) is independently adoptable. The only near-universal action is **(a) upgrade the SDK** and **(b) set `Audience`**.

---

## 3. The one conceptual shift

**v1:** one global OAuth client (`client_id` hardcoded to `simpleauth`); direct-login/Kerberos/SSO access tokens carried **no `aud` claim at all**; roles were **global** (one set per user, identical in every token).

**v2:** one shared directory and one shared login, but **many apps**, each with its own `app_id` + `app_secret`, audience, redirect URIs, roles, and assignments — the **Azure AD / Entra (or Keycloak client-roles) model**.

Two consequences define the new model:

- **One token per app (audience scoping).** A token minted for app A carries `aud: "A"` and is *meant to be rejected* by app B. The server now always stamps `aud`; the security guarantee lives on the **relying-party side** — your app must validate `aud`. "A missing `aud` check would let a foreign-app token through" (V2-DESIGN.md §11).
- **Cross-app SSO is preserved but token isolation is added.** A user still logs in once and flows between apps without re-prompting (the shared `__sa_sso` session), **but each app receives a distinct, app-scoped token with that app's roles.** Single login, many app-bound tokens.

So: **roles are per-app, tokens are per-app, but identity and the login session are still shared.**

---

## 4. Step-by-step migration for an app

### (a) Register the app (operator / master admin)
Ask the master admin to register your app via `POST /api/admin/apps`. This returns an `app_id` (slug, `[a-z0-9_-]`, ≤64 chars) and a one-time `app_secret` (`sa_app_...`, shown once, stored bcrypt-hashed). Have them set `redirect_uris` for your callback(s).

*(If you stay on the default app, skip this — but you still do steps (b)–(c).)*

### (b) Set the SDK / verifier Audience to the app_id
Set the SDK `Audience` (`audience` / `Audience`) option to your `app_id`. This is the single most important app-side change. The verifier then rejects any token whose `aud` is a different app.

- If you stay on the **default app**, set `Audience` to your `AUTH_CLIENT_ID` (or `"simpleauth"`).
- **Do not leave `Audience` empty in production** — an empty audience check accepts *any* app's token.

### (c) Pin alg/iss/exp and reject refresh/id/app-mgmt tokens
Upgrade to the v2 SDK so `verify()` enforces the full baseline. Every v2 app MUST:
- pin `alg = RS256` (reject `none` and any non-RSA method) — `jwt.go:193-195`, SDK `simpleauth.go:714`;
- require and check `exp` (fail closed if absent) — `ValidateToken` now uses `jwt.WithExpirationRequired()` (`jwt.go:197`);
- check `iss` == your issuer (set the SDK `ExpectedIssuer`); for direct-login tokens the issuer is `simpleauth`, **not** the base URL — do not hardcode `iss == base-URL`;
- check `aud` == your app's audience (step b);
- **reject** any token with `family_id` set (refresh), `typ == "ID"` (OIDC id token), or `typ == "app-mgmt"` (app-management token). Accept only no-`typ` or `typ == "Bearer"`.

The v2 SDK does all of this. If you hand-roll verification, replicate the `typ`/`family_id` gate — these classes are signed by the **same RSA key** as access tokens, so the class gate is the only thing stopping an id_token or app-mgmt token from being replayed as a bearer token.

### (d) Move from global roles to per-app role assignments
Once you have a dedicated app, declare its roles and assignments — recommended as **authz-as-code on deploy** via `POST /api/app/bootstrap` (HTTP Basic `app_id:app_secret`, or a token from `POST /api/app/token`):

```jsonc
POST /api/app/bootstrap        Authorization: Basic base64(<app_id>:sa_app_…)
{
  "roles": ["admin", "viewer"],
  "role_permissions": { "admin": ["invoice:write"], "viewer": ["invoice:read"] },
  "assignments": [
    { "group": "CN=Finance,OU=Groups,DC=corp", "roles": ["admin"] },
    { "user":  "jsmith", "roles": ["viewer"] }
  ]
}
```

Effective roles = direct per-app user assignments ∪ AD-group→role assignments for that app (`apps.go:87-141`). Users are matched by GUID, `sAMAccountName`, or any identity-mapping username (`userAssignmentKeys`, `apps.go:65-85`).

> **Critical:** the moment your app defines **any** per-app authz, the v1 global-roles fallback **stops** for that app. Tokens then carry **only** the roles you assigned (empty if you assigned no one). Until you opt in, tokens keep carrying global roles unchanged.

For authn-only apps with your own authz table, key on the **`samaccountname`** claim (the stable AD `sAMAccountName`), not `email` or `preferred_username` (which can be UPN-shaped); fall back to `sub`/`guid` for local users where `samaccountname` is absent.

### (e) Wire redirect_uris + the login / OIDC flow
- **Register your callback(s)** in the app's `redirect_uris`. Once an app defines its own `redirect_uris`, the global `AUTH_REDIRECT_URIS` no longer applies to it (`appAllowsRedirect`, `apps.go:58-63`).
- **Hosted login:** redirect to `GET /login?redirect_uri=<cb>&client_id=<app_id>`; on success → `302 <cb>#access_token=...&refresh_token=...&expires_in=...&token_type=Bearer`.
- **OIDC (authorization_code + PKCE):** set `client_id = <app_id>`, `code_challenge_method=S256` (plain/empty is hard-rejected, L7), always send `redirect_uri` explicitly. Read app roles from `resource_access["<app_id>"].roles`; treat `realm_access.roles` as a separate org-wide layer.
- **Direct REST login:** include `app_id` (or `client_id`) in the `POST /api/auth/login` body to get an app-scoped token. *Note:* the high-level SDK `login()` helpers currently send only `{username, password}` (→ default app); to mint a specific `aud` via direct login, use a raw POST with `app_id`, or use the OIDC `client_id` flow.

### (f) Optional features
- **Per-app admins (upcoming — not in v2.0.x):** a feature in development that lets specific humans manage an app's authz with their own login instead of the shared `app_secret`. Not in the current release — ignore it for migration.
- **App-local users:** only if your app owns users outside the directory. Set `allow_local_users = true`, then `POST /api/app/users` with the app credential. They are resolved app-local-first, only ever get `aud = owner-app` tokens, are **not** SSO-shared, and are **exempt** from `require_assignment`.
- **`enable_session_sso` for cross-app SSO:** silent cross-app SSO is **OFF by default** in v2. If your v1 deployment relied on it, set `AUTH_ENABLE_SESSION_SSO=true` (or enable it in admin settings). Kerberos `/login/sso` is independent of this flag and still works.

---

## 5. Before/After code (per SDK)

The verify *call signature* is unchanged in every SDK — only the **construction options** change (add `Audience`; the `typ`/`family_id` gate comes for free on the v2 build).

### Go
```go
// v1
client := simpleauth.New(simpleauth.Options{URL: url})
claims, err := client.Verify(token)

// v2 — hardened: audience pinned; verify() now rejects id/refresh/app-mgmt + requires exp
client := simpleauth.New(simpleauth.Options{
    URL:            url,
    Audience:       "<your-app-id>",   // reject foreign-app tokens
    ExpectedIssuer: issuer,            // e.g. ".../realms/simpleauth" (NOT the base URL)
    // AppID / AppSecret: optional, for /api/app/* management
})
claims, err := client.Verify(token)   // same call
```

### Python
```python
# v1 (note: the v1 Python SDK shipped unimplemented — examples couldn't run)
auth = SimpleAuth(url=url)
claims = auth.verify(token)

# v2 — implemented SDK; audience pinned; typ/family_id gate + mandatory exp built in
auth = SimpleAuth(url=url, audience="<your-app-id>", expected_issuer=issuer)
claims = auth.verify(token)
```

### JS / TS
```ts
// v1 — built-in issuer check hardcoded iss == base URL (rejected direct-login tokens)
const auth = createSimpleAuth({ url });
const claims = await auth.verify(token);

// v2 — set audience; do NOT set expectedIssuer to the base URL
const auth = createSimpleAuth({ url, audience: '<your-app-id>' /*, appId, appSecret */ });
const claims = await auth.verify(token);  // now rejects typ ID/app-mgmt + refresh
// Never embed appSecret in browser code.
```

### .NET
```csharp
// v1 — same hardcoded iss == BaseUrl bug; accepted id_tokens as access tokens
var client = new SimpleAuthClient(new SimpleAuthOptions { Url = url });
var claims = await client.VerifyAsync(token);

// v2 — pin audience; VerifyAsync rejects id/refresh/app-mgmt and wraps bad input as 401
var client = new SimpleAuthClient(new SimpleAuthOptions {
    Url = url,
    Audience = "<your-app-id>",     // ExpectedIssuer optional (not the base URL)
});
var claims = await client.VerifyAsync(token);
```

---

## 6. Breaking changes checklist

| Change | Breaks if your app... | Fix |
|---|---|---|
| **Per-app `aud`** (every access token now carries `aud = app's audience`) | ...does not validate `aud` — it will silently accept tokens minted for *other* apps | Upgrade SDK; set `Audience` = your `app_id` and enforce it on every verify |
| **SDK token-class gate** (`verify()` rejects `typ` ∈ {`ID`,`app-mgmt`} and `family_id`) | ...is on an old SDK, or hand-rolls verify and passes id_tokens/refresh tokens as bearer tokens | Upgrade to the v2/Pass-3 SDK; stop sending id/refresh tokens to `verify()`; replicate the gate if DIY |
| **`exp` now mandatory** (`ValidateToken` uses `WithExpirationRequired`; old Go SDK skipped absent `exp`) | ...relies on an old Go SDK that accepted tokens without `exp` | Upgrade SDK (exp + RS256 pin handled for you) |
| **Per-app roles** (global fallback stops once you define per-app authz) | ...registers a dedicated app, defines roles, but forgets to assign users → role-less tokens | Populate assignments via `/api/app/bootstrap` or admin UI before relying on roles |
| **`require_assignment`** (per-app, default false) | ...has it flipped on by an admin with no assignments populated → all directory users get 403 `access_denied` at login **and** refresh | Populate assignments **before** enabling; handle `403`/`access_denied` |
| **Per-app `redirect_uris`** | ...defines its own `redirect_uris` and still expects the global `AUTH_REDIRECT_URIS` to apply | Register all callbacks in the app's `redirect_uris` |
| **`enable_session_sso` OFF by default** | ...relied on silent cross-app session SSO in v1 | Set `AUTH_ENABLE_SESSION_SSO=true` (Kerberos `/login/sso` is unaffected) |
| **OIDC end-session hardening** (M18/M20) | ...passed an access/refresh token as `id_token_hint`, or used an unregistered `post_logout_redirect_uri` | Pass the real **id_token** as `id_token_hint`; register the post-logout URI in the app/global allowlist |
| **OIDC PKCE S256-only** (L7) | ...sent `code_challenge_method=plain` or empty | Use `code_challenge_method=S256` |
| **Doc-only: `/api/auth/logout`** | ...calls `https://.../sauth/api/auth/logout` (documented but never existed) | Use `GET /logout` (hosted) or the OIDC end-session endpoint |

---

## 7. Feature compatibility

| Feature | v2 status | Caveat |
|---|---|---|
| **Impersonation** | Works — now **per-app** | `POST /api/auth/impersonate` with `{target_guid, app_id}` mints a token scoped to that app, carrying the target's roles **for that app** plus `impersonated` / `impersonated_by` claims. Disabled or access-revoked targets are refused. |
| **LDAP / AD** | Works, unchanged | `samaccountname` is captured at auth time and now doubles as a per-app assignment key. Group assignments match the user's captured group identifier (default `sAMAccountName`, configurable). |
| **Kerberos SSO** | Works, unchanged | `GET /login/sso` is **independent of `enable_session_sso`** and keeps working. The new code stamps `aud` per the app being redirected to. Directory users only. |
| **OIDC (authorization_code + PKCE)** | Works | `client_id` now **selects the app**; `aud`/`azp`/`resource_access` become that app. PKCE is **S256-only** (plain rejected). Per-app `redirect_uris` take precedence. End-session hardened (see §6). |
| **Refresh rotation** | Works — rotating, single-use, family-revoke-on-reuse | Refresh tokens are **app-bound** (carry `AppID`+`Audience`): refresh re-stamps the original `aud` and **recomputes per-app roles** (does not carry global roles). A disabled app → `app unavailable`; a de-assigned user under `require_assignment` → `403 access_denied` on refresh. |

---

## 8. Gotchas

- **`enable_session_sso` is OFF by default.** Silent cross-app SSO via the shared `__sa_sso` cookie is a no-op unless you enable it (`AUTH_ENABLE_SESSION_SSO=true` or admin settings). Kerberos `/login/sso` is separate and unaffected.
- **An empty `aud` check accepts any app's token.** The server always stamps `aud`, but enforcement is opt-in in code. If you never set `Audience`, a foreign-app token passes. Set it.
- **Refresh tokens are app-bound.** Refreshed tokens keep the **same `aud`** and reflect **current** per-app roles — roles can shrink/expand, or refresh can be **denied** if assignment was revoked. Do not assume refresh preserves global roles.
- **Defining per-app authz turns off the global-roles fallback for that app.** Define roles but forget to assign users → users get **empty** `roles`. Until you opt in, the default app keeps emitting global roles.
- **`require_assignment` fails closed.** Enabling it with no assignments populated locks out **every** directory user (403), by design (H6). Populate assignments first. App-local users are exempt.
- **Don't hardcode `iss == base-URL`.** Direct-login tokens use `iss = "simpleauth"`, not the server URL — the old JS/.NET bug rejected every login token. Use `ExpectedIssuer` (the realm issuer) or leave issuer unset for direct-login tokens.
- **`/api/auth/logout` does not exist.** It's a documentation error (`KEYCLOAK-MIGRATION.md`). Use `GET /logout` (hosted, clears `__sa_sso`, now single-logout when SSO is on) or the OIDC end-session endpoint with a real `id_token_hint`.
- **OIDC logout needs a real id_token.** Passing an access/refresh/app-mgmt token as `id_token_hint` clears the browser cookie but **does not** revoke sessions (M20). Pass the genuine `typ=ID` token.
- **Default-app `aud` ≠ your new `app_id`.** If you add a strict `aud` check but your login still hits the default app (no `client_id`/`app_id` passed), the token's `aud` is the old `ClientID`/`"simpleauth"`, not your new `app_id`. Make the login flow's app match the `aud` you enforce.
- **Keep `app_secret` server-side only.** It's an HTTP Basic password for `/api/app/*`. Never embed it in browser/client code. A leaked secret is blast-radius-limited to one app and is rotatable via `POST /api/admin/apps/{id}/rotate-secret`.
