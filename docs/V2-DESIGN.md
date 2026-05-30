# SimpleAuth v2 — Per-App Authorization (Design)

> Status: **draft / in design**. Branch: `v2`. This document is the source of
> truth for the v2 model; code, README, docs, examples, and all four SDKs must
> match it before v2 ships.

## 1. Goal

One central SimpleAuth, one shared login, **many apps — each with its own
authorization**. A user logs in once and flows between apps without seeing the
login screen again, but **a token minted for app A is useless on app B**, and
each app owns its own roles, permissions, and who's allowed in.

This is the **Azure AD / Entra ID model** (one directory, many app
registrations, per-app roles + assignment, audience-scoped tokens), or
equivalently **Keycloak "client roles" within a single realm**. It is
explicitly **NOT** Keycloak multi-realm — no tenant isolation, no per-realm user
populations, no cross-realm identity brokering. We deliberately avoid that
complexity.

### Non-goals (v2)
- Multi-realm / multi-tenant isolation.
- Cross-realm federation / identity brokering.
- Changing the single-binary, zero-dependency deployment story.

## 2. Concepts & terminology

| Concept | What it is | Industry name |
|---|---|---|
| **App** | A registered application: `app_id` + `app_secret`, redirect URIs, audience, policy. | OAuth2 *client* / Entra *app registration* |
| **Audience-scoped token** | JWT `aud = app_id`; each app rejects tokens whose `aud` isn't itself. | `aud` claim / RFC 8707 resource indicators |
| **App role** | A role defined *inside* an app, distinct from another app's roles. | Keycloak *client role* / Entra *app role* |
| **Assignment** | Which directory users / AD groups may access an app, and with what roles. | Entra *app assignment* / Okta *app assignment* |
| **`require_assignment`** | Per-app switch: must a user be explicitly assigned to get a token? | Entra *"User assignment required"* |
| **Directory user** | A global identity (AD or shared local). Shared across apps, SSO-eligible. | — |
| **App-local user** | A local identity **owned by one app** (e.g. customer-portal users not in AD). Not shared, not SSO. | — |

## 3. Trust tiers

v2 replaces "one master key does everything" with three tiers — which also
resolves the v1 audit finding I1 (single static admin key, no attribution).

| Credential | Scope |
|---|---|
| **Master / root admin key** | The directory (CRUD directory users), the **app registry** (create/rotate/delete apps), global/realm roles, global config. |
| **`app_id` + `app_secret`** | *Only this app's* roles, permissions, assignments, app-local users, and token issuance. Cannot see or touch any other app or the directory. |
| **End-user access token** | `aud = app_id`; carries only that app's roles/permissions. Useless on any other app. |

The master admin **registers apps and owns identities**. Each app
**self-manages everything inside its own scope**. The scope key is `app_id`:
every role/permission/assignment/app-local-user row is partitioned by it, and an
app credential can only ever act on rows tagged with its own `app_id` (the API
derives `app_id` from the credential — there is no way to name another app).

## 4. Data model

New / changed tables (BoltDB buckets + Postgres tables, same as v1's dual store):

```
apps(
  app_id PK, name, audience, secret_hash,
  redirect_uris[], cors_origins[],
  require_assignment bool default false,
  allow_local_users  bool default false,   -- may this app provision app-local users?
  created_at, disabled bool
)

app_roles(app_id, role)                              -- PK (app_id, role)
app_permissions(app_id, permission)                  -- PK (app_id, permission)
app_role_permissions(app_id, role, permission)       -- role -> permission map, per app

app_assignments(
  app_id, subject_type ENUM(user|group), subject_id, roles[]
)   -- PK (app_id, subject_type, subject_id)
    -- subject_id = user GUID, or a group's sAMAccountName
    --   (configurable LDAP attribute; AD group naming varies per deployment)

users(                                  -- extended from v1
  guid PK, ..., password_hash, sam_account_name, disabled, ...,
  owner_app_id NULL                     -- NULL = directory user; set = app-local user
)
```

Identity rules:
- **Directory users** (`owner_app_id = NULL`): usernames globally unique; sourced
  from AD/Kerberos or shared local; SSO-eligible; assignable to any app.
- **App-local users** (`owner_app_id = X`): username unique **within app X**;
  authenticated by local password; only ever get `aud = X` tokens; **not**
  SSO-shared. `alice` in app A and `alice` in app B are different principals;
  both still have globally-unique GUIDs.

Global ("realm") roles from v1 are kept as an optional org-wide layer (e.g.
`employee`) that any app's token can include — see §5.

## 5. Token model

A token issued for app **X** to user **U**:

```jsonc
{
  "sub": "<U.guid>",
  "aud": "X",                          // ← the app; RPs MUST validate this
  "iss": "https://auth.example.com/sauth/realms/simpleauth",
  "preferred_username": "...", "samaccountname": "...",
  "roles":       [...],                // U's effective roles IN app X
  "permissions": [...],                // resolved from those roles + direct grants
  "resource_access": { "X": { "roles": [...] } },   // Keycloak-compatible
  "realm_access":   { "roles": [...] } // optional org-wide roles
}
```

**Effective roles** for a directory user U in app X:
```
roles(U, X) = directRoles(assignment user=U.guid, app=X)
            ∪ ⋃ group∈U.adGroups  roles(assignment group, app=X)
            ∪ realmRoles(U)        // org-wide, optional
```
For an app-local user, `roles = ` the roles the owning app granted them.

**Authorization decision** happens at token issuance:
- If `require_assignment(X)` and U (directory user) has no assignment (direct or
  via group) and no app-local ownership → **deny** (`access_denied`).
- Else issue the token with the effective roles (possibly empty).

The `resource_access` claim shape already exists in v1 and the SDK `audience`
verify option already exists (added in the v1.1.0 hardening, S2/S3) — so RP-side
enforcement is already in place; v2 makes the server side real.

## 6. Authentication flows

Authentication is unchanged in spirit; what's new is **app context** and the two
user kinds.

- **OIDC (per app):** each app is an OIDC client with `client_id = app_id`. The
  standard authorize→token flow yields `aud = app_id`. PKCE (added in v1.1.0)
  stays. Confidential apps present `app_secret`; public apps use PKCE only.
- **Direct REST login:** `POST /api/auth/login` gains app context (via the app
  credential or an `app_id`/`audience` field). The response token is scoped to
  that app with that app's roles.
- **Kerberos / SSO:** directory users only. The shared `__sa_sso` session means
  app #2 skips the login screen; the new code stamps `aud` per the app being
  redirected to.
- **App-local users:** authenticated against their owning app's local store. The
  login page already knows the app (from `client_id`/redirect). Resolution order
  for a username at app X: **app-local(X) first, then directory.** App-local
  users never get SSO into other apps.

## 7. App self-management API (the developer surface)

All under `/sauth/api/app/*`, authenticated with the **app credential** — never
the master key. `app_id` is implicit from the credential (never in the path).

**Auth (both supported):**
- HTTP Basic: `Authorization: Basic base64(app_id:app_secret)` — trivial for curl.
- App-management token: `POST /api/app/token` (client_credentials with
  `app_id`+`app_secret`) → short-lived management JWT, used as `Bearer`. The SDKs
  use this under the hood.

**Endpoints (illustrative):**
```
POST   /api/app/bootstrap                 # idempotent authz-as-code (below)
GET/PUT/POST/DELETE /api/app/roles
GET/PUT/POST/DELETE /api/app/permissions
PUT    /api/app/roles/{role}/permissions
GET/PUT /api/app/assignments              # assign user/group -> roles
DELETE /api/app/assignments/{type}/{id}
# app-local users (only if allow_local_users = true):
GET/POST/PUT/DELETE /api/app/users
PUT    /api/app/users/{guid}/password
GET    /api/app/settings                  # read-only view of this app's policy
```

**App-scoped bootstrap** — the headline DX feature, idempotent, safe on every
deploy, scoped to the calling app:
```jsonc
POST /api/app/bootstrap            Authorization: Basic base64(billing:sa_app_…)
{
  "roles": ["admin", "viewer"],
  "role_permissions": { "admin": ["invoice:write"], "viewer": ["invoice:read"] },
  "assignments": [
    { "group": "CN=Finance,OU=Groups,DC=corp", "roles": ["admin"] },
    { "user":  "jsmith", "roles": ["viewer"] }
  ],
  "local_users": [                         // only if allow_local_users = true
    { "username": "customer1", "password": "…", "roles": ["viewer"] }
  ]
}
```

## 8. Master (root) admin API — app registry

Under `/sauth/api/admin/apps`, master-key only:
```
POST   /api/admin/apps                 # register -> { app_id, app_secret (shown once) }
GET    /api/admin/apps                  # list
GET    /api/admin/apps/{app_id}
PUT    /api/admin/apps/{app_id}         # name, redirect_uris, require_assignment, allow_local_users, disable
POST   /api/admin/apps/{app_id}/rotate-secret
DELETE /api/admin/apps/{app_id}
```
The directory (`/api/admin/users`, LDAP, global roles) stays master-scoped.

## 9. SDK & examples impact (per the documentation standard)

All four SDKs (Go, JS/TS, Python, .NET) get, at parity:
- **`audience` is the integration anchor** — already shipped; v2 makes it
  required-in-practice. `verify()` rejects foreign-app tokens.
- An **app client** mode: construct with `app_id` + `app_secret`; helpers for
  `bootstrap`, role/permission/assignment management, and (if enabled) app-local
  user CRUD — all hitting `/api/app/*`.
- Examples reworked so a dev's whole integration is: *get `app_id`/`app_secret`
  → `bootstrap` roles on deploy → point SDK at SimpleAuth with `audience` →
  `verify()`*.

README + `docs/` get a new "Apps & per-app authorization" guide; the OIDC and API
docs get per-app `aud`/`client_id` updates.

## 10. Migration v1 → v2 (no surprises for existing deployments)

- On first v2 start, create a **default app** from the existing config
  (`app_id` = current `ClientID` or `"simpleauth"`, `audience` = same,
  `redirect_uris` = current allowlist, `require_assignment = false`,
  `allow_local_users = false`).
- Existing **global roles/permissions** become the default app's roles **and**
  stay as org-wide realm roles, so existing tokens/integrations are unaffected.
- Existing users become **directory users** (`owner_app_id = NULL`).
- Master admin key unchanged. Existing single-app integrations keep working with
  zero changes; multi-app is opt-in by registering more apps.

## 11. Security considerations

- **`app_secret` at rest:** store a bcrypt hash (verify-only); show the secret
  once at creation/rotation. (Reuses the password-hash path; the `secret.key`
  at-rest encryption from v1.1.0/H4 remains for the LDAP bind password.)
- **Blast radius of a leaked `app_secret`:** bounded to that one app (its roles,
  assignments, app-local users, and tokens). Cannot reach the directory or other
  apps. Rotatable by the master admin.
- **Authorization decision point** is token issuance (assignment + audience).
- **RP enforcement:** apps MUST set `audience` in the SDK — documented loudly,
  since a missing `aud` check would let a foreign-app token through.
- App-local user passwords follow the same policy/lockout/history machinery as
  local directory users, scoped per app.

## 12. Resolved decisions

1. **Group identifier for assignments → a configurable LDAP attribute, default
   `sAMAccountName`.** AD group naming (CN / full DN / SID) varies too much
   between deployments to hardcode, and `sAMAccountName` is the value that worked
   reliably in practice. Admins can override the group-identifier attribute (same
   spirit as v1's configurable attribute mappings). Assignment `subject_id` for a
   group = this value, matched against the user's resolved groups at login.
2. **App-local username collision → app-local-first at a given app.** At app X an
   app-local(X) user shadows a directory user of the same name, so a customer
   named like an employee never inherits employee access. **(Confirmed.)**
3. **App-local users are NOT gated by `require_assignment`.** They're inherently
   the owning app's users and the app manages their roles itself; the flag only
   gates directory users. **(Confirmed.)**
4. **App-management auth → both** HTTP Basic (`app_id:app_secret`) and a
   short-lived management token (`POST /api/app/token`); the SDKs use the token.

### Still to nail during implementation
- Exact group-membership resolution at login (memberOf → DN → `sAMAccountName`
  vs. a direct group query) — Milestone 3.
- Management-token TTL and claim shape — Milestone 4.

## 13. Milestones

1. **Apps registry** — `apps` table, master CRUD, secret hash + rotation, default-app migration. (No behavior change yet.) ✅ **Done** (store CRUD in both backends + backend migration, `POST/GET/PUT/DELETE /api/admin/apps` + `…/rotate-secret`, bcrypt secret hash shown once, default-app migration on startup, store + HTTP tests). SDK app-registry helpers fold into M2/M6 with the developer-facing surface (app-registry is a root-admin operation, not app integration).
2. **Audience-scoped tokens** — stamp `aud`; OIDC `client_id = app_id`; direct-login app context. ✅ **Done** (every access token carries `aud` = the resolved app's audience; refresh tokens are bound to their app and re-stamp it; OIDC `client_id` selects the app and sets `aud`/`azp`/`resource_access`; per-app `redirect_uris` honored when set; direct `/api/auth/login` accepts `app_id`/`client_id`; absent → default app. Tests: `TestAudienceScopedTokens`.) Per-app **roles** are still M3 — `aud` is scoped now, role *contents* are still global until then. SDKs already verify `aud` via the `audience` option (shipped in v1.1.0 S2/S3).
3. **Per-app roles/permissions/assignments** — tables + resolution at token issuance + `require_assignment`. ✅ **Done** (`AppAuthz` blob per app in both backends + migration; roles resolved per app from direct user assignments ∪ AD-group assignments — groups persisted on the user at LDAP/Kerberos login and matched by their captured identifier (sAMAccountName-configurable); `require_assignment` denies unassigned directory users (403 / `access_denied`); **v1 back-compat**: apps with no per-app authz fall back to global roles so existing deployments are unchanged. Master admin API `GET/PUT /api/admin/apps/{app_id}/authz`. Tests: `TestPerAppAuthz`.) App **self-service** of this same data (app credential + `bootstrap`) is M4; **app-local users** are M5.
4. **App self-management API** — `/api/app/*` + Basic/management-token auth + app-scoped `bootstrap`.
5. **App-local users** — `owner_app_id`, provisioning API, app-scoped login.
6. **SDKs + examples + docs** — all four SDKs to parity, examples reworked, README/docs guide (per the documentation standard).
7. **Admin UI** — apps management, per-app roles/assignments.

Each milestone is independently shippable behind the default-app migration, so
v2 can land incrementally without breaking v1 deployments.
