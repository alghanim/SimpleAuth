# Migrating a standalone deployment into a central SimpleAuth (v2.2)

A standalone SimpleAuth deployment is, in effect, *one app plus its directory*.
This feature adopts that standalone as a **single named app** on a central
SimpleAuth — carrying the authorization **policy**, not signing keys or avoidable
PII.

## What moves

| Moves | Doesn't move |
|---|---|
| home app config: audience, redirect_uris, cors, secret hash | signing keys (the central signs with its own) |
| role catalog + role→permission map → the target app's authz | user PII for AD users (the central re-binds them from AD) |
| each user's **effective** roles, keyed by a portable identity | passwords for AD users (none are stored) |
| local users' password hash → app-local users on the target | LDAP bind credentials |

Users are split by **how they authenticate**, because that's what doesn't move:

- **AD users** travel keyed by `sAMAccountName`. The central must be on the **same
  AD**; it re-binds the same person on their next login and resolves the carried
  assignment. No record or password is copied.
- **Local users** carry their **password hash** and become **app-local users** on
  the target app — same username, same password, no change for the user.

## Steps

1. **On the central:** create the target app (`Apps → New App`), then click
   **Migrate token** on that app to mint a single-use, expiring token.
2. **On the standalone:** open **Migrate**, enter the central URL + target app id +
   token, and click **Preflight (dry run)**. Nothing changes yet.
3. **Review the dry-run report:** the user split (AD same-domain / local / blocked),
   the redirect URIs that will be allowlisted on the central, and any notes.
   Commit is refused while any user is **blocked**.
4. **Commit.** The standalone packages its directory + policy and pushes it to the
   central over TLS-verified HTTP; the token is consumed.
5. **Point your consumer apps at the central's URL.** With *carry secret* on, their
   `client_id`, `audience`, `redirect_uri`, and secret are unchanged — only the
   issuer/JWKS change, handled automatically by OIDC discovery.

## When the central isn't on the same AD

The pre-flight **blocks** AD users the central can't authenticate and tells you why:

- **Central not on AD** → connect it to the same AD first.
- **Central on a different AD** → key by UPN/email or connect the same AD
  *(planned for a later release)*.

Local users are always satisfiable (their hash travels), so a standalone with only
local accounts migrates to *any* central.

## Security

- Importing a directory is a master-level operation, so it is gated by a
  **single-use, app-scoped migration token** a master admin mints on the target app
  — not by the bare app secret. Tokens are stored hashed, expire, and are consumed
  on commit.
- The standalone sends its directory (incl. local-user password hashes) over the
  operator-supplied URL with **TLS verification on**. Confirm you're pointing at the
  real central.
- The default ("home") app cannot be a migration target.
- Commit re-runs the classifier server-side and refuses if any user is blocked.

## Not carried in v2.2 (re-grant on the target if needed)

Direct per-user permissions (named apps derive permissions from roles); per-app
group→role mapping; different-AD identity reconciliation; the reverse direction
(central → standalone).
