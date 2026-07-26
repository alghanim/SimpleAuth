# Integration harness — standalone → central migration

A self-contained, multi-container environment that exercises the v2.2 migration
feature end to end, across real container boundaries (real TLS, real HTTP push) —
the parts the Go unit tests can't reach. **It does not touch the production
`docker-compose.yml` at the repo root.**

```bash
cd test/integration
make test      # FRESH stack + run the Go scenario driver + tear down
make up        # just stand up the env; browse https://localhost:9443/admin
make down      # tear down + wipe volumes
make logs      # follow logs
```

`make test` always recreates the stack first: the scenarios assert exact counts
against clean stores, and the LDAP seed LDIF only applies to a fresh (empty)
directory — asserting against a stack left over from `make up` would silently
run stale fixtures.

Requires Docker + Compose + openssl + Go (the driver runs on the host).

## Topology

| Service | Role | Store / dir |
|---|---|---|
| `postgres` | central's database | — |
| `central` | the ONE centralized SimpleAuth (HTTPS, cert SAN=`central`,`localhost`) | Postgres |
| `standalone-local` | local-accounts deployment → migrates in | BoltDB |
| `standalone-ad` | **same-AD** deployment → policy-only migration | BoltDB + corp.local |
| `standalone-addiff` | **different-AD** deployment → blocked at preflight | BoltDB + other.local |
| `ldap-corp` / `ldap-other` | OpenLDAP directories (`uid`/seed LDIF) | corp.local / other.local |

Published to the host (loopback only): central `https://localhost:9443`,
standalone-local `:9447`, standalone-ad `:9445`, standalone-addiff `:9446`.

### Cross-container TLS

The migration's transport guard requires **https for any non-loopback target**,
and the standalone's outbound client verifies the cert. So `certs/gen.sh` mints an
internal CA + a `central` cert; the standalone trusts the CA via
`SSL_CERT_FILE=/certs/ca.crt`. The standalone pushes to `https://central:8080`
(the internal name in the cert's SANs). This makes the harness validate the real
secure path, not a bypass.

## What the driver asserts (`driver_test.go`, `//go:build integration`)

`TestLocalToCentralMigration`:
1. seeds the standalone (role catalog + a local user `alice` with role `admin`);
2. on the central, creates a fresh target app `billing` and mints a single-use
   migration token;
3. confirms a **cleartext `http://` push is refused** (the transport guard);
4. runs **preflight** (dry run) over TLS and checks the report (1 local user, none
   blocked);
5. **commits**, and verifies `alice → [admin]` landed in the central's `billing`
   authz;
6. logs `alice` in **against the central** with her original password (carried
   hash) and asserts the token carries `roles=[admin]`, `perms` incl.
   `invoice:write`, and the **carried source audience** (not the target app id —
   that's what lets the consumer app keep its existing token validation).

## AD scenarios (`ad_test.go`)

`TestADMigrationScenarios` drives the AD half of the matrix against the two
OpenLDAP directories. SimpleAuth is pointed at `username_attr=uid`, so
`User.SAMAccountName` is populated from `uid` and vanilla OpenLDAP suffices (no
samba schema); AD users are provisioned via the login/JIT path.

- **same-AD** — `bob` logs into `standalone-ad`, gets a role, and is migrated to
  the central **policy-only** (no record/password copied, `local_users=0`); he
  then **re-binds from the same AD on the central** and resolves his migrated
  role.
- **different-AD** — `carol` (other.local) is **blocked at preflight** (the
  central is on corp.local) and commit is refused (409).
- **direct app** — an app registered straight on the central; `bob` authenticates
  directly against it (no migration).

## More scenarios (`scenarios2_test.go`)

`TestMoreScenarios`:
- **carry_secret round-trip** — the source home app's secret is rotated, migrated
  with `carry_secret`, and the *same* secret then authenticates the central app
  (`/api/app/token`) — the consumer keeps its credential after cutover.
- **central_not_on_ad** — with the central's LDAP removed, an AD standalone's
  users are blocked at preflight.
- **migration_guards** — across the container boundary: a reused single-use token
  is `401`, and a fresh token cannot re-migrate into an already-populated app
  (fresh-target guard).
- **mixed_population** — one standalone with an AD user **and** a local break-glass
  account: the AD user migrates policy-only, the local one carries its hash, and
  both authenticate on the central.
- **group_to_role** — `bob` gets a role on a central app purely via **group
  membership** (he's in the `Finance` group), with no per-user assignment. The
  directory's memberof overlay stamps bob with the DN-shaped `memberOf` value
  real AD emits (see `ldap/corp.ldif`), and SimpleAuth extracts the CN — so the
  assignment is keyed by the bare group name, exactly as in production.

> Not wired into CI by design — it's a local/manual harness (`make up` to explore,
> `make test` to assert). Run it when you touch the migration paths.
