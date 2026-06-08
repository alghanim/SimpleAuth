# Integration harness — standalone → central migration

A self-contained, multi-container environment that exercises the v2.2 migration
feature end to end, across real container boundaries (real TLS, real HTTP push) —
the parts the Go unit tests can't reach. **It does not touch the production
`docker-compose.yml` at the repo root.**

```bash
cd test/integration
make test      # up + run the Go scenario driver + tear down
make up        # just stand up the env; browse https://localhost:9443/admin
make down      # tear down + wipe volumes
make logs      # follow logs
```

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
standalone-local `:9444`, standalone-ad `:9445`, standalone-addiff `:9446`.

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
