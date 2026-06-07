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

## Topology (phase 1)

| Service | Role | Store | TLS |
|---|---|---|---|
| `postgres` | central's database | — | — |
| `central` | the ONE centralized SimpleAuth | Postgres | serves HTTPS (cert SAN=`central`,`localhost`,`127.0.0.1`) |
| `standalone-local` | a local-accounts deployment that migrates in | BoltDB | plain HTTP internally |

Published to the host (loopback only): central `https://localhost:9443`,
standalone `http://localhost:9444`.

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
   `invoice:write`, `aud=billing`.

## Phase 2 (planned)

Add `ldap-corp` / `ldap-other` (seeded with `sAMAccountName`/`memberOf` via LDIF)
and standalones for: **same-AD** (policy-only migration, AD re-bind), **different
AD** (preflight blocks), and a **direct app** registered straight on the central.
