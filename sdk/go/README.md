# simpleauth-go

Go SDK for [SimpleAuth](https://github.com/bodaay/SimpleAuth) — a lightweight authentication server.

> **Important:**
> - Access tokens expire in **15 minutes** — implement token refresh
> - URL must include the base path `/sauth` (e.g. `https://auth.example.com/sauth`)
> - `AdminKey` is required for admin operations (roles, permissions, bootstrap)

Zero external dependencies. Uses only the Go standard library.

## Install

```bash
go get github.com/bodaay/simpleauth-go
```

Requires **Go 1.21+**.

## Quick start

```go
package main

import (
    "context"
    "fmt"
    "log"

    sa "github.com/bodaay/simpleauth-go"
)

func main() {
    client := sa.New(sa.Options{
        URL: "https://auth.example.com/sauth",
    })

    // Password login
    tok, err := client.Login(context.Background(), "alice", "password123")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Access token:", tok.AccessToken)

    // Verify the token locally (RS256 + JWKS)
    user, err := client.Verify(tok.AccessToken)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Hello,", user.PreferredUsername)
}
```

> **Note:** The default access token TTL is **15 minutes**. Applications should implement proper token refresh using the `Refresh` method before the access token expires, rather than relying on long-lived tokens.

## Authentication flows

### Password Login

```go
tok, err := client.Login(ctx, "username", "password")
```

Sends `POST /api/auth/login` with a JSON body `{"username": "...", "password": "..."}`.

### Refresh Token

```go
tok, err := client.Refresh(ctx, tok.RefreshToken)
```

Sends `POST /api/auth/refresh` with a JSON body.

## Handling Force Password Change

The login response may indicate that the user must change their password before proceeding:

```go
// Handle force password change
tok, err := client.Login(ctx, "alice", "password123")
if tok.ForcePasswordChange {
    // Redirect user to change their password before proceeding
}
```

## Token verification

`Verify` decodes and cryptographically verifies a JWT using the RS256 algorithm. Public keys are fetched from `GET /.well-known/jwks.json` and cached for one hour. A cache miss on the `kid` header triggers an automatic re-fetch.

```go
user, err := client.Verify(accessToken)
if err != nil {
    // invalid or expired token
}

fmt.Println(user.Sub, user.Email, user.Roles)
```

## User helpers

```go
if user.HasRole("admin") { ... }
if user.HasPermission("documents:write") { ... }
if user.HasAnyRole("admin", "editor") { ... }
```

## UserInfo endpoint

Fetches user claims from `GET /api/auth/userinfo`.

```go
info, err := client.UserInfo(ctx, accessToken)
```

## HTTP middleware

The SDK provides middleware for `net/http` that validates the `Authorization: Bearer <token>` header on every request.

### Basic authentication middleware

```go
mux := http.NewServeMux()
mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
    user := sa.UserFromContext(r.Context())
    fmt.Fprintf(w, "Hello %s", user.PreferredUsername)
})

// Wrap with auth middleware
http.ListenAndServe(":8080", client.Middleware(mux))
```

### Role / permission gates

```go
adminOnly := client.RequireRole("admin", adminHandler)
canWrite  := client.RequirePermission("documents:write", writeHandler)

mux.Handle("/admin", adminOnly)
mux.Handle("/write", canWrite)
```

Unauthenticated requests receive **401 Unauthorized**. Requests that lack the required role or permission receive **403 Forbidden**.

## Admin operations

Manage user roles and permissions via the SimpleAuth admin API. Admin operations require the admin key -- it is sent as a Bearer token (not Basic auth) to authenticate with the admin API.

```go
roles, err := client.GetUserRoles(ctx, userGUID)
err = client.SetUserRoles(ctx, userGUID, []string{"admin", "editor"})

perms, err := client.GetUserPermissions(ctx, userGUID)
err = client.SetUserPermissions(ctx, userGUID, []string{"read", "write"})
```

> **Note:** Roles and permissions must be defined in SimpleAuth before they can be assigned to users. Use the admin API to define roles (`PUT /api/admin/role-permissions`) and permissions (`PUT /api/admin/permissions`) first, or define them in the Admin UI under Roles & Permissions.

## v2: per-app management

In v2 an **app** is an OAuth client (`app_id` + `app_secret`) that owns its own roles, permissions, and assignments. Apps self-manage their authorization under `/api/app/*` using **HTTP Basic** `app_id:app_secret` — no admin key, and an app can only ever touch its own scope (the `app_id` is derived from the credential server-side).

A token minted for app A is useless on app B. Set `Audience` to the app's `app_id`/audience so `Verify` rejects tokens issued for any other app:

```go
client := sa.New(sa.Options{
    URL:       "https://auth.example.com/sauth",
    AppID:     "billing",
    AppSecret: os.Getenv("SIMPLEAUTH_APP_SECRET"), // never hardcode
    Audience:  "billing",                          // reject tokens for other apps
})
```

### Bootstrap (authz-as-code)

`AppBootstrap` declares this app's roles, permissions, the role→permission map, and assignments. It is idempotent and safe to call on every deploy:

```go
res, err := client.AppBootstrap(ctx, sa.BootstrapSpec{
    Roles:       []string{"admin", "viewer"},
    Permissions: []string{"invoice:read", "invoice:write"},
    RolePermissions: map[string][]string{
        "admin":  {"invoice:read", "invoice:write"},
        "viewer": {"invoice:read"},
    },
    Assignments: []sa.Assignment{
        {Group: "Finance", Roles: []string{"admin"}},  // AD group -> admin
        {User: "jsmith", Roles: []string{"viewer"}},   // directory user -> viewer
    },
})
```

### Read / replace authz and read settings

```go
authz, err := client.GetAppAuthz(ctx)              // GET  /api/app/authz
authz, err = client.SetAppAuthz(ctx, *authz)       // PUT  /api/app/authz (replace; AppID may be empty)
settings, err := client.AppSettings(ctx)           // GET  /api/app/settings
```

### App-local users

If the app has `allow_local_users` set, it can provision its own users (e.g. a customer portal). App-local usernames are unique per app, only ever get `aud=<this app>` tokens, and are exempt from `require_assignment`:

```go
u, err := client.CreateLocalUser(ctx, "customer1", "S3cret!", "Customer One", "", []string{"viewer"})
users, err := client.ListLocalUsers(ctx)
err = client.SetLocalUserPassword(ctx, u.GUID, "newS3cret!")
err = client.DeleteLocalUser(ctx, u.GUID)
```

All app-management methods return a clear error if `AppID`/`AppSecret` are unset. See [`examples/go/app-integration`](../../examples/go/app-integration) for a full, self-contained example.

## Self-signed certificates

For development environments with self-signed TLS certificates:

```go
client := sa.New(sa.Options{
    URL:                "https://localhost:8443/sauth",
    InsecureSkipVerify: true,
})
```

## Embedding SimpleAuth in your Go app

Instead of running SimpleAuth as a separate binary, you can embed it directly into your Go application. The full auth server (REST API, admin UI, JWT issuance) runs inside your process.

```go
import (
    "simpleauth/pkg/server"
    "simpleauth/ui"
)

// Programmatic config — full control, no env vars read
cfg := server.Defaults()
cfg.Hostname = "myapp.example.com"
cfg.AdminKey = "my-secret-key"
cfg.DataDir = "./auth-data"
cfg.BasePath = "/auth"
cfg.TLSDisabled = true

sa, err := server.New(cfg, ui.FS()) // pass nil instead of ui.FS() for API-only
if err != nil {
    log.Fatal(err)
}
defer sa.Close()

// Or load from env vars / config file (same as standalone binary):
// sa, err := server.New(nil, ui.FS())

// Mount on your router
mux.Handle("/auth/", http.StripPrefix("/auth", sa.Handler()))
```

`server.Config` is the same struct used by the standalone binary — every field is available. `server.Defaults()` gives you sensible defaults, modify only what you need. Pass `nil` to `New()` to load from env vars instead.

## Configuration reference

| Field | Description | Default |
|---|---|---|
| `URL` | SimpleAuth server base URL (include `/sauth` base path, e.g. `https://auth.example.com/sauth`) | *(required)* |
| `AdminKey` | Admin key for admin API operations (sent as Bearer token) | `""` |
| `AppID` | App's `app_id` for v2 per-app management (sent as HTTP Basic username to `/api/app/*`) | `""` |
| `AppSecret` | App's `app_secret` for v2 per-app management (HTTP Basic password) | `""` |
| `ExpectedIssuer` | Required `iss` claim on verified tokens (empty = skip check) | `""` |
| `Audience` | Required `aud` claim on verified tokens — set to the app's `app_id` (empty = skip check) | `""` |
| `InsecureSkipVerify` | Skip TLS certificate verification | `false` |
