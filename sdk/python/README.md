# SimpleAuth Python SDK

Python SDK for [SimpleAuth](https://github.com/bodaay/SimpleAuth) — a lightweight authentication server.

> **Important:**
> - Access tokens expire in **15 minutes** — implement token refresh
> - URL must include the base path `/sauth` (e.g. `https://auth.example.com/sauth`)
> - `admin_key` is required for admin operations (roles, permissions, bootstrap)

## Installation

```bash
pip install simpleauth

# With framework extras:
pip install simpleauth[fastapi]
pip install simpleauth[flask]
pip install simpleauth[django]
```

## Quick Start

```python
from simpleauth import SimpleAuth

auth = SimpleAuth(
    url="https://auth.example.com/sauth",
)
```

> **Note:** The default access token TTL is **15 minutes**. Applications should implement proper token refresh using the `refresh` method before the access token expires, rather than relying on long-lived tokens.

## Authentication

### Password Login

Sends `POST /api/auth/login` with a JSON body.

```python
tokens = auth.login(username="alice", password="secret")
print(tokens.access_token)
print(tokens.refresh_token)
```

### Handling Force Password Change

The login response may indicate that the user must change their password before proceeding:

```python
tokens = auth.login(username="alice", password="secret")
if tokens.force_password_change:
    # Redirect user to password change page
```

### Refresh Token

Sends `POST /api/auth/refresh` with a JSON body.

```python
new_tokens = auth.refresh(refresh_token=tokens.refresh_token)
```

## Token Verification

Verify a JWT access token locally using the server's JWKS from `GET /.well-known/jwks.json` (cached for 1 hour, re-fetched on key ID miss):

```python
user = auth.verify(tokens.access_token)

print(user.sub)           # user GUID
print(user.name)          # display name
print(user.email)
print(user.roles)         # ["admin", "editor"]
print(user.permissions)   # ["read:posts", "write:posts"]
print(user.groups)        # LDAP groups
print(user.department)
print(user.company)
print(user.job_title)

# Role/permission checks
if user.has_role("admin"):
    print("User is admin")

if user.has_permission("write:posts"):
    print("User can write posts")

if user.has_any_role("admin", "editor"):
    print("User is admin or editor")
```

## User Info

Fetch user info from `GET /api/auth/userinfo` (requires a valid access token):

```python
info = auth.userinfo(access_token=tokens.access_token)
```

## Admin Operations

Manage user roles and permissions (requires admin key). The key is sent as a Bearer token (not Basic auth) to the SimpleAuth admin API:

```python
# Roles
roles = auth.get_user_roles(guid="user-guid")
auth.set_user_roles(guid="user-guid", roles=["admin", "editor"])

# Permissions
perms = auth.get_user_permissions(guid="user-guid")
auth.set_user_permissions(guid="user-guid", permissions=["read:posts", "write:posts"])
```

> **Note:** Roles and permissions must be defined in SimpleAuth before they can be assigned to users. Use the admin API to define roles (`PUT /api/admin/role-permissions`) and permissions (`PUT /api/admin/permissions`) first, or define them in the Admin UI under Roles & Permissions.

## v2: Per-App Management

In SimpleAuth v2 an **app** is an OAuth client (`app_id` + `app_secret`) that self-manages its **own** authorization — its roles, permissions, and which directory users / AD groups are assigned to it. Tokens are scoped to the app via the `aud` claim, so **a token minted for app A is rejected by app B**.

Construct the client with `app_id` / `app_secret` (the app credential) and `audience`. The app helpers authenticate to `/api/app/*` with HTTP Basic `app_id:app_secret`; the `app_id` is derived from the credential, so an app can only ever touch its own scope. No master admin key is involved.

> **Set `audience` to your app.** `verify()` only rejects foreign-app tokens when `audience` is configured — a missing `aud` check would let another app's token through.

```python
from simpleauth import SimpleAuth

auth = SimpleAuth(
    url="https://auth.example.com/sauth",
    app_id="billing",
    app_secret="...",         # from your secret store
    audience="billing",       # verify() rejects tokens whose aud != "billing"
)
```

### Bootstrap (authz-as-code)

`app_bootstrap` is idempotent — call it on every deploy to declare the app's roles, role→permission map, and assignments:

```python
auth.app_bootstrap(
    roles=["admin", "viewer"],
    role_permissions={"admin": ["invoice:write"], "viewer": ["invoice:read"]},
    assignments=[
        {"group": "Finance", "roles": ["admin"]},   # group = sAMAccountName by default
        {"user": "jsmith", "roles": ["viewer"]},     # user = GUID / sAMAccountName / username
    ],
)
```

### Read / replace authorization

```python
authz = auth.get_app_authz()       # -> AppAuthz(roles, permissions, role_permissions,
                                   #             user_assignments, group_assignments)

authz.user_assignments["alice"] = ["viewer"]
auth.set_app_authz(authz)          # PUT (full replace); app_id in the body is ignored

settings = auth.app_settings()     # read-only view (no secret), e.g. require_assignment
```

### App-local users (requires `allow_local_users`)

For users that aren't in your directory (e.g. a customer portal). They authenticate locally, only ever get `aud=<this app>` tokens, are **not** SSO-shared, and are exempt from `require_assignment`:

```python
created = auth.create_local_user(
    "customer1", "s3cr3t!",
    display_name="Customer One",
    email="c1@example.com",
    roles=["viewer"],
)
guid = created["guid"]

auth.list_local_users()
auth.set_local_user_password(guid, "new-s3cr3t!")
auth.delete_local_user(guid)
```

All app helpers raise `AppError` (subclass of `SimpleAuthError`) if `app_id`/`app_secret` are missing or the request fails. See [`examples/python/app_integration.py`](../../examples/python/app_integration.py) for a full runnable example.

## Framework Middleware

### FastAPI

```python
from fastapi import Depends, FastAPI
from simpleauth import SimpleAuth, User
from simpleauth.middleware import SimpleAuthDep

auth = SimpleAuth(url="https://auth.example.com/sauth")

# Create a dependency
get_user = SimpleAuthDep(auth)

# Or with a role requirement
require_admin = SimpleAuthDep(auth, required_role="admin")

app = FastAPI()

@app.get("/me")
async def me(user: User = Depends(get_user)):
    return {"sub": user.sub, "name": user.name, "roles": user.roles}

@app.get("/admin")
async def admin(user: User = Depends(require_admin)):
    return {"admin": user.name}
```

### Flask

```python
from flask import Flask, g, jsonify
from simpleauth import SimpleAuth
from simpleauth.middleware import flask_middleware

auth = SimpleAuth(url="https://auth.example.com/sauth")
app = Flask(__name__)

@app.route("/me")
@flask_middleware(auth)
def me():
    user = g.user
    return jsonify({"sub": user.sub, "name": user.name})

@app.route("/admin")
@flask_middleware(auth, required_role="admin")
def admin():
    return jsonify({"admin": g.user.name})
```

### Django

Add the middleware to `settings.py`:

```python
# settings.py
MIDDLEWARE = [
    ...
    "simpleauth.middleware.SimpleAuthMiddleware",
]

SIMPLEAUTH_URL = "https://auth.example.com/sauth"
SIMPLEAUTH_ADMIN_KEY = ""           # optional — only needed for admin operations
SIMPLEAUTH_VERIFY_SSL = True        # optional
```

Use in views:

```python
from simpleauth.middleware import django_login_required

@django_login_required()
def my_view(request):
    user = request.simpleauth_user
    return JsonResponse({"sub": user.sub, "name": user.name})

@django_login_required(required_role="admin")
def admin_view(request):
    return JsonResponse({"admin": request.simpleauth_user.name})
```

## Self-Signed Certificates

For development with self-signed TLS certificates:

```python
auth = SimpleAuth(
    url="https://localhost:8443/sauth",
    verify_ssl=False,
)
```

## Error Handling

```python
from simpleauth import SimpleAuth, AuthenticationError, TokenVerificationError, SimpleAuthError

auth = SimpleAuth(url="https://auth.example.com/sauth")  # include /sauth base path

try:
    tokens = auth.login("alice", "wrong-password")
except AuthenticationError as e:
    print(f"Login failed: {e} (status={e.status_code})")

try:
    user = auth.verify("invalid-token")
except TokenVerificationError as e:
    print(f"Token invalid: {e}")
```

## Dependencies

- `requests` -- HTTP client
- `cryptography` -- RSA/JWKS signature verification

No JWT library is used. Tokens are parsed manually (base64url-decode header + payload) and RS256 signatures are verified directly using `cryptography`.

## License

MIT
