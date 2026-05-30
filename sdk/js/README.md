# @simpleauth/js

Zero-dependency JavaScript/TypeScript SDK for [SimpleAuth](https://github.com/bodaay/SimpleAuth). Works in Node.js (18+) and browsers.

> **Important:**
> - Access tokens expire in **15 minutes** — implement token refresh
> - URL must include the base path `/sauth` (e.g. `https://auth.example.com/sauth`)
> - `adminKey` is required for admin operations (roles, permissions, bootstrap)

## Installation

```bash
npm install @simpleauth/js
```

## Quick Start

```ts
import { SimpleAuth } from '@simpleauth/js';

const auth = new SimpleAuth({
  url: 'https://auth.corp.local/sauth',
});
```

> **Note:** The default access token TTL is **15 minutes**. Applications should implement proper token refresh using the `refresh` method before the access token expires, rather than relying on long-lived tokens.

## Authentication

### Password Login

Sends `POST /api/auth/login` with a JSON body.

```ts
const tokens = await auth.login('username', 'password');
console.log(tokens.access_token);
console.log(tokens.refresh_token);
```

### Handling Force Password Change

The login response may indicate that the user must change their password before proceeding:

```ts
const tokens = await auth.login('username', 'password');
if (tokens.force_password_change) {
  // Redirect user to password change page
}
```

### Refresh Token

Sends `POST /api/auth/refresh` with a JSON body.

```ts
const newTokens = await auth.refresh(tokens.refresh_token);
```

### Logout

```ts
await auth.logout(tokens.id_token);
```

> **Hosted login flow with auto-SSO:** If your app uses the SimpleAuth hosted login page, redirect users to `/logout?redirect_uri=...` instead of `/login?redirect_uri=...` when logging out. This clears SSO cookies and prevents auto-SSO from immediately re-authenticating the user.

## Token Verification (Server-Side)

Verify a JWT access token using the server's JWKS (fetched from `GET /.well-known/jwks.json`). The SDK caches JWKS keys for 1 hour and automatically re-fetches on key ID miss.

```ts
const user = await auth.verify(tokens.access_token);

console.log(user.sub);           // GUID
console.log(user.name);          // Display name
console.log(user.email);
console.log(user.roles);         // ['admin', 'editor']
console.log(user.permissions);   // ['read', 'write']
console.log(user.groups);        // ['engineering']
console.log(user.department);
console.log(user.company);
console.log(user.job_title);

// Helper methods
user.hasRole('admin');            // true
user.hasPermission('write');      // true
user.hasAnyRole('admin', 'mod'); // true
```

## User Info

Fetch user claims from `GET /api/auth/userinfo`:

```ts
const info = await auth.userInfo(tokens.access_token);
```

## Express Middleware

Protect your Express routes with automatic JWT verification:

```ts
import express from 'express';
import { SimpleAuth } from '@simpleauth/js';

const app = express();
const auth = new SimpleAuth({
  url: 'https://auth.corp.local/sauth',
});

// Require authentication (returns 401 if no valid token)
app.get('/api/protected', auth.expressMiddleware(), (req, res) => {
  const user = req.user; // SimpleAuthUser
  res.json({ message: `Hello ${user.name}` });
});

// Optional authentication (continues without user if no token)
app.get('/api/public', auth.expressMiddleware({ required: false }), (req, res) => {
  if (req.user) {
    res.json({ message: `Hello ${req.user.name}` });
  } else {
    res.json({ message: 'Hello anonymous' });
  }
});
```

### Role-Based Access Control

```ts
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !req.user.hasAnyRole(...roles)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

app.get('/api/admin',
  auth.expressMiddleware(),
  requireRole('admin'),
  (req, res) => {
    res.json({ admin: true });
  }
);
```

## Admin Operations

Admin operations require the admin key. The key is sent as a Bearer token (not Basic auth) to the SimpleAuth admin API.

### Get User

```ts
const user = await auth.getUser('user-guid-here');
```

### Roles

```ts
// Get roles for a user
const roles = await auth.getUserRoles('user-guid');

// Set roles
await auth.setUserRoles('user-guid', ['admin', 'editor']);
```

### Permissions

```ts
// Get permissions for a user
const perms = await auth.getUserPermissions('user-guid');

// Set permissions
await auth.setUserPermissions('user-guid', ['read', 'write', 'delete']);
```

> **Note:** Roles and permissions must be defined in SimpleAuth before they can be assigned to users. Use the admin API to define roles (`PUT /api/admin/role-permissions`) and permissions (`PUT /api/admin/permissions`) first, or define them in the Admin UI under Roles & Permissions.

## v2: Per-App Management

In v2, an **app** is an OAuth client identified by `app_id` + `app_secret`. An app self-manages its own authorization via the `/api/app/*` endpoints, authenticated with **HTTP Basic** (`app_id:app_secret`) — no master admin key required. The `app_id` is taken from the credential, so an app can only ever read or write its own scope.

Construct the client with `appId`, `appSecret`, and `audience` (set `audience` to the app so `verify()` rejects tokens minted for other apps):

```ts
const auth = new SimpleAuth({
  url: 'https://auth.example.com/sauth',
  appId: process.env.SIMPLEAUTH_APP_ID,
  appSecret: process.env.SIMPLEAUTH_APP_SECRET,
  audience: process.env.SIMPLEAUTH_APP_ID, // verify() rejects other apps' tokens
});
```

### Bootstrap (authz-as-code)

`appBootstrap` is **idempotent** — call it on startup / every deploy to converge the app's roles, permissions, and assignments to the declared state:

```ts
await auth.appBootstrap({
  roles: ['admin', 'viewer'],
  permissions: ['invoice:read', 'invoice:write'],
  role_permissions: {
    admin: ['invoice:read', 'invoice:write'],
    viewer: ['invoice:read'],
  },
  assignments: [
    { group: 'Finance', roles: ['admin'] },   // directory group -> roles
    { user: 'jsmith', roles: ['viewer'] },     // directory user  -> roles
  ],
});
```

### Read / Replace Authz & Settings

```ts
const authz = await auth.getAppAuthz();   // { app_id, roles, permissions, role_permissions, user_assignments, group_assignments }
await auth.setAppAuthz(authz);            // PUT — replaces the app's authz

const settings = await auth.appSettings(); // read-only policy view (no secret)
```

### App-Local Users

When the app has `allow_local_users` enabled, it can own users that aren't in your directory (e.g. a customer portal). They authenticate locally and only ever receive `aud=<the app>` tokens.

```ts
const user = await auth.createLocalUser({
  username: 'customer1',
  password: '…',
  display_name: 'Customer One',
  roles: ['viewer'],
});

const users = await auth.listLocalUsers();
await auth.setLocalUserPassword(user.guid, 'new-password');
await auth.deleteLocalUser(user.guid);
```

All app-management methods throw `SimpleAuthError` if `appId`/`appSecret` are not configured. See [`examples/js/app-integration.ts`](../../examples/js/app-integration.ts) for a full integration.

## Error Handling

All methods throw `SimpleAuthError` on failure:

```ts
import { SimpleAuthError } from '@simpleauth/js';

try {
  await auth.login('bad-user', 'bad-pass');
} catch (err) {
  if (err instanceof SimpleAuthError) {
    console.error(err.message);      // Human-readable message
    console.error(err.status);       // HTTP status code
    console.error(err.code);         // OAuth2 error code (e.g. 'invalid_grant')
    console.error(err.description);  // OAuth2 error description
  }
}
```

## Configuration

| Option         | Type     | Required | Default         | Description                              |
|----------------|----------|----------|-----------------|------------------------------------------|
| `url`          | `string` | Yes      | --              | SimpleAuth server URL (include `/sauth` base path, e.g. `https://auth.example.com/sauth`) |
| `adminKey`     | `string` | No       | --              | Admin key for admin API operations (sent as Bearer token) |
| `appId`        | `string` | No       | --              | App (OAuth client) id for v2 per-app management (`/api/app/*`), sent with `appSecret` as HTTP Basic |
| `appSecret`    | `string` | No       | --              | App secret paired with `appId` (credential — do not embed in browser code) |
| `audience`     | `string` | No       | --              | If set, `verify()` requires this value in the token's `aud` claim (set to the app to reject other apps' tokens) |
| `expectedIssuer` | `string` | No     | --              | If set, `verify()` requires the token's `iss` claim to equal this value |

## Browser Usage

The SDK works in browsers without any bundler configuration. It uses the native `fetch` API and `SubtleCrypto` for RS256 token verification.

```html
<script type="module">
import { SimpleAuth } from './index.js';

const auth = new SimpleAuth({
  url: 'https://auth.corp.local/sauth',
});

const tokens = await auth.login('username', 'password');
</script>
```

> **Note:** Do not include `adminKey` in browser code. For browser-based applications, use the hosted login page redirect flow at `/login` instead of embedding credentials.

## Platform Support

- **Node.js** 18+ (uses native `fetch` and `crypto.subtle` or `crypto` module)
- **Browsers** -- all modern browsers with `fetch` and `SubtleCrypto` support
- **Deno** -- compatible via npm specifier
- **Bun** -- compatible
