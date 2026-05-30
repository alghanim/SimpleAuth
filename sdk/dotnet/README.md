# SimpleAuth .NET SDK

.NET 8 SDK for [SimpleAuth](https://github.com/bodaay/SimpleAuth). JWT verification with JWKS caching, admin operations, and ASP.NET Core middleware.

> **Important:**
> - Access tokens expire in **15 minutes** — implement token refresh
> - URL must include the base path `/sauth` (e.g. `https://auth.example.com/sauth`)
> - `AdminKey` is required for admin operations (roles, permissions, bootstrap)

## Installation

Add a project reference or package reference:

```xml
<PackageReference Include="SimpleAuth" Version="1.0.0" />
```

## Quick Start

### Standalone Client

```csharp
using SimpleAuth;

var client = new SimpleAuthClient(new SimpleAuthOptions
{
    Url = "https://auth.corp.local/sauth",
});

// Password login
var tokens = await client.LoginAsync("alice", "password123");
Console.WriteLine(tokens.AccessToken);

// Verify a token (JWKS is cached automatically)
var user = await client.VerifyAsync(tokens.AccessToken);
Console.WriteLine($"Hello, {user.Name}");
Console.WriteLine($"Is admin? {user.HasRole("admin")}");
```

### ASP.NET Core Integration

**Program.cs:**

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSimpleAuth(options =>
{
    options.Url = "https://auth.corp.local/sauth";
});

var app = builder.Build();

app.UseSimpleAuth();
app.MapControllers();
app.Run();
```

**Controller:**

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SimpleAuth;

[ApiController]
[Route("api/[controller]")]
public class ProfileController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        var user = HttpContext.GetSimpleAuthUser();
        if (user is null)
            return Unauthorized();

        return Ok(new { user.Name, user.Email, user.Roles });
    }

    [HttpGet("admin")]
    [SimpleAuthRole("admin")]
    public IActionResult Admin()
    {
        return Ok("You are an admin.");
    }

    [HttpGet("reports")]
    [SimpleAuthPermission("reports:read")]
    public IActionResult Reports()
    {
        return Ok("Here are your reports.");
    }
}
```

> **Note:** The default access token TTL is **15 minutes**. Applications should implement proper token refresh using the `RefreshAsync` method before the access token expires, rather than relying on long-lived tokens.

## Authentication Flows

### Password Login

Sends `POST /api/auth/login` with a JSON body.

```csharp
var tokens = await client.LoginAsync("alice", "password123");
```

### Handling Force Password Change

The login response may indicate that the user must change their password before proceeding:

```csharp
var tokens = await client.LoginAsync("alice", "password123");
if (tokens.ForcePasswordChange)
{
    // Redirect user to change their password
}
```

### Refresh Token

Sends `POST /api/auth/refresh` with a JSON body.

```csharp
var newTokens = await client.RefreshAsync(tokens.RefreshToken);
```

## Token Verification

Tokens are verified locally using RS256. JWKS keys are fetched from `GET /.well-known/jwks.json` and cached for 1 hour. If a token contains a `kid` that is not in the cache, the SDK automatically re-fetches the JWKS endpoint.

```csharp
var user = await client.VerifyAsync(accessToken);
// Checks: RS256 signature, exp claim, iss claim
```

## User Info

```csharp
var info = await client.UserInfoAsync(tokens.AccessToken);
```

## Admin Operations

Admin operations require the admin key. The key is sent as a Bearer token (not Basic auth) to the SimpleAuth admin API.

```csharp
// Roles
var roles = await client.GetUserRolesAsync(userGuid);
await client.SetUserRolesAsync(userGuid, new List<string> { "admin", "editor" });

// Permissions
var perms = await client.GetUserPermissionsAsync(userGuid);
await client.SetUserPermissionsAsync(userGuid, new List<string> { "reports:read", "reports:write" });
```

> **Note:** Roles and permissions must be defined in SimpleAuth before they can be assigned to users. Use the admin API to define roles (`PUT /api/admin/role-permissions`) and permissions (`PUT /api/admin/permissions`) first, or define them in the Admin UI under Roles & Permissions.

## v2: Per-App Management

In SimpleAuth v2 an **app** is an OAuth client (`app_id` + `app_secret`) that self-manages its own authorization: its roles, permissions, the role→permission map, and which directory users / AD groups are assigned. Tokens are scoped to the app via the `aud` claim, so **a token minted for app A is rejected by app B**.

A developer's whole integration is: get `app_id` / `app_secret` from the admin → `bootstrap` roles on deploy → point the SDK at SimpleAuth with `Audience` set to the app → `VerifyAsync()`.

Construct the client as an app and set `Audience` to the app id so `VerifyAsync` rejects tokens minted for other apps. The `/api/app/*` calls authenticate with HTTP Basic `app_id:app_secret` under the hood; the `app_id` is derived from the credential, so an app can only ever touch its own scope.

```csharp
using SimpleAuth;

using var client = new SimpleAuthClient(new SimpleAuthOptions
{
    Url = "https://auth.corp.local/sauth",
    AppId = Environment.GetEnvironmentVariable("SIMPLEAUTH_APP_ID"),       // never hardcode
    AppSecret = Environment.GetEnvironmentVariable("SIMPLEAUTH_APP_SECRET"),
    Audience = Environment.GetEnvironmentVariable("SIMPLEAUTH_APP_ID"),     // reject other apps' tokens
});

// Bootstrap is idempotent -- safe to run on every deploy (authz-as-code).
await client.AppBootstrapAsync(new BootstrapSpec
{
    Roles = ["admin", "viewer"],
    RolePermissions = new Dictionary<string, List<string>>
    {
        ["admin"] = ["invoice:write", "invoice:read"],
        ["viewer"] = ["invoice:read"],
    },
    Assignments =
    [
        new Assignment { Group = "Finance", Roles = ["admin"] },   // AD group -> admin
        new Assignment { User = "jsmith", Roles = ["viewer"] },    // directory user -> viewer
    ],
});

// Read / replace this app's authorization, and read its settings.
AppAuthz authz = await client.GetAppAuthzAsync();
await client.SetAppAuthzAsync(authz);
AppSettings settings = await client.AppSettingsAsync();

// Verify an incoming token -- its roles/permissions are this app's, resolved
// per app at issuance. A token whose `aud` is a different app is rejected.
var user = await client.VerifyAsync(accessToken);
Console.WriteLine($"Is admin in this app? {user.HasRole("admin")}");
```

### App-local users

If the app's `allow_local_users` flag is set, it can own **local users that aren't in the directory** (e.g. a customer portal). They authenticate locally, only ever receive `aud=<the app>` tokens, and are not shared via cross-app SSO.

```csharp
LocalUser u = await client.CreateLocalUserAsync(
    "customer1", "S3cret!", displayName: "Customer One", roles: ["viewer"]);

List<LocalUser> users = await client.ListLocalUsersAsync();
await client.SetLocalUserPasswordAsync(u.Guid, "newS3cret!");
await client.DeleteLocalUserAsync(u.Guid);
```

> **Note:** The app-management methods throw `SimpleAuthException` if `AppId`/`AppSecret` are unset. See the runnable [`examples/dotnet/AppIntegration`](../../examples/dotnet/AppIntegration) example.

## Authorization Attributes

Use `[SimpleAuthRole]` and `[SimpleAuthPermission]` on controllers or actions:

```csharp
[SimpleAuthRole("admin")]
[SimpleAuthPermission("users:manage")]
public class AdminController : ControllerBase { ... }
```

Multiple attributes are evaluated independently -- each one must pass.

## SSL Validation

To disable SSL certificate validation (development only):

```csharp
var client = new SimpleAuthClient(new SimpleAuthOptions
{
    Url = "https://localhost/sauth",
    ValidateSsl = false,
});
```

## Configuration

| Option         | Type     | Required | Default         | Description                              |
|----------------|----------|----------|-----------------|------------------------------------------|
| `Url`          | `string` | Yes      | --              | SimpleAuth server URL (include `/sauth` base path, e.g. `https://auth.example.com/sauth`) |
| `AdminKey`     | `string` | No       | `""`            | Admin key for admin API operations (sent as Bearer token) |
| `AppId`        | `string` | No       | `""`            | App's OAuth client id for v2 per-app management (`/api/app/*`, HTTP Basic) |
| `AppSecret`    | `string` | No       | `""`            | App's OAuth client secret for v2 per-app management (never hardcode) |
| `Audience`     | `string` | No       | `null`          | If set, `VerifyAsync` requires this value in the token's `aud` claim (set to the app id) |
| `ExpectedIssuer` | `string` | No     | `null`          | If set, `VerifyAsync` requires the token's `iss` claim to equal this value |
| `ValidateSsl`  | `bool`   | No       | `true`          | Whether to validate SSL certificates     |

## Error Handling

All errors throw `SimpleAuthException`:

```csharp
try
{
    var user = await client.VerifyAsync(token);
}
catch (SimpleAuthException ex)
{
    Console.WriteLine($"Auth failed: {ex.Message}");
}
```
