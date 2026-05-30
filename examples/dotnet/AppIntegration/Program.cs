// AppIntegration/Program.cs -- v2 per-app management with SimpleAuth (.NET).
//
// In SimpleAuth v2 an *app* is an OAuth client (app_id + app_secret) that
// self-manages its own authorization: its roles, permissions, and which
// directory users / AD groups are assigned to it. Tokens are scoped to the app
// via the `aud` claim, so a token minted for app A is rejected by app B.
//
// A developer's whole integration is:
//   1. Get app_id / app_secret from the SimpleAuth admin.
//   2. Declare the app's roles + assignments on deploy with AppBootstrapAsync
//      (idempotent -- safe to run on every startup).
//   3. Point the SDK at SimpleAuth with Audience set to the app, then
//      VerifyAsync() incoming tokens -- foreign-app tokens are rejected because
//      their `aud` won't match.
//
// Authentication to /api/app/* uses HTTP Basic app_id:app_secret under the hood;
// the app_id is derived from the credential, so this app can only ever touch its
// own scope.
//
// Prerequisites:
//   dotnet add reference to the SimpleAuth SDK project
//   (see AppIntegration.csproj for project reference setup)
//
// Environment variables (no secrets in code):
//   SIMPLEAUTH_URL         SimpleAuth server URL incl. /sauth base path
//                          (default: https://auth.example.com/sauth)
//   SIMPLEAUTH_APP_ID      This app's app_id     (required)
//   SIMPLEAUTH_APP_SECRET  This app's app_secret (required; never hardcode)
//   SIMPLEAUTH_AUDIENCE    Expected token audience (default: SIMPLEAUTH_APP_ID)
//   SIMPLEAUTH_GROUP       Directory group to grant "admin" (default: Finance)
//   SIMPLEAUTH_TOKEN       Optional access token to verify at the end
//   SIMPLEAUTH_INSECURE    Set "true" to trust self-signed certs (dev only)
//
// Usage:
//   cd examples/dotnet/AppIntegration
//   SIMPLEAUTH_APP_ID=billing SIMPLEAUTH_APP_SECRET=sa_app_... dotnet run

using SimpleAuth;

// ---------------------------------------------------------------------------
// Configuration -- read everything from the environment
// ---------------------------------------------------------------------------

var url = Environment.GetEnvironmentVariable("SIMPLEAUTH_URL")
    ?? "https://auth.example.com/sauth";

// The app credential. Never hardcode these.
var appId = Environment.GetEnvironmentVariable("SIMPLEAUTH_APP_ID");
var appSecret = Environment.GetEnvironmentVariable("SIMPLEAUTH_APP_SECRET");

if (string.IsNullOrEmpty(appId) || string.IsNullOrEmpty(appSecret))
{
    Console.WriteLine(
        "Error: SIMPLEAUTH_APP_ID and SIMPLEAUTH_APP_SECRET are required.\n" +
        "Set this app's credentials and try again, e.g.:\n" +
        "  export SIMPLEAUTH_APP_ID=billing\n" +
        "  export SIMPLEAUTH_APP_SECRET=...   # from your secret store");
    return;
}

// The audience VerifyAsync requires. Defaults to the app id, which is what the
// server stamps into `aud` for this app in most deployments.
var audience = Environment.GetEnvironmentVariable("SIMPLEAUTH_AUDIENCE") ?? appId;

// A directory group to grant the "admin" role to (sAMAccountName by default).
var group = Environment.GetEnvironmentVariable("SIMPLEAUTH_GROUP") ?? "Finance";

// Optionally verify a real token at the end of the run.
var token = Environment.GetEnvironmentVariable("SIMPLEAUTH_TOKEN");

// Construct the client as an *app*: AppId/AppSecret authenticate the /api/app/*
// calls, and Audience makes VerifyAsync reject other apps' tokens.
var options = new SimpleAuthOptions
{
    Url = url,
    AppId = appId,
    AppSecret = appSecret,
    Audience = audience, // reject tokens minted for other apps
    // TLS verification stays ON by default; SIMPLEAUTH_INSECURE=true is dev-only.
    ValidateSsl = Environment.GetEnvironmentVariable("SIMPLEAUTH_INSECURE") != "true",
};

using var client = new SimpleAuthClient(options);

// ---------------------------------------------------------------------------
// Step 1: Bootstrap this app's authorization on startup (authz-as-code)
// ---------------------------------------------------------------------------
// Declare the roles this app understands, what each role can do, and who is
// assigned. This is idempotent and safe to run on every deploy -- it upserts.

Console.WriteLine($"[1] Bootstrapping app '{appId}' authorization (authz-as-code)...");

try
{
    var result = await client.AppBootstrapAsync(new BootstrapSpec
    {
        Roles = ["admin", "viewer"],
        Permissions = ["invoice:read", "invoice:write"],
        RolePermissions = new Dictionary<string, List<string>>
        {
            ["admin"] = ["invoice:read", "invoice:write"],
            ["viewer"] = ["invoice:read"],
        },
        Assignments =
        [
            // Grant everyone in the directory group the "admin" role.
            new Assignment { Group = group, Roles = ["admin"] },
            // And assign one named directory user the "viewer" role.
            new Assignment { User = "jsmith", Roles = ["viewer"] },
        ],
    });

    Console.WriteLine(
        $"  Bootstrapped app '{result.AppId}': {result.RolesCount} roles, " +
        $"{result.AssignmentsCount} assignments (status: {result.Status}).");
}
catch (SimpleAuthException ex)
{
    Console.WriteLine($"  Bootstrap failed: {ex.Message}");
    return;
}

// Read the app's authorization back to confirm what the server now stores.
try
{
    var authz = await client.GetAppAuthzAsync();
    Console.WriteLine($"  Roles:             [{string.Join(", ", authz.Roles)}]");
    Console.WriteLine($"  Permissions:       [{string.Join(", ", authz.Permissions)}]");
    Console.WriteLine($"  User assignments:  {authz.UserAssignments.Count}");
    Console.WriteLine($"  Group assignments: {authz.GroupAssignments.Count}");
}
catch (SimpleAuthException ex)
{
    Console.WriteLine($"  Could not read authz: {ex.Message}");
}

// The app's own settings (no secret) -- e.g. require_assignment.
try
{
    var settings = await client.AppSettingsAsync();
    Console.WriteLine($"  Name:               {settings.Name}");
    Console.WriteLine($"  Audience:           {settings.Audience}");
    Console.WriteLine($"  Require assignment: {settings.RequireAssignment}");
    Console.WriteLine($"  Allow local users:  {settings.AllowLocalUsers}");
}
catch (SimpleAuthException ex)
{
    Console.WriteLine($"  Could not read settings: {ex.Message}");
}

// If this app provisions its own users (allow_local_users), the app-local user
// methods are available, e.g.:
//
//   var u = await client.CreateLocalUserAsync("customer1", "S3cret!", "Customer One", null, ["viewer"]);
//   var users = await client.ListLocalUsersAsync();
//   await client.SetLocalUserPasswordAsync(u.Guid, "newS3cret!");
//   await client.DeleteLocalUserAsync(u.Guid);

// ---------------------------------------------------------------------------
// Step 2: Verify an incoming token and read its per-app roles
// ---------------------------------------------------------------------------
// In a real service this token arrives on each request (Authorization: Bearer
// ...). Because the client was built with Audience = this app's id, VerifyAsync
// rejects any token whose `aud` is a different app.

Console.WriteLine("\n[2] Token verification (audience-scoped)...");

// Anything not minted for this app fails to verify -- this is the RP-side check
// that makes a foreign-app token useless here. (We catch the broad Exception
// only because this token is deliberately malformed; a real, well-formed token
// that merely fails verification throws SimpleAuthException -- see Step 2 below.)
try
{
    await client.VerifyAsync("not.a.valid-token-for-this-app");
    Console.WriteLine("  WARNING: a foreign token verified -- check the Audience option.");
}
catch (Exception ex)
{
    Console.WriteLine($"  Rejected token not minted for '{audience}': {ex.Message}");
}

if (string.IsNullOrEmpty(token))
{
    Console.WriteLine(
        "\nSet SIMPLEAUTH_TOKEN to a token issued for this app to see " +
        "VerifyAsync read its per-app roles.");
    Console.WriteLine("\nDone.");
    return;
}

Console.WriteLine("\nVerifying the supplied access token...");
try
{
    var user = await client.VerifyAsync(token);
    Console.WriteLine($"  Token verified (aud matches '{audience}').");
    Console.WriteLine($"  Subject (GUID): {user.Sub}");
    Console.WriteLine($"  Username:       {user.PreferredUsername}");
    // roles/permissions here are this app's, resolved per app at issuance.
    Console.WriteLine($"  App roles:      [{string.Join(", ", user.Roles)}]");
    Console.WriteLine($"  App perms:      [{string.Join(", ", user.Permissions)}]");

    if (user.HasRole("admin"))
        Console.WriteLine("  -> user is an admin in this app");
    else if (user.HasRole("viewer"))
        Console.WriteLine("  -> user is a viewer in this app");
    else
        Console.WriteLine("  -> user has no role in this app");
}
catch (SimpleAuthException ex)
{
    // This is what a foreign-app token (wrong `aud`) looks like, too.
    Console.WriteLine($"  Token rejected: {ex.Message}");
}

Console.WriteLine("\nDone.");
