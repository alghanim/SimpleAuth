using System.Text.Json.Serialization;

namespace SimpleAuth;

public class SimpleAuthUser
{
    [JsonPropertyName("sub")]
    public string Sub { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("email")]
    public string? Email { get; set; }

    [JsonPropertyName("preferred_username")]
    public string? PreferredUsername { get; set; }

    [JsonPropertyName("roles")]
    public List<string> Roles { get; set; } = [];

    [JsonPropertyName("permissions")]
    public List<string> Permissions { get; set; } = [];

    [JsonPropertyName("groups")]
    public List<string> Groups { get; set; } = [];

    [JsonPropertyName("department")]
    public string? Department { get; set; }

    [JsonPropertyName("company")]
    public string? Company { get; set; }

    [JsonPropertyName("job_title")]
    public string? JobTitle { get; set; }

    public bool HasRole(string role) =>
        Roles.Contains(role, StringComparer.OrdinalIgnoreCase);

    public bool HasPermission(string permission) =>
        Permissions.Contains(permission, StringComparer.OrdinalIgnoreCase);

    public bool HasAnyRole(params string[] roles) =>
        roles.Any(r => HasRole(r));
}

public class SimpleAuthOptions
{
    /// <summary>SimpleAuth server URL (e.g. https://auth.corp.local:9090)</summary>
    public string Url { get; set; } = string.Empty;

    /// <summary>Admin API key for admin operations (Bearer auth)</summary>
    public string AdminKey { get; set; } = string.Empty;

    /// <summary>
    /// This app's OAuth client id (v2 per-app management). When set with
    /// <see cref="AppSecret"/>, the app self-management methods authenticate to
    /// <c>/api/app/*</c> with HTTP Basic <c>app_id:app_secret</c>. Set
    /// <see cref="Audience"/> to this value so <c>VerifyAsync</c> rejects tokens
    /// minted for other apps.
    /// </summary>
    public string AppId { get; set; } = string.Empty;

    /// <summary>This app's OAuth client secret (v2 per-app management). Never hardcode it.</summary>
    public string AppSecret { get; set; } = string.Empty;

    /// <summary>Whether to validate SSL certificates</summary>
    public bool ValidateSsl { get; set; } = true;

    /// <summary>
    /// If set, VerifyAsync requires the token's <c>iss</c> claim to equal this
    /// value. Leave null/empty to skip the issuer check. Note: direct
    /// login/refresh tokens use iss="simpleauth"; OIDC code-flow tokens use the
    /// realm URL.
    /// </summary>
    public string? ExpectedIssuer { get; set; }

    /// <summary>If set, VerifyAsync requires this value in the <c>aud</c> claim.</summary>
    public string? Audience { get; set; }
}

public class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string? AccessToken { get; set; }

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    [JsonPropertyName("id_token")]
    public string? IdToken { get; set; }

    [JsonPropertyName("token_type")]
    public string? TokenType { get; set; }

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    [JsonPropertyName("force_password_change")]
    public bool ForcePasswordChange { get; set; }
}

public class UserInfo
{
    [JsonPropertyName("sub")]
    public string Sub { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("email")]
    public string? Email { get; set; }

    [JsonPropertyName("preferred_username")]
    public string? PreferredUsername { get; set; }

    [JsonPropertyName("email_verified")]
    public bool EmailVerified { get; set; }

    [JsonPropertyName("roles")]
    public List<string> Roles { get; set; } = [];

    [JsonPropertyName("permissions")]
    public List<string> Permissions { get; set; } = [];

    [JsonPropertyName("groups")]
    public List<string> Groups { get; set; } = [];

    [JsonPropertyName("department")]
    public string? Department { get; set; }

    [JsonPropertyName("company")]
    public string? Company { get; set; }

    [JsonPropertyName("job_title")]
    public string? JobTitle { get; set; }
}

// ─────────────────────────────────────────────────────────────────────────────
// v2 — per-app management (the developer surface under /api/app/*)
//
// An "app" is an OAuth client (app_id + app_secret) that self-manages its own
// authorization: roles, permissions, the role→permission map, and which
// directory users / AD groups are assigned. Tokens are scoped to the app via
// the `aud` claim, so a token minted for app A is rejected by app B (set
// SimpleAuthOptions.Audience to the app id so VerifyAsync enforces this).
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// An app's complete authorization: its roles, permissions, the
/// role→permission map, and the user/group→role assignments. Shape of
/// <c>GET/PUT /api/app/authz</c>.
/// </summary>
public class AppAuthz
{
    [JsonPropertyName("app_id")]
    public string AppId { get; set; } = string.Empty;

    [JsonPropertyName("roles")]
    public List<string> Roles { get; set; } = [];

    [JsonPropertyName("permissions")]
    public List<string> Permissions { get; set; } = [];

    [JsonPropertyName("role_permissions")]
    public Dictionary<string, List<string>> RolePermissions { get; set; } = [];

    /// <summary>User reference (GUID / sAMAccountName / username) → roles.</summary>
    [JsonPropertyName("user_assignments")]
    public Dictionary<string, List<string>> UserAssignments { get; set; } = [];

    /// <summary>Group identifier (sAMAccountName by default) → roles.</summary>
    [JsonPropertyName("group_assignments")]
    public Dictionary<string, List<string>> GroupAssignments { get; set; } = [];
}

/// <summary>
/// Grants a set of roles to either a directory user or an AD group. Set exactly
/// one of <see cref="User"/> (a username / sAMAccountName / GUID) or
/// <see cref="Group"/> (the group's identifier, sAMAccountName by default).
/// </summary>
public class Assignment
{
    [JsonPropertyName("user")]
    public string? User { get; set; }

    [JsonPropertyName("group")]
    public string? Group { get; set; }

    [JsonPropertyName("roles")]
    public List<string> Roles { get; set; } = [];
}

/// <summary>
/// Idempotent authz-as-code for the calling app: declares the app's roles,
/// permissions, role→permission map, and assignments. Body of
/// <c>POST /api/app/bootstrap</c>; safe to call on every deploy.
/// </summary>
public class BootstrapSpec
{
    [JsonPropertyName("roles")]
    public List<string> Roles { get; set; } = [];

    [JsonPropertyName("permissions")]
    public List<string> Permissions { get; set; } = [];

    [JsonPropertyName("role_permissions")]
    public Dictionary<string, List<string>> RolePermissions { get; set; } = [];

    [JsonPropertyName("assignments")]
    public List<Assignment> Assignments { get; set; } = [];
}

/// <summary>Response from <c>POST /api/app/bootstrap</c>.</summary>
public class BootstrapResult
{
    [JsonPropertyName("status")]
    public string? Status { get; set; }

    [JsonPropertyName("app_id")]
    public string AppId { get; set; } = string.Empty;

    [JsonPropertyName("roles_count")]
    public int RolesCount { get; set; }

    [JsonPropertyName("assignments_count")]
    public int AssignmentsCount { get; set; }
}

/// <summary>An app's own settings (no secret). Shape of <c>GET /api/app/settings</c>.</summary>
public class AppSettings
{
    [JsonPropertyName("app_id")]
    public string AppId { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("audience")]
    public string? Audience { get; set; }

    [JsonPropertyName("redirect_uris")]
    public List<string> RedirectUris { get; set; } = [];

    [JsonPropertyName("cors_origins")]
    public List<string> CorsOrigins { get; set; } = [];

    [JsonPropertyName("require_assignment")]
    public bool RequireAssignment { get; set; }

    [JsonPropertyName("allow_local_users")]
    public bool AllowLocalUsers { get; set; }

    [JsonPropertyName("disabled")]
    public bool Disabled { get; set; }

    [JsonPropertyName("created_at")]
    public string? CreatedAt { get; set; }
}

/// <summary>
/// An app-local user (owned by one app, e.g. a customer-portal account not in
/// the directory). Returned by <c>ListLocalUsersAsync</c> and (with just the
/// GUID/username populated) <c>CreateLocalUserAsync</c>.
/// </summary>
public class LocalUser
{
    [JsonPropertyName("guid")]
    public string Guid { get; set; } = string.Empty;

    [JsonPropertyName("username")]
    public string? Username { get; set; }

    [JsonPropertyName("display_name")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("email")]
    public string? Email { get; set; }

    [JsonPropertyName("owner_app_id")]
    public string? OwnerAppId { get; set; }

    [JsonPropertyName("disabled")]
    public bool Disabled { get; set; }

    [JsonPropertyName("created_at")]
    public string? CreatedAt { get; set; }
}
