using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SimpleAuth;

public class SimpleAuthClient : IDisposable
{
    private readonly SimpleAuthOptions _options;
    private readonly HttpClient _http;
    private readonly SemaphoreSlim _jwksLock = new(1, 1);
    private Dictionary<string, RSAParameters>? _jwksCache;
    private DateTime _jwksCacheExpiry = DateTime.MinValue;

    private string BaseUrl => _options.Url.TrimEnd('/');
    private string LoginUrl => $"{BaseUrl}/api/auth/login";
    private string RefreshUrl => $"{BaseUrl}/api/auth/refresh";
    private string CertsUrl => $"{BaseUrl}/.well-known/jwks.json";
    private string UserInfoUrl => $"{BaseUrl}/api/auth/userinfo";
    private string AdminUrl => $"{BaseUrl}/api/admin";
    private string AppUrl => $"{BaseUrl}/api/app";

    /// <summary>Admin key for Bearer auth on admin endpoints.</summary>
    private string EffectiveAdminKey => _options.AdminKey;

    public SimpleAuthClient(SimpleAuthOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));

        if (string.IsNullOrWhiteSpace(options.Url))
            throw new ArgumentException("Url is required.", nameof(options));

        var handler = new HttpClientHandler();
        if (!options.ValidateSsl)
        {
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }

        _http = new HttpClient(handler);
    }

    // ── Authentication ──────────────────────────────────────────────────

    public async Task<TokenResponse> LoginAsync(string username, string password)
    {
        var body = new { username, password };
        var content = new StringContent(
            JsonSerializer.Serialize(body),
            Encoding.UTF8,
            "application/json");

        using var response = await _http.PostAsync(LoginUrl, content);
        var json = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new SimpleAuthException($"Login request failed ({response.StatusCode}): {json}");

        return JsonSerializer.Deserialize<TokenResponse>(json)
            ?? throw new SimpleAuthException("Empty login response.");
    }

    public async Task<TokenResponse> RefreshAsync(string refreshToken)
    {
        var body = new { refresh_token = refreshToken };
        var content = new StringContent(
            JsonSerializer.Serialize(body),
            Encoding.UTF8,
            "application/json");

        using var response = await _http.PostAsync(RefreshUrl, content);
        var json = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new SimpleAuthException($"Refresh request failed ({response.StatusCode}): {json}");

        return JsonSerializer.Deserialize<TokenResponse>(json)
            ?? throw new SimpleAuthException("Empty refresh response.");
    }

    // ── Token verification ──────────────────────────────────────────────

    public async Task<SimpleAuthUser> VerifyAsync(string token)
    {
        var parts = token.Split('.');
        if (parts.Length != 3)
            throw new SimpleAuthException("Invalid JWT: expected 3 parts.");

        JwtHeader header;
        try
        {
            var headerJson = Base64UrlDecode(parts[0]);
            header = JsonSerializer.Deserialize<JwtHeader>(headerJson)
                ?? throw new SimpleAuthException("Failed to parse JWT header.");
        }
        catch (Exception ex) when (ex is not SimpleAuthException)
        {
            // Header is attacker-controlled and parsed before signature
            // verification — surface malformed/non-JSON input as our own
            // exception type so the middleware/examples map it to a 401.
            throw new SimpleAuthException("Invalid JWT header.", ex);
        }

        if (!string.Equals(header.Alg, "RS256", StringComparison.OrdinalIgnoreCase))
            throw new SimpleAuthException($"Unsupported algorithm: {header.Alg}");

        var kid = header.Kid ?? throw new SimpleAuthException("JWT header missing kid.");

        // Verify signature
        var rsaParams = await GetRsaKeyAsync(kid);
        VerifySignature(parts[0], parts[1], parts[2], rsaParams);

        // Parse and validate claims. Wrap the whole body so that malformed or
        // attacker-crafted claims (non-base64, non-JSON, or a non-numeric
        // `exp`) raise a SimpleAuthException rather than an uncaught
        // InvalidOperationException/FormatException/JsonException, which would
        // escape the middleware as an unhandled 500 instead of a 401.
        try
        {
            var payloadJson = Base64UrlDecode(parts[1]);
            using var doc = JsonDocument.Parse(payloadJson);
            var root = doc.RootElement;

            // Reject refresh tokens presented as access tokens: they are signed by
            // the same key but carry a family_id and no authorization claims.
            if (root.TryGetProperty("family_id", out var famEl) &&
                famEl.ValueKind == JsonValueKind.String &&
                !string.IsNullOrEmpty(famEl.GetString()))
                throw new SimpleAuthException("Refresh token is not valid for resource access.");

            // Reject non-access token types. Access tokens carry no `typ`;
            // OIDC ID tokens use typ="ID" and app-management tokens use
            // typ="app-mgmt" — neither is a user access token even though both
            // are signed by the same key.
            if (root.TryGetProperty("typ", out var typEl) &&
                typEl.ValueKind == JsonValueKind.String)
            {
                var typ = typEl.GetString();
                if (string.Equals(typ, "ID", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(typ, "app-mgmt", StringComparison.OrdinalIgnoreCase))
                    throw new SimpleAuthException("Token is not a user access token.");
            }

            // Expiration is mandatory — fail closed if the claim is absent or
            // not a number.
            if (!root.TryGetProperty("exp", out var expEl) ||
                expEl.ValueKind != JsonValueKind.Number ||
                !expEl.TryGetInt64(out var exp))
                throw new SimpleAuthException("Token missing a valid exp claim.");
            var expTime = DateTimeOffset.FromUnixTimeSeconds(exp);
            if (expTime < DateTimeOffset.UtcNow)
                throw new SimpleAuthException("Token has expired.");

            // Issuer check is opt-in. Direct login tokens use iss="simpleauth", so
            // the old hardcoded BaseUrl check rejected every login token — only
            // enforce when an ExpectedIssuer is configured.
            if (!string.IsNullOrEmpty(_options.ExpectedIssuer))
            {
                var issuer = root.TryGetProperty("iss", out var issEl) ? issEl.GetString() : null;
                if (!string.Equals(issuer, _options.ExpectedIssuer, StringComparison.Ordinal))
                    throw new SimpleAuthException($"Invalid issuer: {issuer}, expected: {_options.ExpectedIssuer}");
            }

            // Optional audience check.
            if (!string.IsNullOrEmpty(_options.Audience) && !AudienceContains(root, _options.Audience!))
                throw new SimpleAuthException($"Token audience does not include {_options.Audience}");

            // Map claims to SimpleAuthUser
            var user = new SimpleAuthUser
            {
                Sub = root.TryGetProperty("sub", out var sub) ? sub.GetString() ?? "" : "",
                Name = root.TryGetProperty("name", out var name) ? name.GetString() : null,
                Email = root.TryGetProperty("email", out var email) ? email.GetString() : null,
                PreferredUsername = root.TryGetProperty("preferred_username", out var pref)
                    ? pref.GetString() : null,
                Department = root.TryGetProperty("department", out var dept) ? dept.GetString() : null,
                Company = root.TryGetProperty("company", out var comp) ? comp.GetString() : null,
                JobTitle = root.TryGetProperty("job_title", out var jt) ? jt.GetString() : null,
                Roles = GetStringList(root, "roles"),
                Permissions = GetStringList(root, "permissions"),
                Groups = GetStringList(root, "groups"),
            };

            return user;
        }
        catch (Exception ex) when (ex is not SimpleAuthException)
        {
            throw new SimpleAuthException("Invalid JWT claims.", ex);
        }
    }

    private static bool AudienceContains(JsonElement root, string audience)
    {
        if (!root.TryGetProperty("aud", out var audEl)) return false;
        if (audEl.ValueKind == JsonValueKind.String)
            return string.Equals(audEl.GetString(), audience, StringComparison.Ordinal);
        if (audEl.ValueKind == JsonValueKind.Array)
            foreach (var item in audEl.EnumerateArray())
                if (item.ValueKind == JsonValueKind.String &&
                    string.Equals(item.GetString(), audience, StringComparison.Ordinal))
                    return true;
        return false;
    }

    private static List<string> GetStringList(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var el) || el.ValueKind != JsonValueKind.Array)
            return [];
        return el.EnumerateArray()
            .Where(v => v.ValueKind == JsonValueKind.String)
            .Select(v => v.GetString()!)
            .ToList();
    }

    private static void VerifySignature(string headerB64, string payloadB64, string signatureB64, RSAParameters rsaParams)
    {
        var data = Encoding.ASCII.GetBytes($"{headerB64}.{payloadB64}");
        var signature = Base64UrlDecodeBytes(signatureB64);

        using var rsa = RSA.Create();
        rsa.ImportParameters(rsaParams);

        var valid = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (!valid)
            throw new SimpleAuthException("Invalid JWT signature.");
    }

    // ── JWKS ────────────────────────────────────────────────────────────

    private async Task<RSAParameters> GetRsaKeyAsync(string kid)
    {
        // Fast path: cache is valid and key exists
        if (_jwksCache is not null && _jwksCacheExpiry > DateTime.UtcNow && _jwksCache.TryGetValue(kid, out var cached))
            return cached;

        await _jwksLock.WaitAsync();
        try
        {
            // Double-check after acquiring lock
            if (_jwksCache is not null && _jwksCacheExpiry > DateTime.UtcNow && _jwksCache.TryGetValue(kid, out cached))
                return cached;

            // Fetch fresh JWKS (also handles kid-miss refresh)
            await FetchJwksAsync();

            if (_jwksCache!.TryGetValue(kid, out cached))
                return cached;

            throw new SimpleAuthException($"Key with kid '{kid}' not found in JWKS.");
        }
        finally
        {
            _jwksLock.Release();
        }
    }

    private async Task FetchJwksAsync()
    {
        using var response = await _http.GetAsync(CertsUrl);
        var json = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new SimpleAuthException($"Failed to fetch JWKS ({response.StatusCode}): {json}");

        using var doc = JsonDocument.Parse(json);
        var keys = doc.RootElement.GetProperty("keys");

        var newCache = new Dictionary<string, RSAParameters>();
        foreach (var key in keys.EnumerateArray())
        {
            var kty = key.GetProperty("kty").GetString();
            if (!string.Equals(kty, "RSA", StringComparison.OrdinalIgnoreCase))
                continue;

            var keyKid = key.GetProperty("kid").GetString();
            if (keyKid is null) continue;

            var n = Base64UrlDecodeBytes(key.GetProperty("n").GetString()!);
            var e = Base64UrlDecodeBytes(key.GetProperty("e").GetString()!);

            newCache[keyKid] = new RSAParameters { Modulus = n, Exponent = e };
        }

        _jwksCache = newCache;
        _jwksCacheExpiry = DateTime.UtcNow.AddHours(1);
    }

    // ── User info ───────────────────────────────────────────────────────

    public async Task<UserInfo> UserInfoAsync(string accessToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, UserInfoUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await _http.SendAsync(request);
        var json = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new SimpleAuthException($"UserInfo request failed ({response.StatusCode}): {json}");

        return JsonSerializer.Deserialize<UserInfo>(json)
            ?? throw new SimpleAuthException("Empty userinfo response.");
    }

    // ── Admin operations ────────────────────────────────────────────────

    public async Task<List<string>> GetUserRolesAsync(string guid)
    {
        var url = $"{AdminUrl}/users/{guid}/roles";
        return await AdminGetListAsync(url);
    }

    public async Task SetUserRolesAsync(string guid, List<string> roles)
    {
        var url = $"{AdminUrl}/users/{guid}/roles";
        await AdminPutListAsync(url, roles);
    }

    public async Task<List<string>> GetUserPermissionsAsync(string guid)
    {
        var url = $"{AdminUrl}/users/{guid}/permissions";
        return await AdminGetListAsync(url);
    }

    public async Task SetUserPermissionsAsync(string guid, List<string> permissions)
    {
        var url = $"{AdminUrl}/users/{guid}/permissions";
        await AdminPutListAsync(url, permissions);
    }

    private async Task<List<string>> AdminGetListAsync(string url)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Add("Authorization", $"Bearer {EffectiveAdminKey}");

        using var response = await _http.SendAsync(request);
        var json = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new SimpleAuthException($"Admin request failed ({response.StatusCode}): {json}");

        return JsonSerializer.Deserialize<List<string>>(json) ?? [];
    }

    private async Task AdminPutListAsync(string url, List<string> items)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, url)
        {
            Content = new StringContent(
                JsonSerializer.Serialize(items),
                Encoding.UTF8,
                "application/json"),
        };
        request.Headers.Add("Authorization", $"Bearer {EffectiveAdminKey}");

        using var response = await _http.SendAsync(request);
        if (!response.IsSuccessStatusCode)
        {
            var json = await response.Content.ReadAsStringAsync();
            throw new SimpleAuthException($"Admin request failed ({response.StatusCode}): {json}");
        }
    }

    // ── App self-management (v2 — per-app authorization) ─────────────────
    //
    // An "app" is an OAuth client (app_id + app_secret) that self-manages its own
    // authorization under /api/app/*, authenticated with HTTP Basic
    // app_id:app_secret. The app_id is derived from the credential by the server —
    // an app can only ever read or write its own scope. Set Options.Audience to
    // the app id so VerifyAsync rejects tokens minted for other apps.

    /// <summary>
    /// Declares the calling app's roles, permissions, role→permission map, and
    /// assignments (authz-as-code). Idempotent and safe to call on every deploy.
    /// <c>POST /api/app/bootstrap</c>.
    /// </summary>
    public async Task<BootstrapResult> AppBootstrapAsync(BootstrapSpec spec)
    {
        if (spec is null) throw new ArgumentNullException(nameof(spec));
        var json = await AppRequestAsync(HttpMethod.Post, $"{AppUrl}/bootstrap", spec);
        return JsonSerializer.Deserialize<BootstrapResult>(json)
            ?? throw new SimpleAuthException("Empty bootstrap response.");
    }

    /// <summary>
    /// Returns the calling app's current authorization (roles, permissions,
    /// role→permission map, and assignments). <c>GET /api/app/authz</c>.
    /// </summary>
    public async Task<AppAuthz> GetAppAuthzAsync()
    {
        var json = await AppRequestAsync(HttpMethod.Get, $"{AppUrl}/authz", null);
        return JsonSerializer.Deserialize<AppAuthz>(json)
            ?? throw new SimpleAuthException("Empty authz response.");
    }

    /// <summary>
    /// Replaces the calling app's authorization wholesale. The server uses the
    /// credential's app_id authoritatively, so <see cref="AppAuthz.AppId"/> may be
    /// left empty. <c>PUT /api/app/authz</c>.
    /// </summary>
    public async Task<AppAuthz> SetAppAuthzAsync(AppAuthz authz)
    {
        if (authz is null) throw new ArgumentNullException(nameof(authz));
        var json = await AppRequestAsync(HttpMethod.Put, $"{AppUrl}/authz", authz);
        return JsonSerializer.Deserialize<AppAuthz>(json)
            ?? throw new SimpleAuthException("Empty authz response.");
    }

    /// <summary>Returns the calling app's own settings (no secret). <c>GET /api/app/settings</c>.</summary>
    public async Task<AppSettings> AppSettingsAsync()
    {
        var json = await AppRequestAsync(HttpMethod.Get, $"{AppUrl}/settings", null);
        return JsonSerializer.Deserialize<AppSettings>(json)
            ?? throw new SimpleAuthException("Empty settings response.");
    }

    /// <summary>
    /// Provisions an app-local user owned by the calling app. Requires the app's
    /// <c>allow_local_users</c> flag. <paramref name="roles"/>, if non-empty, are
    /// recorded as the app's assignment for that username;
    /// <paramref name="displayName"/> and <paramref name="email"/> are optional
    /// (pass null). <c>POST /api/app/users</c>.
    /// </summary>
    public async Task<LocalUser> CreateLocalUserAsync(
        string username,
        string password,
        string? displayName = null,
        string? email = null,
        List<string>? roles = null)
    {
        var payload = new Dictionary<string, object>
        {
            ["username"] = username,
            ["password"] = password,
        };
        if (!string.IsNullOrEmpty(displayName)) payload["display_name"] = displayName;
        if (!string.IsNullOrEmpty(email)) payload["email"] = email;
        if (roles is { Count: > 0 }) payload["roles"] = roles;

        var json = await AppRequestAsync(HttpMethod.Post, $"{AppUrl}/users", payload);
        return JsonSerializer.Deserialize<LocalUser>(json)
            ?? throw new SimpleAuthException("Empty create-user response.");
    }

    /// <summary>Lists the calling app's local users. <c>GET /api/app/users</c>.</summary>
    public async Task<List<LocalUser>> ListLocalUsersAsync()
    {
        var json = await AppRequestAsync(HttpMethod.Get, $"{AppUrl}/users", null);
        var wrapper = JsonSerializer.Deserialize<LocalUserList>(json);
        return wrapper?.Users ?? [];
    }

    /// <summary>
    /// Deletes an app-local user owned by the calling app.
    /// <c>DELETE /api/app/users/{guid}</c>.
    /// </summary>
    public async Task DeleteLocalUserAsync(string guid)
    {
        await AppRequestAsync(HttpMethod.Delete, $"{AppUrl}/users/{guid}", null);
    }

    /// <summary>
    /// Resets an app-local user's password.
    /// <c>PUT /api/app/users/{guid}/password</c>.
    /// </summary>
    public async Task SetLocalUserPasswordAsync(string guid, string password)
    {
        await AppRequestAsync(HttpMethod.Put, $"{AppUrl}/users/{guid}/password",
            new { password });
    }

    /// <summary>
    /// Performs an authenticated request against /api/app/*. Mirrors the admin
    /// helpers but authenticates with HTTP Basic app_id:app_secret instead of a
    /// Bearer admin key. Throws if AppId/AppSecret are unset.
    /// </summary>
    private async Task<string> AppRequestAsync(HttpMethod method, string url, object? payload)
    {
        if (string.IsNullOrWhiteSpace(_options.AppId) || string.IsNullOrWhiteSpace(_options.AppSecret))
            throw new SimpleAuthException(
                "AppId and AppSecret are required for app-management operations.");

        using var request = new HttpRequestMessage(method, url);

        var credentials = Convert.ToBase64String(
            Encoding.UTF8.GetBytes($"{_options.AppId}:{_options.AppSecret}"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        if (payload is not null)
        {
            request.Content = new StringContent(
                JsonSerializer.Serialize(payload),
                Encoding.UTF8,
                "application/json");
        }

        using var response = await _http.SendAsync(request);
        var json = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new SimpleAuthException($"App request failed ({response.StatusCode}): {json}");

        return json;
    }

    private sealed class LocalUserList
    {
        [JsonPropertyName("users")]
        public List<LocalUser> Users { get; set; } = [];
    }

    // ── Base64url helpers ───────────────────────────────────────────────

    private static byte[] Base64UrlDecode(string input)
    {
        return Base64UrlDecodeBytes(input);
    }

    private static byte[] Base64UrlDecodeBytes(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    public void Dispose()
    {
        _http.Dispose();
        _jwksLock.Dispose();
        GC.SuppressFinalize(this);
    }

    private sealed class JwtHeader
    {
        [JsonPropertyName("alg")]
        public string? Alg { get; set; }

        [JsonPropertyName("kid")]
        public string? Kid { get; set; }
    }
}

public class SimpleAuthException : Exception
{
    public SimpleAuthException(string message) : base(message) { }
    public SimpleAuthException(string message, Exception inner) : base(message, inner) { }
}
