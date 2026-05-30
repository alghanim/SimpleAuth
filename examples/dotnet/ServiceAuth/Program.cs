// ServiceAuth/Program.cs -- Service-to-service authentication with SimpleAuth.
//
// Demonstrates:
//   - Service-account login (machine-to-machine via a dedicated user)
//   - IHttpClientFactory with auto-injected Bearer token via DelegatingHandler
//   - Background service that maintains a fresh token
//   - Making authenticated calls to downstream APIs
//
// Environment variables:
//   SIMPLEAUTH_URL               SimpleAuth server URL incl. /sauth base path
//   SIMPLEAUTH_SERVICE_USER      Service-account username (required)
//   SIMPLEAUTH_SERVICE_PASSWORD  Service-account password (required)
//
// Prerequisites:
//   dotnet add reference to the SimpleAuth SDK project
//   (see ServiceAuth.csproj for project reference setup)
//
// Usage:
//   cd examples/dotnet/ServiceAuth
//   dotnet run

using System.Net.Http.Headers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SimpleAuth;

// ---------------------------------------------------------------------------
// Build the host with DI
// ---------------------------------------------------------------------------

var builder = Host.CreateApplicationBuilder(args);

// Register SimpleAuth client as a singleton.
// The server URL must include the /sauth base path.
var authOptions = new SimpleAuthOptions
{
    Url = Environment.GetEnvironmentVariable("SIMPLEAUTH_URL")
        ?? "https://auth.example.com/sauth",
    ValidateSsl = true,
};
var authClient = new SimpleAuthClient(authOptions);
builder.Services.AddSingleton(authClient);

// SimpleAuth's recommended M2M pattern is a dedicated service-account user.
// Credentials are supplied via environment variables -- never hardcode them.
var serviceUser = Environment.GetEnvironmentVariable("SIMPLEAUTH_SERVICE_USER")
    ?? throw new InvalidOperationException(
        "SIMPLEAUTH_SERVICE_USER environment variable is required.");
var servicePassword = Environment.GetEnvironmentVariable("SIMPLEAUTH_SERVICE_PASSWORD")
    ?? throw new InvalidOperationException(
        "SIMPLEAUTH_SERVICE_PASSWORD environment variable is required.");

// Register the token provider (holds and refreshes the service token).
// The service-account credentials are wired in explicitly here.
builder.Services.AddSingleton(sp => new ServiceTokenProvider(
    sp.GetRequiredService<SimpleAuthClient>(),
    sp.GetRequiredService<ILogger<ServiceTokenProvider>>(),
    serviceUser,
    servicePassword));

// Register the DelegatingHandler that injects Bearer tokens
builder.Services.AddTransient<AuthenticatedHttpHandler>();

// Register a named HttpClient for the downstream orders API.
// Every request through this client automatically includes a valid Bearer token.
builder.Services.AddHttpClient("OrdersApi", client =>
{
    client.BaseAddress = new Uri("https://api.internal.example.com/");
    client.Timeout = TimeSpan.FromSeconds(30);
})
.AddHttpMessageHandler<AuthenticatedHttpHandler>();

// Register the background worker that periodically calls the orders API
builder.Services.AddHostedService<OrderPollingService>();

var host = builder.Build();
await host.RunAsync();


// ===========================================================================
// ServiceTokenProvider -- obtains and caches a service-account token
// ===========================================================================

/// <summary>
/// Thread-safe token provider that authenticates a dedicated service-account
/// user via service-account login and re-logs in before the token expires.
/// </summary>
public class ServiceTokenProvider
{
    private readonly SimpleAuthClient _client;
    private readonly ILogger<ServiceTokenProvider> _logger;
    private readonly string _username;
    private readonly string _password;
    private readonly SemaphoreSlim _lock = new(1, 1);

    private string? _accessToken;
    private DateTime _expiresAt = DateTime.MinValue;

    // Refresh 60 seconds before the token actually expires
    private static readonly TimeSpan RefreshMargin = TimeSpan.FromSeconds(60);

    public ServiceTokenProvider(
        SimpleAuthClient client,
        ILogger<ServiceTokenProvider> logger,
        string username,
        string password)
    {
        _client = client;
        _logger = logger;
        _username = username;
        _password = password;
    }

    /// <summary>
    /// Returns a valid access token, obtaining or refreshing one if needed.
    /// </summary>
    public async Task<string> GetTokenAsync(CancellationToken ct = default)
    {
        // Fast path: token is still valid
        if (_accessToken is not null && DateTime.UtcNow < _expiresAt)
            return _accessToken;

        await _lock.WaitAsync(ct);
        try
        {
            // Double-check after acquiring the lock
            if (_accessToken is not null && DateTime.UtcNow < _expiresAt)
                return _accessToken;

            _logger.LogInformation(
                "Obtaining new service token via service-account login for {User}...",
                _username);

            var tokens = await _client.LoginAsync(_username, _password);
            _accessToken = tokens.AccessToken!;
            _expiresAt = DateTime.UtcNow.AddSeconds(tokens.ExpiresIn) - RefreshMargin;

            _logger.LogInformation(
                "Service token obtained. Expires in {ExpiresIn}s (will refresh at {RefreshAt:HH:mm:ss})",
                tokens.ExpiresIn,
                _expiresAt);

            return _accessToken;
        }
        catch (SimpleAuthException ex)
        {
            _logger.LogError(ex, "Failed to obtain service token");
            throw;
        }
        finally
        {
            _lock.Release();
        }
    }
}


// ===========================================================================
// AuthenticatedHttpHandler -- DelegatingHandler for IHttpClientFactory
// ===========================================================================

/// <summary>
/// A DelegatingHandler that injects a Bearer token from
/// <see cref="ServiceTokenProvider"/> into every outgoing HTTP request.
///
/// Register with IHttpClientFactory:
///   builder.Services.AddHttpClient("MyApi").AddHttpMessageHandler&lt;AuthenticatedHttpHandler&gt;();
/// </summary>
public class AuthenticatedHttpHandler : DelegatingHandler
{
    private readonly ServiceTokenProvider _tokenProvider;

    public AuthenticatedHttpHandler(ServiceTokenProvider tokenProvider)
    {
        _tokenProvider = tokenProvider;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var token = await _tokenProvider.GetTokenAsync(cancellationToken);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await base.SendAsync(request, cancellationToken);
    }
}


// ===========================================================================
// OrderPollingService -- BackgroundService example
// ===========================================================================

/// <summary>
/// A hosted background service that periodically calls a downstream API
/// using the authenticated HttpClient. Demonstrates a real-world pattern
/// for service-to-service communication.
/// </summary>
public class OrderPollingService : BackgroundService
{
    private readonly IHttpClientFactory _httpFactory;
    private readonly ILogger<OrderPollingService> _logger;

    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(1);

    public OrderPollingService(
        IHttpClientFactory httpFactory,
        ILogger<OrderPollingService> logger)
    {
        _httpFactory = httpFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("OrderPollingService started. Polling every {Interval}.", PollInterval);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PollOrdersAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error polling orders");
            }

            await Task.Delay(PollInterval, stoppingToken);
        }

        _logger.LogInformation("OrderPollingService stopped.");
    }

    private async Task PollOrdersAsync(CancellationToken ct)
    {
        // The "OrdersApi" named client is configured with the
        // AuthenticatedHttpHandler, so Bearer token is injected automatically.
        using var client = _httpFactory.CreateClient("OrdersApi");

        _logger.LogInformation("Fetching pending orders...");

        var response = await client.GetAsync("orders?status=pending", ct);

        if (response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            _logger.LogInformation("Received orders: {Body}", body);

            // Process orders here...
        }
        else
        {
            _logger.LogWarning(
                "Orders API returned {StatusCode}: {Body}",
                response.StatusCode,
                await response.Content.ReadAsStringAsync(ct));
        }
    }
}
