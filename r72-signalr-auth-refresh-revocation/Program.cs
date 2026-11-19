using System.Collections.Concurrent;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.Options;

const string AuthenticationScheme = "R72Lab";

var evidenceDirectory = Path.GetFullPath(args.Length > 0 ? args[0] : "evidence");
Directory.CreateDirectory(evidenceDirectory);

var cycles = ReadPositiveInt("R72_CYCLES", 75);
var fanout = ReadPositiveInt("R72_FANOUT", 8);
var port = ReadPositiveInt("R72_PORT", 5072);
var baseUrl = $"http://127.0.0.1:{port}";

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls(baseUrl);
builder.Logging.ClearProviders();
builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = AuthenticationScheme;
        options.DefaultChallengeScheme = AuthenticationScheme;
    })
    .AddScheme<AuthenticationSchemeOptions, LabAuthenticationHandler>(AuthenticationScheme, _ => { });
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("HighScope", policy =>
    {
        policy.AddAuthenticationSchemes(AuthenticationScheme);
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("scope", RequiredScope);
    });
});
builder.Services.AddSignalR(options =>
{
    options.EnableDetailedErrors = true;
    options.MaximumParallelInvocationsPerClient = 1;
});
builder.Services.AddSingleton<ProtectedExecutionLedger>();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/health", () => Results.Json(new
{
    ready = true,
    framework = Environment.Version.ToString(),
    process = Environment.ProcessId,
}));
app.MapHub<RevocationHub>("/hub", options =>
{
    options.EnableAuthenticationRefresh = true;
})
.RequireAuthorization();

var startedAt = DateTimeOffset.UtcNow;
var result = new LabResult
{
    Schema = "r72-signalr-auth-refresh-revocation/v1",
    StartedAtUtc = startedAt,
    FrameworkVersion = Environment.Version.ToString(),
    CyclesPerTransport = cycles,
    FanoutPerLowRefresh = fanout,
};

try
{
    await app.StartAsync().WaitAsync(TimeSpan.FromSeconds(30));

    using var healthClient = new HttpClient();
    var health = await healthClient.GetStringAsync($"{baseUrl}/health").WaitAsync(TimeSpan.FromSeconds(10));
    await File.WriteAllTextAsync(Path.Combine(evidenceDirectory, "health.json"), health + Environment.NewLine);

    var ledger = app.Services.GetRequiredService<ProtectedExecutionLedger>();
    foreach (var transport in new[]
    {
        HttpTransportType.WebSockets,
        HttpTransportType.ServerSentEvents,
        HttpTransportType.LongPolling,
    })
    {
        var transportResult = await RunTransportAsync(baseUrl, transport, cycles, fanout);
        result.Transports.Add(transportResult);
    }

    result.Executions = ledger.Snapshot();
}
catch (Exception exception)
{
    result.FatalError = exception.ToString();
}
finally
{
    try
    {
        await app.StopAsync().WaitAsync(TimeSpan.FromSeconds(15));
    }
    catch (Exception exception)
    {
        result.StopError = exception.ToString();
    }
}

result.CompletedAtUtc = DateTimeOffset.UtcNow;
result.Verdict = BuildVerdict(result);

var serializerOptions = new JsonSerializerOptions
{
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
};
await File.WriteAllTextAsync(
    Path.Combine(evidenceDirectory, "result.json"),
    JsonSerializer.Serialize(result, serializerOptions) + Environment.NewLine);
await File.WriteAllTextAsync(
    Path.Combine(evidenceDirectory, "summary.txt"),
    $"status={result.Verdict.Status}{Environment.NewLine}" +
    $"controlsPassed={result.Verdict.ControlsPassed}{Environment.NewLine}" +
    $"transientBypassCount={result.Verdict.TransientBypassCount}{Environment.NewLine}" +
    $"invalidObservationCount={result.Verdict.InvalidObservationCount}{Environment.NewLine}" +
    $"cyclesPerTransport={cycles}{Environment.NewLine}" +
    $"fanout={fanout}{Environment.NewLine}");

Console.WriteLine(JsonSerializer.Serialize(result.Verdict, serializerOptions));
return result.Verdict.Status switch
{
    "RUNTIME_NEGATIVE_CLOSED" => 0,
    "RUNTIME_POSITIVE_REVIEW_REQUIRED" => 3,
    _ => 2,
};

static int ReadPositiveInt(string name, int fallback)
{
    return int.TryParse(Environment.GetEnvironmentVariable(name), out var value) && value > 0
        ? value
        : fallback;
}

static async Task<TransportResult> RunTransportAsync(
    string baseUrl,
    HttpTransportType transport,
    int cycles,
    int fanout)
{
    var transportResult = new TransportResult { Transport = transport.ToString() };

    var lowOnlyState = new TokenState("low");
    await using (var lowOnlyConnection = BuildConnection(baseUrl, transport, lowOnlyState))
    {
        try
        {
            await lowOnlyConnection.StartAsync().WaitAsync(TimeSpan.FromSeconds(30));
            var lowOnlyObservation = await InvokeProtectedAsync(lowOnlyConnection, "fresh-low-control");
            transportResult.FreshLowControl = lowOnlyObservation;
            await lowOnlyConnection.StopAsync().WaitAsync(TimeSpan.FromSeconds(15));
        }
        catch (Exception exception)
        {
            transportResult.Errors.Add($"fresh-low-control: {exception}");
        }
    }

    var tokenState = new TokenState("high");
    await using var connection = BuildConnection(baseUrl, transport, tokenState);
    try
    {
        await connection.StartAsync().WaitAsync(TimeSpan.FromSeconds(30));
        transportResult.InitialHighControl = await InvokeProtectedAsync(connection, "initial-high-control");

        for (var cycle = 1; cycle <= cycles; cycle++)
        {
            var cycleResult = new CycleResult { Cycle = cycle };
            transportResult.Cycles.Add(cycleResult);

            tokenState.Set("low");
            try
            {
                cycleResult.LowRefreshTtlMilliseconds =
                    (await connection.RefreshAuthenticationAsync().WaitAsync(TimeSpan.FromSeconds(15)))?.TotalMilliseconds;
            }
            catch (Exception exception)
            {
                cycleResult.Errors.Add($"low-refresh: {exception}");
                continue;
            }

            var immediateTasks = Enumerable.Range(0, fanout)
                .Select(index => InvokeProtectedAsync(connection, $"low-{transport}-cycle-{cycle}-fanout-{index}"))
                .ToArray();
            cycleResult.ImmediateLowInvocations.AddRange(await Task.WhenAll(immediateTasks));

            await Task.Delay(25);
            cycleResult.DelayedLowInvocation =
                await InvokeProtectedAsync(connection, $"low-{transport}-cycle-{cycle}-delayed");

            tokenState.Set("high");
            try
            {
                cycleResult.HighRefreshTtlMilliseconds =
                    (await connection.RefreshAuthenticationAsync().WaitAsync(TimeSpan.FromSeconds(15)))?.TotalMilliseconds;
            }
            catch (Exception exception)
            {
                cycleResult.Errors.Add($"high-refresh: {exception}");
                continue;
            }

            cycleResult.HighInvocation =
                await InvokeProtectedAsync(connection, $"high-{transport}-cycle-{cycle}");
        }

        await connection.StopAsync().WaitAsync(TimeSpan.FromSeconds(15));
    }
    catch (Exception exception)
    {
        transportResult.Errors.Add($"main-connection: {exception}");
    }

    return transportResult;
}

static HubConnection BuildConnection(string baseUrl, HttpTransportType transport, TokenState tokenState)
{
    return new HubConnectionBuilder()
        .WithUrl($"{baseUrl}/hub", transport, options =>
        {
            options.AccessTokenProvider = () => Task.FromResult<string?>(tokenState.Value);
        })
        .WithAuthenticationRefresh(options => options.EnableAutoRefresh = false)
        .Build();
}

static async Task<InvocationObservation> InvokeProtectedAsync(HubConnection connection, string marker)
{
    var started = DateTimeOffset.UtcNow;
    try
    {
        var response = await connection
            .InvokeAsync<string>(nameof(RevocationHub.ScopeProtected), marker)
            .WaitAsync(TimeSpan.FromSeconds(15));
        return new InvocationObservation
        {
            Marker = marker,
            Outcome = "executed",
            Response = response,
            StartedAtUtc = started,
            CompletedAtUtc = DateTimeOffset.UtcNow,
        };
    }
    catch (HubException exception)
    {
        return new InvocationObservation
        {
            Marker = marker,
            Outcome = "denied",
            ExceptionType = exception.GetType().FullName,
            ExceptionMessage = exception.Message,
            StartedAtUtc = started,
            CompletedAtUtc = DateTimeOffset.UtcNow,
        };
    }
    catch (Exception exception)
    {
        return new InvocationObservation
        {
            Marker = marker,
            Outcome = "invalid-error",
            ExceptionType = exception.GetType().FullName,
            ExceptionMessage = exception.Message,
            StartedAtUtc = started,
            CompletedAtUtc = DateTimeOffset.UtcNow,
        };
    }
}

static LabVerdict BuildVerdict(LabResult result)
{
    var controlsPassed = result.FatalError is null
        && result.Transports.Count == 3
        && result.Transports.All(transport =>
            transport.Errors.Count == 0
            && transport.FreshLowControl?.Outcome == "denied"
            && transport.InitialHighControl?.Outcome == "executed"
            && transport.Cycles.Count == result.CyclesPerTransport
            && transport.Cycles.All(cycle =>
                cycle.Errors.Count == 0
                && cycle.DelayedLowInvocation?.Outcome == "denied"
                && cycle.HighInvocation?.Outcome == "executed"));

    var immediateObservations = result.Transports
        .SelectMany(transport => transport.Cycles)
        .SelectMany(cycle => cycle.ImmediateLowInvocations)
        .ToArray();
    var transientBypasses = immediateObservations
        .Where(observation => observation.Outcome == "executed")
        .ToArray();
    var invalidObservations = immediateObservations
        .Where(observation => observation.Outcome == "invalid-error")
        .Concat(result.Transports
            .SelectMany(transport => transport.Cycles)
            .Select(cycle => cycle.DelayedLowInvocation)
            .Where(observation => observation?.Outcome == "invalid-error")
            .Cast<InvocationObservation>())
        .ToArray();

    var status = !controlsPassed || invalidObservations.Length > 0
        ? "RUNTIME_INVALID"
        : transientBypasses.Length > 0
            ? "RUNTIME_POSITIVE_REVIEW_REQUIRED"
            : "RUNTIME_NEGATIVE_CLOSED";

    return new LabVerdict
    {
        Status = status,
        ControlsPassed = controlsPassed,
        TransientBypassCount = transientBypasses.Length,
        InvalidObservationCount = invalidObservations.Length,
        BypassSamples = transientBypasses.Take(20).ToList(),
    };
}

sealed class LabAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authorization = Request.Headers.Authorization.ToString();
        var token = authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? authorization["Bearer ".Length..].Trim()
            : Request.Query["access_token"].ToString();

        if (string.IsNullOrWhiteSpace(token))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        if (token is not ("high" or "low"))
        {
            return Task.FromResult(AuthenticateResult.Fail("unknown laboratory token"));
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, UserId),
            new(ClaimTypes.Name, UserId),
            new("token_mode", token),
        };
        if (token == "high")
        {
            claims.Add(new Claim("scope", RequiredScope));
        }

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var now = DateTimeOffset.UtcNow;
        var properties = new AuthenticationProperties
        {
            IssuedUtc = now,
            ExpiresUtc = now.AddMinutes(30),
        };
        var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}

sealed class TokenState(string initialValue)
{
    private string _value = initialValue;

    public string Value => Volatile.Read(ref _value);

    public void Set(string value) => Volatile.Write(ref _value, value);
}

sealed class RevocationHub(ProtectedExecutionLedger ledger) : Hub
{
    public string Echo(string message) => message;

    [Authorize("HighScope")]
    public string ScopeProtected(string marker)
    {
        var user = Context.User;
        var execution = new ProtectedExecution
        {
            Marker = marker,
            AtUtc = DateTimeOffset.UtcNow,
            ConnectionId = Context.ConnectionId,
            UserIdentifier = Context.UserIdentifier,
            TokenMode = user?.FindFirst("token_mode")?.Value,
            HasRequiredScope = user?.HasClaim("scope", RequiredScope) == true,
            Claims = user?.Claims.Select(claim => $"{claim.Type}={claim.Value}").ToArray() ?? [],
        };
        ledger.Record(execution);
        return $"executed:{execution.TokenMode}:{execution.HasRequiredScope}:{marker}";
    }
}

sealed class ProtectedExecutionLedger
{
    private readonly ConcurrentQueue<ProtectedExecution> _executions = new();

    public void Record(ProtectedExecution execution) => _executions.Enqueue(execution);

    public List<ProtectedExecution> Snapshot() => _executions.ToList();
}

sealed class LabResult
{
    public string Schema { get; set; } = string.Empty;
    public DateTimeOffset StartedAtUtc { get; set; }
    public DateTimeOffset CompletedAtUtc { get; set; }
    public string FrameworkVersion { get; set; } = string.Empty;
    public int CyclesPerTransport { get; set; }
    public int FanoutPerLowRefresh { get; set; }
    public List<TransportResult> Transports { get; } = [];
    public List<ProtectedExecution> Executions { get; set; } = [];
    public string? FatalError { get; set; }
    public string? StopError { get; set; }
    public LabVerdict Verdict { get; set; } = new();
}

sealed class TransportResult
{
    public string Transport { get; set; } = string.Empty;
    public InvocationObservation? FreshLowControl { get; set; }
    public InvocationObservation? InitialHighControl { get; set; }
    public List<CycleResult> Cycles { get; } = [];
    public List<string> Errors { get; } = [];
}

sealed class CycleResult
{
    public int Cycle { get; set; }
    public double? LowRefreshTtlMilliseconds { get; set; }
    public List<InvocationObservation> ImmediateLowInvocations { get; } = [];
    public InvocationObservation? DelayedLowInvocation { get; set; }
    public double? HighRefreshTtlMilliseconds { get; set; }
    public InvocationObservation? HighInvocation { get; set; }
    public List<string> Errors { get; } = [];
}

sealed class InvocationObservation
{
    public string Marker { get; set; } = string.Empty;
    public string Outcome { get; set; } = string.Empty;
    public string? Response { get; set; }
    public string? ExceptionType { get; set; }
    public string? ExceptionMessage { get; set; }
    public DateTimeOffset StartedAtUtc { get; set; }
    public DateTimeOffset CompletedAtUtc { get; set; }
}

sealed class ProtectedExecution
{
    public string Marker { get; set; } = string.Empty;
    public DateTimeOffset AtUtc { get; set; }
    public string ConnectionId { get; set; } = string.Empty;
    public string? UserIdentifier { get; set; }
    public string? TokenMode { get; set; }
    public bool HasRequiredScope { get; set; }
    public string[] Claims { get; set; } = [];
}

sealed class LabVerdict
{
    public string Status { get; set; } = "RUNTIME_INVALID";
    public bool ControlsPassed { get; set; }
    public int TransientBypassCount { get; set; }
    public int InvalidObservationCount { get; set; }
    public List<InvocationObservation> BypassSamples { get; set; } = [];
}
