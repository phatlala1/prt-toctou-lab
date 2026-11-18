using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using R65PasskeyReplay.Server;

const string SeededUserId = "r65-victim-user";
const string SeededUserName = "victim@example.test";
const string ApplicationCookieName = ".R65.Application";
const string PasskeyStateCookieName = ".R65.PasskeyState";
const string RelyingPartyId = "localhost";

var keyPath = Environment.GetEnvironmentVariable("R65_KEY_PATH")
    ?? throw new InvalidOperationException("R65_KEY_PATH must point to the private-key laboratory file.");
Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(keyPath))!);

using var credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
if (File.Exists(keyPath))
{
    credentialKey.ImportPkcs8PrivateKey(File.ReadAllBytes(keyPath), out _);
}
else
{
    File.WriteAllBytes(keyPath, credentialKey.ExportPkcs8PrivateKey());
}

var publicParameters = credentialKey.ExportParameters(includePrivateParameters: false);
var publicKey = EncodeEs256CosePublicKey(
    publicParameters.Q.X ?? throw new InvalidOperationException("Missing P-256 X coordinate."),
    publicParameters.Q.Y ?? throw new InvalidOperationException("Missing P-256 Y coordinate."));
var credentialId = SHA256.HashData(Encoding.UTF8.GetBytes("R65 deterministic synced passkey credential"));
var passkey = new UserPasskeyInfo(
    credentialId,
    publicKey,
    DateTimeOffset.UtcNow,
    signCount: 0,
    transports: ["internal", "hybrid"],
    isUserVerified: true,
    isBackupEligible: true,
    isBackedUp: true,
    attestationObject: [],
    clientDataJson: [])
{
    Name = "R65 zero-counter synced credential",
    Aaguid = new byte[16],
};
var seededUser = new R65User
{
    Id = SeededUserId,
    UserName = SeededUserName,
    NormalizedUserName = SeededUserName.ToUpperInvariant(),
};
var store = new InMemoryPasskeyStore(seededUser, passkey);

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
        options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
        options.DefaultSignInScheme = IdentityConstants.ApplicationScheme;
    })
    .AddIdentityCookies();

builder.Services.Configure<CookieAuthenticationOptions>(IdentityConstants.ApplicationScheme, options =>
{
    options.Cookie.Name = ApplicationCookieName;
    options.Events.OnRedirectToLogin = context =>
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    };
});

builder.Services.Configure<CookieAuthenticationOptions>(IdentityConstants.TwoFactorUserIdScheme, options =>
{
    options.Cookie.Name = PasskeyStateCookieName;
});

builder.Services.AddAuthorization();
builder.Services
    .AddIdentityCore<R65User>(options =>
    {
        options.SignIn.RequireConfirmedAccount = false;
        options.SignIn.RequireConfirmedEmail = false;
        options.SignIn.RequireConfirmedPhoneNumber = false;
    })
    .AddSignInManager();

builder.Services.Configure<IdentityPasskeyOptions>(options =>
{
    options.ServerDomain = RelyingPartyId;
    options.UserVerificationRequirement = "required";
});

builder.Services.AddSingleton(store);
builder.Services.AddSingleton<IUserStore<R65User>>(store);
builder.Services.AddSingleton<IUserPasskeyStore<R65User>>(store);

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Json(new
{
    ok = true,
    runtime = Environment.Version.ToString(),
}));

app.MapGet("/descriptor", () => Results.Json(new
{
    userId = SeededUserId,
    userName = SeededUserName,
    credentialId = Base64UrlEncode(credentialId),
    rpId = RelyingPartyId,
    expectedOrigin = "http://localhost:5265",
    authenticatorFlags = 0x1D,
    signCount = store.GetStoredSignCount(SeededUserId),
    applicationCookieName = ApplicationCookieName,
    passkeyStateCookieName = PasskeyStateCookieName,
}));

app.MapPost("/options", async (UserManager<R65User> userManager, SignInManager<R65User> signInManager) =>
{
    var user = await userManager.FindByIdAsync(SeededUserId)
        ?? throw new InvalidOperationException("The seeded R65 user was not found.");
    var optionsJson = await signInManager.MakePasskeyRequestOptionsAsync(user);
    return Results.Content(optionsJson, "application/json");
});

app.MapPost("/login", async (LoginRequest request, SignInManager<R65User> signInManager, ILoggerFactory loggerFactory) =>
{
    var logger = loggerFactory.CreateLogger("R65.Login");
    try
    {
        signInManager.AuthenticationScheme = IdentityConstants.ApplicationScheme;
        var result = await signInManager.PasskeySignInAsync(request.CredentialJson);
        logger.LogInformation("R65 passkey sign-in result: {Result}", result.ToString());
        return result.Succeeded
            ? Results.Json(new { succeeded = true })
            : Results.Unauthorized();
    }
    catch (Exception exception)
    {
        logger.LogWarning(exception, "R65 passkey sign-in threw and was rejected.");
        return Results.Unauthorized();
    }
});

app.MapGet("/whoami", (ClaimsPrincipal principal) => Results.Json(new
{
    authenticated = principal.Identity?.IsAuthenticated == true,
    userId = principal.FindFirstValue(ClaimTypes.NameIdentifier),
    userName = principal.Identity?.Name,
})).RequireAuthorization();

app.MapGet("/debug/passkey", () => Results.Json(new
{
    userId = SeededUserId,
    signCount = store.GetStoredSignCount(SeededUserId),
}));

app.Run();

static byte[] EncodeEs256CosePublicKey(byte[] x, byte[] y)
{
    if (x.Length != 32 || y.Length != 32)
    {
        throw new InvalidOperationException("Expected 32-byte P-256 coordinates.");
    }

    // Canonical COSE_Key map: { 1: 2, 3: -7, -1: 1, -2: x, -3: y }.
    var output = new byte[77];
    var offset = 0;
    output[offset++] = 0xA5;
    output[offset++] = 0x01;
    output[offset++] = 0x02;
    output[offset++] = 0x03;
    output[offset++] = 0x26;
    output[offset++] = 0x20;
    output[offset++] = 0x01;
    output[offset++] = 0x21;
    output[offset++] = 0x58;
    output[offset++] = 0x20;
    x.CopyTo(output.AsSpan(offset));
    offset += x.Length;
    output[offset++] = 0x22;
    output[offset++] = 0x58;
    output[offset++] = 0x20;
    y.CopyTo(output.AsSpan(offset));
    offset += y.Length;

    if (offset != output.Length)
    {
        throw new InvalidOperationException($"Unexpected COSE key length {offset}.");
    }

    return output;
}

static string Base64UrlEncode(ReadOnlySpan<byte> value)
    => Convert.ToBase64String(value)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');

public sealed record LoginRequest(string CredentialJson);
