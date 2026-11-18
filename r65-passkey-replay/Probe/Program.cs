using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var options = ProbeOptions.Parse(args);
using var handler = new HttpClientHandler
{
    AllowAutoRedirect = false,
    UseCookies = false,
};
using var client = new HttpClient(handler)
{
    Timeout = TimeSpan.FromSeconds(20),
};

await WaitForHealthAsync(client, options.BaseUri);

var descriptor = await GetJsonAsync(client, new Uri(options.BaseUri, "/descriptor"));
var userId = descriptor.GetProperty("userId").GetString()
    ?? throw new InvalidOperationException("Descriptor omitted userId.");
var credentialId = descriptor.GetProperty("credentialId").GetString()
    ?? throw new InvalidOperationException("Descriptor omitted credentialId.");
var expectedRpId = descriptor.GetProperty("rpId").GetString()
    ?? throw new InvalidOperationException("Descriptor omitted rpId.");
var flags = checked((byte)descriptor.GetProperty("authenticatorFlags").GetInt32());
var applicationCookieName = descriptor.GetProperty("applicationCookieName").GetString()
    ?? throw new InvalidOperationException("Descriptor omitted applicationCookieName.");
var passkeyStateCookieName = descriptor.GetProperty("passkeyStateCookieName").GetString()
    ?? throw new InvalidOperationException("Descriptor omitted passkeyStateCookieName.");
var initialSignCount = descriptor.GetProperty("signCount").GetUInt32();

var originalCeremony = await GetOptionsAsync(client, options.BaseUri, passkeyStateCookieName);
if (!string.Equals(expectedRpId, originalCeremony.RpId, StringComparison.Ordinal))
{
    throw new InvalidOperationException($"RP ID mismatch: descriptor={expectedRpId}, options={originalCeremony.RpId}.");
}

using var credentialKey = ECDsa.Create();
credentialKey.ImportPkcs8PrivateKey(await File.ReadAllBytesAsync(options.KeyPath), out var bytesRead);
if (bytesRead == 0)
{
    throw new InvalidOperationException("No PKCS#8 private-key bytes were imported.");
}

var assertion = BuildAssertion(
    credentialKey,
    credentialId,
    userId,
    originalCeremony.Challenge,
    originalCeremony.RpId,
    options.Origin,
    flags,
    signCount: 0);

var first = await LoginAsync(
    client,
    options.BaseUri,
    options.Origin,
    originalCeremony.CookieHeader,
    assertion.CredentialJson,
    applicationCookieName,
    passkeyStateCookieName);
var firstWhoAmI = await WhoAmIAsync(client, options.BaseUri, first.ApplicationCookieHeader);

// Exact replay: same protected ceremony cookie and byte-identical signed assertion in a separate HTTP request.
var replay = await LoginAsync(
    client,
    options.BaseUri,
    options.Origin,
    originalCeremony.CookieHeader,
    assertion.CredentialJson,
    applicationCookieName,
    passkeyStateCookieName);
var replayWhoAmI = await WhoAmIAsync(client, options.BaseUri, replay.ApplicationCookieHeader);

// Control A: a newly issued ceremony cookie contains a different challenge; the old assertion must fail.
var freshCeremony = await GetOptionsAsync(client, options.BaseUri, passkeyStateCookieName);
var freshChallengeControl = await LoginAsync(
    client,
    options.BaseUri,
    options.Origin,
    freshCeremony.CookieHeader,
    assertion.CredentialJson,
    applicationCookieName,
    passkeyStateCookieName);

// Control B: the original ceremony cookie cannot authorize a modified signature.
var mutatedSignature = assertion.Signature.ToArray();
mutatedSignature[^1] ^= 0x01;
var mutatedCredentialJson = BuildCredentialJson(
    credentialId,
    userId,
    assertion.AuthenticatorData,
    assertion.ClientDataJson,
    mutatedSignature);
var signatureControl = await LoginAsync(
    client,
    options.BaseUri,
    options.Origin,
    originalCeremony.CookieHeader,
    mutatedCredentialJson,
    applicationCookieName,
    passkeyStateCookieName);

var finalDebug = await GetJsonAsync(client, new Uri(options.BaseUri, "/debug/passkey"));
var finalSignCount = finalDebug.GetProperty("signCount").GetUInt32();

var firstSetupPassed = first.StatusCode == HttpStatusCode.OK
    && !string.IsNullOrEmpty(first.ApplicationCookieHeader)
    && firstWhoAmI.StatusCode == HttpStatusCode.OK;
var controlsPassed = freshChallengeControl.StatusCode == HttpStatusCode.Unauthorized
    && signatureControl.StatusCode == HttpStatusCode.Unauthorized;
var exactReplayAccepted = replay.StatusCode == HttpStatusCode.OK
    && !string.IsNullOrEmpty(replay.ApplicationCookieHeader)
    && replayWhoAmI.StatusCode == HttpStatusCode.OK;

var verdict = !firstSetupPassed
    ? "INCONCLUSIVE_SETUP_FAILURE"
    : !controlsPassed
        ? "INCONCLUSIVE_CONTROL_FAILURE"
        : exactReplayAccepted && initialSignCount == 0 && finalSignCount == 0
            ? "POSITIVE_EXACT_PASSKEY_ASSERTION_REPLAY"
            : "NEGATIVE_REPLAY_REJECTED";

var output = new
{
    verdict,
    runtime = Environment.Version.ToString(),
    target = new
    {
        baseUri = options.BaseUri.ToString(),
        origin = options.Origin,
        userId,
        credentialIdSha256 = Sha256Hex(Encoding.UTF8.GetBytes(credentialId)),
        rpId = originalCeremony.RpId,
        authenticatorFlags = flags,
        initialSignCount,
        finalSignCount,
    },
    exactReplay = new
    {
        stateCookieSha256 = Sha256Hex(Encoding.UTF8.GetBytes(originalCeremony.CookieHeader)),
        assertionSha256 = Sha256Hex(Encoding.UTF8.GetBytes(assertion.CredentialJson)),
        first = first.ToEvidence(),
        replay = replay.ToEvidence(),
        firstWhoAmI = firstWhoAmI.ToEvidence(),
        replayWhoAmI = replayWhoAmI.ToEvidence(),
        applicationCookiesEqual = FixedStringEquals(first.ApplicationCookieHeader, replay.ApplicationCookieHeader),
        accepted = exactReplayAccepted,
    },
    controls = new
    {
        freshChallenge = new
        {
            originalChallengeSha256 = Sha256Hex(Encoding.UTF8.GetBytes(originalCeremony.Challenge)),
            freshChallengeSha256 = Sha256Hex(Encoding.UTF8.GetBytes(freshCeremony.Challenge)),
            challengesDiffer = !FixedStringEquals(originalCeremony.Challenge, freshCeremony.Challenge),
            result = freshChallengeControl.ToEvidence(),
            passed = freshChallengeControl.StatusCode == HttpStatusCode.Unauthorized,
        },
        mutatedSignature = new
        {
            originalSignatureSha256 = Sha256Hex(assertion.Signature),
            mutatedSignatureSha256 = Sha256Hex(mutatedSignature),
            result = signatureControl.ToEvidence(),
            passed = signatureControl.StatusCode == HttpStatusCode.Unauthorized,
        },
    },
};

var outputJson = JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true });
Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(options.OutputPath))!);
await File.WriteAllTextAsync(options.OutputPath, outputJson + Environment.NewLine);
Console.WriteLine(outputJson);
return;

static async Task WaitForHealthAsync(HttpClient client, Uri baseUri)
{
    var deadline = DateTimeOffset.UtcNow.AddSeconds(60);
    Exception? lastException = null;
    while (DateTimeOffset.UtcNow < deadline)
    {
        try
        {
            using var response = await client.GetAsync(new Uri(baseUri, "/health"));
            if (response.IsSuccessStatusCode)
            {
                return;
            }
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            lastException = exception;
        }

        await Task.Delay(500);
    }

    throw new InvalidOperationException("R65 server did not become healthy.", lastException);
}

static async Task<JsonElement> GetJsonAsync(HttpClient client, Uri uri)
{
    using var response = await client.GetAsync(uri);
    var body = await response.Content.ReadAsStringAsync();
    if (!response.IsSuccessStatusCode)
    {
        throw new InvalidOperationException($"GET {uri} returned {(int)response.StatusCode}: {body}");
    }

    using var document = JsonDocument.Parse(body);
    return document.RootElement.Clone();
}

static async Task<CeremonyOptions> GetOptionsAsync(HttpClient client, Uri baseUri, string stateCookieName)
{
    using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(baseUri, "/options"));
    using var response = await client.SendAsync(request);
    var body = await response.Content.ReadAsStringAsync();
    if (!response.IsSuccessStatusCode)
    {
        throw new InvalidOperationException($"POST /options returned {(int)response.StatusCode}: {body}");
    }

    using var document = JsonDocument.Parse(body);
    var challenge = document.RootElement.GetProperty("challenge").GetString()
        ?? throw new InvalidOperationException("Options omitted challenge.");
    var rpId = document.RootElement.GetProperty("rpId").GetString()
        ?? throw new InvalidOperationException("Options omitted rpId.");
    var cookieHeader = ExtractCookieHeader(response, stateCookieName);
    if (string.IsNullOrEmpty(cookieHeader))
    {
        throw new InvalidOperationException("The passkey state cookie was not issued.");
    }

    return new CeremonyOptions(challenge, rpId, cookieHeader);
}

static async Task<LoginAttempt> LoginAsync(
    HttpClient client,
    Uri baseUri,
    string origin,
    string stateCookieHeader,
    string credentialJson,
    string applicationCookieName,
    string stateCookieName)
{
    var requestJson = JsonSerializer.Serialize(new { credentialJson });
    using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(baseUri, "/login"))
    {
        Content = new StringContent(requestJson, Encoding.UTF8, "application/json"),
    };
    request.Headers.TryAddWithoutValidation("Origin", origin);
    request.Headers.TryAddWithoutValidation("Cookie", stateCookieHeader);

    using var response = await client.SendAsync(request);
    var body = await response.Content.ReadAsStringAsync();
    var applicationCookieHeader = ExtractCookieHeader(response, applicationCookieName);
    var stateDeletionObserved = HasDeletionCookie(response, stateCookieName);
    return new LoginAttempt(response.StatusCode, body, applicationCookieHeader, stateDeletionObserved);
}

static async Task<HttpResult> WhoAmIAsync(HttpClient client, Uri baseUri, string cookieHeader)
{
    if (string.IsNullOrEmpty(cookieHeader))
    {
        return new HttpResult(0, "application cookie missing");
    }

    using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(baseUri, "/whoami"));
    request.Headers.TryAddWithoutValidation("Cookie", cookieHeader);
    using var response = await client.SendAsync(request);
    var body = await response.Content.ReadAsStringAsync();
    return new HttpResult(response.StatusCode, body);
}

static AssertionMaterial BuildAssertion(
    ECDsa credentialKey,
    string credentialId,
    string userId,
    string challenge,
    string rpId,
    string origin,
    byte flags,
    uint signCount)
{
    var clientDataJson = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
    {
        challenge,
        origin,
        type = "webauthn.get",
    }));

    var authenticatorData = new byte[37];
    SHA256.HashData(Encoding.UTF8.GetBytes(rpId)).CopyTo(authenticatorData, 0);
    authenticatorData[32] = flags;
    BinaryPrimitives.WriteUInt32BigEndian(authenticatorData.AsSpan(33), signCount);

    var clientDataHash = SHA256.HashData(clientDataJson);
    var signedData = new byte[authenticatorData.Length + clientDataHash.Length];
    authenticatorData.CopyTo(signedData, 0);
    clientDataHash.CopyTo(signedData, authenticatorData.Length);
    var signature = credentialKey.SignData(
        signedData,
        HashAlgorithmName.SHA256,
        DSASignatureFormat.Rfc3279DerSequence);

    var credentialJson = BuildCredentialJson(
        credentialId,
        userId,
        authenticatorData,
        clientDataJson,
        signature);
    return new AssertionMaterial(credentialJson, authenticatorData, clientDataJson, signature);
}

static string BuildCredentialJson(
    string credentialId,
    string userId,
    byte[] authenticatorData,
    byte[] clientDataJson,
    byte[] signature)
    => JsonSerializer.Serialize(new
    {
        id = credentialId,
        response = new
        {
            authenticatorData = Base64UrlEncode(authenticatorData),
            clientDataJSON = Base64UrlEncode(clientDataJson),
            signature = Base64UrlEncode(signature),
            userHandle = Base64UrlEncode(Encoding.UTF8.GetBytes(userId)),
        },
        type = "public-key",
        clientExtensionResults = new { },
        authenticatorAttachment = "platform",
    });

static string ExtractCookieHeader(HttpResponseMessage response, string baseCookieName)
{
    if (!response.Headers.TryGetValues("Set-Cookie", out var setCookieValues))
    {
        return string.Empty;
    }

    var pairs = new List<string>();
    foreach (var setCookie in setCookieValues)
    {
        var separator = setCookie.IndexOf(';');
        var pair = separator >= 0 ? setCookie[..separator] : setCookie;
        var equals = pair.IndexOf('=');
        if (equals <= 0)
        {
            continue;
        }

        var name = pair[..equals];
        if (string.Equals(name, baseCookieName, StringComparison.Ordinal)
            || name.StartsWith(baseCookieName + "C", StringComparison.Ordinal))
        {
            if (pair.Length > equals + 1)
            {
                pairs.Add(pair);
            }
        }
    }

    return string.Join("; ", pairs);
}

static bool HasDeletionCookie(HttpResponseMessage response, string cookieName)
{
    if (!response.Headers.TryGetValues("Set-Cookie", out var setCookieValues))
    {
        return false;
    }

    foreach (var setCookie in setCookieValues)
    {
        if (!setCookie.StartsWith(cookieName + "=", StringComparison.Ordinal))
        {
            continue;
        }

        var firstPair = setCookie.Split(';', 2)[0];
        if (firstPair == cookieName + "="
            || setCookie.Contains("max-age=0", StringComparison.OrdinalIgnoreCase)
            || setCookie.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
    }

    return false;
}

static string Base64UrlEncode(ReadOnlySpan<byte> value)
    => Convert.ToBase64String(value)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');

static string Sha256Hex(ReadOnlySpan<byte> value)
    => Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();

static bool FixedStringEquals(string left, string right)
    => CryptographicOperations.FixedTimeEquals(
        SHA256.HashData(Encoding.UTF8.GetBytes(left)),
        SHA256.HashData(Encoding.UTF8.GetBytes(right)));

internal sealed record ProbeOptions(Uri BaseUri, string Origin, string KeyPath, string OutputPath)
{
    public static ProbeOptions Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index += 2)
        {
            if (index + 1 >= args.Length || !args[index].StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException("Expected --name value arguments.");
            }
            values[args[index][2..]] = args[index + 1];
        }

        return new ProbeOptions(
            new Uri(Required("base"), UriKind.Absolute),
            Required("origin"),
            Required("key"),
            Required("out"));

        string Required(string name)
            => values.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
                ? value
                : throw new ArgumentException($"Missing --{name}.");
    }
}

internal sealed record CeremonyOptions(string Challenge, string RpId, string CookieHeader);
internal sealed record AssertionMaterial(string CredentialJson, byte[] AuthenticatorData, byte[] ClientDataJson, byte[] Signature);

internal sealed record LoginAttempt(
    HttpStatusCode StatusCode,
    string Body,
    string ApplicationCookieHeader,
    bool StateDeletionObserved)
{
    public object ToEvidence() => new
    {
        status = (int)StatusCode,
        body = Body.Length <= 500 ? Body : Body[..500],
        applicationCookieIssued = !string.IsNullOrEmpty(ApplicationCookieHeader),
        applicationCookieSha256 = string.IsNullOrEmpty(ApplicationCookieHeader)
            ? null
            : Sha256Hex(Encoding.UTF8.GetBytes(ApplicationCookieHeader)),
        stateDeletionObserved = StateDeletionObserved,
    };
}

internal sealed record HttpResult(HttpStatusCode StatusCode, string Body)
{
    public object ToEvidence() => new
    {
        status = (int)StatusCode,
        body = Body.Length <= 500 ? Body : Body[..500],
    };
}
