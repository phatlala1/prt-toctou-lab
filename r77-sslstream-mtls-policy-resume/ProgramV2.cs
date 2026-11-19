using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

internal static class Program
{
    private const int TrialsPerProtocol = 3;
    private const int ResumeProbeLimit = 12;
    private const int SecPkgAttrSessionInfo = 0x5D;
    private const uint SslSessionReconnect = 0x01;

    private static readonly BindingFlags InstanceFlags =
        BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
    private static readonly FieldInfo? SecurityContextField =
        typeof(SslStream).GetField("_securityContext", InstanceFlags);

    public static async Task<int> Main(string[] args)
    {
        string outputPath = args.Length > 0 ? args[0] : "result.json";
        var protocols = new List<ProtocolResult>();

        foreach (SslProtocols protocol in new[] { SslProtocols.Tls12, SslProtocols.Tls13 })
        {
            protocols.Add(await RunProtocolAsync(protocol));
        }

        List<ProtocolResult> valid = protocols
            .Where(p => p.Status is "RUNTIME_POSITIVE_REVIEW_REQUIRED" or "RUNTIME_NEGATIVE_CLOSED")
            .ToList();

        string status;
        string? reason = null;
        if (valid.Any(p => p.Status == "RUNTIME_POSITIVE_REVIEW_REQUIRED"))
        {
            status = "RUNTIME_POSITIVE_REVIEW_REQUIRED";
        }
        else if (valid.Count > 0)
        {
            status = "RUNTIME_NEGATIVE_CLOSED";
        }
        else
        {
            status = "INVALID_RUNTIME";
            reason = "No protocol completed a controlled matrix with a native TLS-resumption signal.";
        }

        var result = new FinalResult
        {
            Schema = "r77-sslstream-mtls-policy-resume/v2",
            Status = status,
            InvalidReason = reason,
            Runtime = Environment.Version.ToString(),
            Framework = RuntimeInformation.FrameworkDescription,
            Os = RuntimeInformation.OSDescription,
            ResumptionDetector = NativeResumeDetector.Description,
            SecurityContextFieldFound = SecurityContextField is not null,
            Protocols = protocols,
        };

        string json = JsonSerializer.Serialize(result, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        });
        Console.WriteLine(json);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
        await File.WriteAllTextAsync(outputPath, json + Environment.NewLine);

        return status switch
        {
            "RUNTIME_POSITIVE_REVIEW_REQUIRED" => 10,
            "INVALID_RUNTIME" => 2,
            _ => 0,
        };
    }

    private static async Task<ProtocolResult> RunProtocolAsync(SslProtocols protocol)
    {
        var trials = new List<TrialResult>();
        for (int number = 1; number <= TrialsPerProtocol; number++)
        {
            try
            {
                trials.Add(await RunTrialAsync(protocol, number));
            }
            catch (AuthenticationException exception) when (
                exception.Message.Contains("protocol", StringComparison.OrdinalIgnoreCase))
            {
                return new ProtocolResult
                {
                    Protocol = protocol.ToString(),
                    Status = "UNSUPPORTED",
                    Reason = Describe(exception),
                    Trials = trials,
                };
            }
            catch (Exception exception)
            {
                trials.Add(new TrialResult
                {
                    TrialNumber = number,
                    InvalidReason = Describe(exception),
                });
                break;
            }
        }

        bool complete = trials.Count == TrialsPerProtocol &&
            trials.All(t => t.InvalidReason is null);
        if (!complete)
        {
            return new ProtocolResult
            {
                Protocol = protocol.ToString(),
                Status = "INVALID_RUNTIME",
                Reason = "The runtime matrix did not complete all trials.",
                Trials = trials,
            };
        }

        if (trials.Any(t => !t.ResumeBaselineProved))
        {
            return new ProtocolResult
            {
                Protocol = protocol.ToString(),
                Status = "UNTESTABLE_NO_RESUMPTION",
                Reason = "No native resumption signal was observed for the anonymous baseline.",
                Trials = trials,
            };
        }

        if (trials.Any(t => !t.ControlsPassed))
        {
            return new ProtocolResult
            {
                Protocol = protocol.ToString(),
                Status = "INVALID_RUNTIME",
                Reason = "At least one matched control failed.",
                Trials = trials,
            };
        }

        int positiveCount = trials.Count(t => t.CandidatePositive);
        return new ProtocolResult
        {
            Protocol = protocol.ToString(),
            Status = positiveCount switch
            {
                TrialsPerProtocol => "RUNTIME_POSITIVE_REVIEW_REQUIRED",
                0 => "RUNTIME_NEGATIVE_CLOSED",
                _ => "INCONCLUSIVE",
            },
            Reason = positiveCount is 0 or TrialsPerProtocol
                ? null
                : $"Candidate positive in {positiveCount}/{TrialsPerProtocol} trials.",
            Trials = trials,
        };
    }

    private static async Task<TrialResult> RunTrialAsync(SslProtocols protocol, int trialNumber)
    {
        string id = $"r77-{protocol}-{trialNumber}-{Guid.NewGuid():N}";
        var trial = new TrialResult { TrialNumber = trialNumber };

        // Control 1: an anonymous fresh handshake must fail under the strict mTLS policy.
        using (var serverCertificate = OwnedCertificate.CreateServer($"{id}-fresh.local"))
        using (var runner = new EndpointRunner())
        {
            var policy = new ClientCertificatePolicy("not-a-real-thumbprint");
            SslServerAuthenticationOptions server = CreateServerOptions(
                protocol, serverCertificate.Certificate, true, false, policy.Validate);
            SslClientAuthenticationOptions client = CreateClientOptions(
                protocol, $"{id}-fresh.local", false, null);
            policy.Reset();
            trial.FreshStrictAnonymous = await runner.ExchangeAsync(
                "fresh-strict-anonymous", server, client, "DENY");
            StampPolicy(trial.FreshStrictAnonymous, policy);
            trial.FreshStrictAnonymousControlPassed =
                !trial.FreshStrictAnonymous.HandshakeSucceeded &&
                !trial.FreshStrictAnonymous.ApplicationDataSucceeded;
        }

        // Control 2: the expected client certificate must pass the same strict policy.
        using (var serverCertificate = OwnedCertificate.CreateServer($"{id}-valid.local"))
        using (var clientCertificate = OwnedCertificate.CreateClient($"{id}-valid-client"))
        using (var runner = new EndpointRunner())
        {
            string expected = clientCertificate.Certificate.GetCertHashString(HashAlgorithmName.SHA256);
            var policy = new ClientCertificatePolicy(expected);
            SslServerAuthenticationOptions server = CreateServerOptions(
                protocol, serverCertificate.Certificate, true, false, policy.Validate);
            SslClientAuthenticationOptions client = CreateClientOptions(
                protocol, $"{id}-valid.local", false, clientCertificate.Certificate);
            policy.Reset();
            trial.ValidClientCertificate = await runner.ExchangeAsync(
                "strict-valid-client", server, client, "ADMIN-VALID");
            StampPolicy(trial.ValidClientCertificate, policy);
            trial.ValidClientCertificateControlPassed =
                trial.ValidClientCertificate.HandshakeSucceeded &&
                trial.ValidClientCertificate.ApplicationDataSucceeded &&
                trial.ValidClientCertificate.ServerRemoteCertificatePresent &&
                policy.ValidCertificateCalls >= 1;
        }

        // Control 3: a different client certificate must be rejected.
        using (var serverCertificate = OwnedCertificate.CreateServer($"{id}-wrong.local"))
        using (var expectedCertificate = OwnedCertificate.CreateClient($"{id}-expected-client"))
        using (var wrongCertificate = OwnedCertificate.CreateClient($"{id}-wrong-client"))
        using (var runner = new EndpointRunner())
        {
            string expected = expectedCertificate.Certificate.GetCertHashString(HashAlgorithmName.SHA256);
            var policy = new ClientCertificatePolicy(expected);
            SslServerAuthenticationOptions server = CreateServerOptions(
                protocol, serverCertificate.Certificate, true, false, policy.Validate);
            SslClientAuthenticationOptions client = CreateClientOptions(
                protocol, $"{id}-wrong.local", false, wrongCertificate.Certificate);
            policy.Reset();
            trial.WrongClientCertificate = await runner.ExchangeAsync(
                "strict-wrong-client", server, client, "DENY");
            StampPolicy(trial.WrongClientCertificate, policy);
            trial.WrongClientCertificateControlPassed =
                !trial.WrongClientCertificate.HandshakeSucceeded &&
                !trial.WrongClientCertificate.ApplicationDataSucceeded &&
                policy.OtherCertificateCalls >= 1;
        }

        // Candidate: establish an anonymous public session, prove that the same session cache
        // resumes, then enforce mTLS while retaining the same certificate/protocol/host/cache scope.
        using (var serverCertificate = OwnedCertificate.CreateServer($"{id}-shared.local"))
        using (var expectedCertificate = OwnedCertificate.CreateClient($"{id}-shared-expected"))
        using (var runner = new EndpointRunner())
        {
            string host = $"{id}-shared.local";
            string expected = expectedCertificate.Certificate.GetCertHashString(HashAlgorithmName.SHA256);
            var policy = new ClientCertificatePolicy(expected);
            SslServerAuthenticationOptions publicServer = CreateServerOptions(
                protocol, serverCertificate.Certificate, false, true, null);
            SslServerAuthenticationOptions strictServer = CreateServerOptions(
                protocol, serverCertificate.Certificate, true, true, policy.Validate);
            SslClientAuthenticationOptions anonymousClient = CreateClientOptions(
                protocol, host, true, null);

            trial.PublicInitial = await runner.ExchangeAsync(
                "public-initial", publicServer, anonymousClient, "PUBLIC-INITIAL");
            if (!trial.PublicInitial.HandshakeSucceeded ||
                !trial.PublicInitial.ApplicationDataSucceeded ||
                trial.PublicInitial.ServerRemoteCertificatePresent)
            {
                trial.InvalidReason = "Anonymous public baseline failed.";
                return trial;
            }

            for (int probe = 1; probe <= ResumeProbeLimit; probe++)
            {
                ConnectionResult connection = await runner.ExchangeAsync(
                    $"public-resume-{probe}", publicServer, anonymousClient, $"PUBLIC-{probe}");
                trial.PublicResumeProbes.Add(connection);
                if (connection.HandshakeSucceeded &&
                    connection.ApplicationDataSucceeded &&
                    connection.ClientTlsResumed == true &&
                    connection.ServerTlsResumed == true)
                {
                    trial.ResumeBaselineProved = true;
                    break;
                }
            }

            if (!trial.ResumeBaselineProved)
            {
                trial.InvalidReason = "Native detector did not observe an anonymous resumed session.";
                return trial;
            }

            policy.Reset();
            trial.Candidate = await runner.ExchangeAsync(
                "strict-after-anonymous-resume", strictServer, anonymousClient,
                $"ADMIN-CANARY-{trialNumber}");
            StampPolicy(trial.Candidate, policy);
            trial.CandidatePositive =
                trial.Candidate.HandshakeSucceeded &&
                trial.Candidate.ApplicationDataSucceeded &&
                trial.Candidate.ClientTlsResumed == true &&
                trial.Candidate.ServerTlsResumed == true &&
                !trial.Candidate.ServerRemoteCertificatePresent &&
                policy.Calls == 0 &&
                string.Equals(
                    trial.Candidate.ResponseText,
                    $"ADMIN-CANARY-{trialNumber}",
                    StringComparison.Ordinal);

            // Matched full-handshake control: resumption disabled on both sides.
            SslServerAuthenticationOptions strictNoResumeServer = CreateServerOptions(
                protocol, serverCertificate.Certificate, true, false, policy.Validate);
            SslClientAuthenticationOptions anonymousNoResumeClient = CreateClientOptions(
                protocol, host, false, null);
            policy.Reset();
            trial.StrictNoResume = await runner.ExchangeAsync(
                "strict-no-resume", strictNoResumeServer, anonymousNoResumeClient, "DENY");
            StampPolicy(trial.StrictNoResume, policy);
            trial.StrictNoResumeControlPassed =
                !trial.StrictNoResume.HandshakeSucceeded &&
                !trial.StrictNoResume.ApplicationDataSucceeded;
        }

        trial.ControlsPassed =
            trial.FreshStrictAnonymousControlPassed &&
            trial.ValidClientCertificateControlPassed &&
            trial.WrongClientCertificateControlPassed &&
            trial.StrictNoResumeControlPassed &&
            trial.ResumeBaselineProved;
        return trial;
    }

    private static SslServerAuthenticationOptions CreateServerOptions(
        SslProtocols protocol,
        X509Certificate2 certificate,
        bool requireClientCertificate,
        bool allowResume,
        RemoteCertificateValidationCallback? callback)
        => new()
        {
            EnabledSslProtocols = protocol,
            ServerCertificateContext = SslStreamCertificateContext.Create(certificate, null, offline: true),
            ClientCertificateRequired = requireClientCertificate,
            AllowTlsResume = allowResume,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = callback,
        };

    private static SslClientAuthenticationOptions CreateClientOptions(
        SslProtocols protocol,
        string host,
        bool allowResume,
        X509Certificate2? certificate)
    {
        var options = new SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = protocol,
            AllowTlsResume = allowResume,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = static (_, _, _, _) => true,
        };
        if (certificate is not null)
        {
            options.ClientCertificates = new X509CertificateCollection { certificate };
        }
        return options;
    }

    private static void StampPolicy(ConnectionResult result, ClientCertificatePolicy policy)
    {
        result.StrictCallbackCount = policy.Calls;
        result.StrictNullCertificateCalls = policy.NullCertificateCalls;
        result.StrictValidCertificateCalls = policy.ValidCertificateCalls;
        result.StrictOtherCertificateCalls = policy.OtherCertificateCalls;
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int count = await stream.ReadAsync(buffer[offset..], cancellationToken);
            if (count == 0)
            {
                throw new EndOfStreamException();
            }
            offset += count;
        }
    }

    private static async Task<Exception?> CaptureAsync(Func<Task> action)
    {
        try
        {
            await action();
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    private static async Task IgnoreAsync(Func<Task> action)
    {
        try { await action(); } catch { }
    }

    private static string Describe(Exception exception)
        => $"{exception.GetType().FullName}: {exception.Message}";

    private sealed class EndpointRunner : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);

        public EndpointRunner() => _listener.Start();

        public async Task<ConnectionResult> ExchangeAsync(
            string label,
            SslServerAuthenticationOptions serverOptions,
            SslClientAuthenticationOptions clientOptions,
            string responseText)
        {
            var result = new ConnectionResult { Label = label };
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            TcpClient? accepted = null;
            SslStream? clientSsl = null;
            SslStream? serverSsl = null;

            try
            {
                Task<TcpClient> acceptTask = _listener.AcceptTcpClientAsync(timeout.Token).AsTask();
                using var clientTcp = new TcpClient { NoDelay = true };
                int port = ((IPEndPoint)_listener.LocalEndpoint).Port;
                await clientTcp.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
                accepted = await acceptTask;
                accepted.NoDelay = true;
                clientSsl = new SslStream(clientTcp.GetStream());
                serverSsl = new SslStream(accepted.GetStream());

                Task<Exception?> clientAuth = CaptureAsync(
                    () => clientSsl.AuthenticateAsClientAsync(clientOptions, timeout.Token));
                Task<Exception?> serverAuth = CaptureAsync(
                    () => serverSsl.AuthenticateAsServerAsync(serverOptions, timeout.Token));
                await Task.WhenAll(clientAuth, serverAuth).WaitAsync(timeout.Token);
                Exception? clientError = await clientAuth;
                Exception? serverError = await serverAuth;
                result.ClientAuthenticationError = clientError is null ? null : Describe(clientError);
                result.ServerAuthenticationError = serverError is null ? null : Describe(serverError);
                result.HandshakeSucceeded =
                    clientError is null && serverError is null &&
                    clientSsl.IsAuthenticated && serverSsl.IsAuthenticated;

                result.ClientTlsResumed = NativeResumeDetector.IsResumed(clientSsl);
                result.ServerTlsResumed = NativeResumeDetector.IsResumed(serverSsl);
                if (result.HandshakeSucceeded)
                {
                    result.ServerRemoteCertificatePresent = serverSsl.RemoteCertificate is not null;
                    result.ClientLocalCertificatePresent = clientSsl.LocalCertificate is not null;
                    result.NegotiatedProtocol = clientSsl.SslProtocol.ToString();
                    byte[] request = Encoding.ASCII.GetBytes("PING");
                    byte[] requestBuffer = new byte[request.Length];
                    byte[] response = Encoding.UTF8.GetBytes(responseText);
                    byte[] responseBuffer = new byte[response.Length];
                    await clientSsl.WriteAsync(request, timeout.Token);
                    await clientSsl.FlushAsync(timeout.Token);
                    await ReadExactlyAsync(serverSsl, requestBuffer, timeout.Token);
                    await serverSsl.WriteAsync(response, timeout.Token);
                    await serverSsl.FlushAsync(timeout.Token);
                    await ReadExactlyAsync(clientSsl, responseBuffer, timeout.Token);
                    result.ResponseText = Encoding.UTF8.GetString(responseBuffer);
                    result.ApplicationDataSucceeded =
                        requestBuffer.AsSpan().SequenceEqual(request) &&
                        responseBuffer.AsSpan().SequenceEqual(response);

                    // Permit TLS 1.3 NewSessionTicket processing before shutdown.
                    await Task.Delay(600, timeout.Token);
                    await Task.WhenAll(
                        IgnoreAsync(() => clientSsl.ShutdownAsync()),
                        IgnoreAsync(() => serverSsl.ShutdownAsync()))
                        .WaitAsync(TimeSpan.FromSeconds(4));
                }
            }
            catch (Exception exception)
            {
                result.HarnessError = Describe(exception);
            }
            finally
            {
                clientSsl?.Dispose();
                serverSsl?.Dispose();
                accepted?.Dispose();
            }
            return result;
        }

        public void Dispose() => _listener.Stop();
    }

    private sealed class ClientCertificatePolicy
    {
        private readonly string _expectedThumbprint;
        private int _calls;
        private int _null;
        private int _valid;
        private int _other;

        public ClientCertificatePolicy(string expectedThumbprint)
            => _expectedThumbprint = expectedThumbprint;

        public int Calls => Volatile.Read(ref _calls);
        public int NullCertificateCalls => Volatile.Read(ref _null);
        public int ValidCertificateCalls => Volatile.Read(ref _valid);
        public int OtherCertificateCalls => Volatile.Read(ref _other);

        public bool Validate(
            object sender,
            X509Certificate? certificate,
            X509Chain? chain,
            SslPolicyErrors errors)
        {
            _ = sender;
            _ = chain;
            _ = errors;
            Interlocked.Increment(ref _calls);
            if (certificate is null)
            {
                Interlocked.Increment(ref _null);
                return false;
            }
            string actual = certificate.GetCertHashString(HashAlgorithmName.SHA256);
            if (string.Equals(actual, _expectedThumbprint, StringComparison.OrdinalIgnoreCase))
            {
                Interlocked.Increment(ref _valid);
                return true;
            }
            Interlocked.Increment(ref _other);
            return false;
        }

        public void Reset()
        {
            Volatile.Write(ref _calls, 0);
            Volatile.Write(ref _null, 0);
            Volatile.Write(ref _valid, 0);
            Volatile.Write(ref _other, 0);
        }
    }

    private sealed class OwnedCertificate : IDisposable
    {
        private readonly RSA _key;
        private OwnedCertificate(RSA key, X509Certificate2 certificate)
        {
            _key = key;
            Certificate = certificate;
        }

        public X509Certificate2 Certificate { get; }
        public static OwnedCertificate CreateServer(string name) => Create(name, true);
        public static OwnedCertificate CreateClient(string name) => Create(name, false);

        private static OwnedCertificate Create(string name, bool server)
        {
            RSA key = RSA.Create(2048);
            var request = new CertificateRequest(
                $"CN={name}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection
                {
                    new(server ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2"),
                }, true));
            if (server)
            {
                var san = new SubjectAlternativeNameBuilder();
                san.AddDnsName(name);
                request.CertificateExtensions.Add(san.Build());
            }
            X509Certificate2 certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2));
            return new OwnedCertificate(key, certificate);
        }

        public void Dispose()
        {
            Certificate.Dispose();
            _key.Dispose();
        }
    }

    private static class NativeResumeDetector
    {
        private static readonly FieldInfo? ContextHandleField;
        private static readonly FieldInfo? LowerField;
        private static readonly FieldInfo? UpperField;

        static NativeResumeDetector()
        {
            if (OperatingSystem.IsWindows() && SecurityContextField is not null)
            {
                Type? contextType = SecurityContextField.FieldType;
                ContextHandleField = FindField(contextType, "_handle");
                Type? handleType = ContextHandleField?.FieldType;
                LowerField = handleType is null ? null : FindField(handleType, "dwLower");
                UpperField = handleType is null ? null : FindField(handleType, "dwUpper");
            }
        }

        public static string Description => OperatingSystem.IsWindows()
            ? "Schannel QueryContextAttributesW(SECPKG_ATTR_SESSION_INFO)"
            : OperatingSystem.IsLinux()
                ? "CryptoNative_SslSessionReused(SSL*)"
                : "unsupported-platform";

        public static bool? IsResumed(SslStream stream)
        {
            object? context = SecurityContextField?.GetValue(stream);
            if (context is null)
            {
                return null;
            }

            try
            {
                if (OperatingSystem.IsLinux())
                {
                    if (context is not SafeHandle safeHandle)
                    {
                        return null;
                    }
                    bool release = false;
                    try
                    {
                        safeHandle.DangerousAddRef(ref release);
                        IntPtr ssl = safeHandle.DangerousGetHandle();
                        return ssl == IntPtr.Zero ? null : CryptoNativeSslSessionReused(ssl) != 0;
                    }
                    finally
                    {
                        if (release) safeHandle.DangerousRelease();
                    }
                }

                if (OperatingSystem.IsWindows())
                {
                    object? boxedHandle = ContextHandleField?.GetValue(context);
                    if (boxedHandle is null || LowerField is null || UpperField is null)
                    {
                        return null;
                    }
                    var handle = new CredHandle
                    {
                        Lower = (IntPtr)(LowerField.GetValue(boxedHandle) ?? IntPtr.Zero),
                        Upper = (IntPtr)(UpperField.GetValue(boxedHandle) ?? IntPtr.Zero),
                    };
                    int status = QueryContextAttributesW(
                        ref handle, SecPkgAttrSessionInfo, out SessionInfo info);
                    return status == 0 ? (info.Flags & SslSessionReconnect) != 0 : null;
                }
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
            catch (TargetInvocationException) { }
            catch (InvalidOperationException) { }
            return null;
        }

        private static FieldInfo? FindField(Type? type, string name)
        {
            while (type is not null)
            {
                FieldInfo? field = type.GetField(name, InstanceFlags);
                if (field is not null) return field;
                type = type.BaseType;
            }
            return null;
        }

        [DllImport("System.Security.Cryptography.Native.OpenSsl",
            EntryPoint = "CryptoNative_SslSessionReused")]
        private static extern int CryptoNativeSslSessionReused(IntPtr ssl);

        [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
        private static extern int QueryContextAttributesW(
            ref CredHandle context,
            int attribute,
            out SessionInfo buffer);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct CredHandle
        {
            public IntPtr Lower;
            public IntPtr Upper;
        }

        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct SessionInfo
        {
            public uint Flags;
            public uint SessionIdLength;
            public fixed byte SessionId[32];
        }
    }
}

internal sealed class FinalResult
{
    public string Schema { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string? InvalidReason { get; set; }
    public string Runtime { get; set; } = string.Empty;
    public string Framework { get; set; } = string.Empty;
    public string Os { get; set; } = string.Empty;
    public string ResumptionDetector { get; set; } = string.Empty;
    public bool SecurityContextFieldFound { get; set; }
    public List<ProtocolResult> Protocols { get; set; } = new();
}

internal sealed class ProtocolResult
{
    public string Protocol { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string? Reason { get; set; }
    public List<TrialResult> Trials { get; set; } = new();
}

internal sealed class TrialResult
{
    public int TrialNumber { get; set; }
    public string? InvalidReason { get; set; }
    public bool ResumeBaselineProved { get; set; }
    public bool ControlsPassed { get; set; }
    public bool CandidatePositive { get; set; }
    public bool FreshStrictAnonymousControlPassed { get; set; }
    public bool ValidClientCertificateControlPassed { get; set; }
    public bool WrongClientCertificateControlPassed { get; set; }
    public bool StrictNoResumeControlPassed { get; set; }
    public ConnectionResult FreshStrictAnonymous { get; set; } = new();
    public ConnectionResult ValidClientCertificate { get; set; } = new();
    public ConnectionResult WrongClientCertificate { get; set; } = new();
    public ConnectionResult PublicInitial { get; set; } = new();
    public List<ConnectionResult> PublicResumeProbes { get; set; } = new();
    public ConnectionResult Candidate { get; set; } = new();
    public ConnectionResult StrictNoResume { get; set; } = new();
}

internal sealed class ConnectionResult
{
    public string Label { get; set; } = string.Empty;
    public bool HandshakeSucceeded { get; set; }
    public bool ApplicationDataSucceeded { get; set; }
    public bool? ClientTlsResumed { get; set; }
    public bool? ServerTlsResumed { get; set; }
    public bool ServerRemoteCertificatePresent { get; set; }
    public bool ClientLocalCertificatePresent { get; set; }
    public int StrictCallbackCount { get; set; }
    public int StrictNullCertificateCalls { get; set; }
    public int StrictValidCertificateCalls { get; set; }
    public int StrictOtherCertificateCalls { get; set; }
    public string? NegotiatedProtocol { get; set; }
    public string? ResponseText { get; set; }
    public string? ClientAuthenticationError { get; set; }
    public string? ServerAuthenticationError { get; set; }
    public string? HarnessError { get; set; }
}
