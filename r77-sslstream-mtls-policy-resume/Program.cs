using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

internal static class Program
{
    private const int TrialsPerProtocol = 3;
    private const int ResumeProbeLimit = 12;
    private static readonly BindingFlags ReflectionFlags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
    private static readonly FieldInfo? ConnectionInfoField = typeof(SslStream).GetField("_connectionInfo", ReflectionFlags);
    private static readonly PropertyInfo? TlsResumedProperty = typeof(SslStream).Assembly
        .GetType("System.Net.Security.SslConnectionInfo")?
        .GetProperty("TlsResumed", ReflectionFlags);

    public static async Task<int> Main(string[] args)
    {
        string outputPath = args.Length > 0 ? args[0] : "result.json";
        var protocolResults = new List<ProtocolResult>();

        if (ConnectionInfoField is null || TlsResumedProperty is null)
        {
            return await WriteResultAsync(outputPath, new FinalResult
            {
                Status = "INVALID_RUNTIME",
                InvalidReason = "Unable to inspect SslConnectionInfo.TlsResumed on this runtime.",
                Protocols = protocolResults,
            });
        }

        foreach (SslProtocols protocol in new[] { SslProtocols.Tls12, SslProtocols.Tls13 })
        {
            ProtocolResult result = await RunProtocolAsync(protocol);
            protocolResults.Add(result);
        }

        List<ProtocolResult> supported = protocolResults.Where(p => p.Supported).ToList();
        string status;
        string? invalidReason = null;

        if (supported.Count == 0)
        {
            status = "INVALID_RUNTIME";
            invalidReason = "Neither TLS 1.2 nor TLS 1.3 produced a valid controlled runtime matrix.";
        }
        else if (supported.Any(p => p.Status is "INVALID_RUNTIME" or "INCONCLUSIVE" or "UNTESTABLE_NO_RESUMPTION"))
        {
            status = "INVALID_RUNTIME";
            invalidReason = "At least one supported protocol failed a control or produced an incomplete/inconsistent matrix.";
        }
        else if (supported.Any(p => p.Status == "RUNTIME_POSITIVE_REVIEW_REQUIRED"))
        {
            status = "RUNTIME_POSITIVE_REVIEW_REQUIRED";
        }
        else
        {
            status = "RUNTIME_NEGATIVE_CLOSED";
        }

        return await WriteResultAsync(outputPath, new FinalResult
        {
            Status = status,
            InvalidReason = invalidReason,
            Protocols = protocolResults,
        });
    }

    private static async Task<int> WriteResultAsync(string outputPath, FinalResult result)
    {
        result.Schema = "r77-sslstream-mtls-policy-resume/v1";
        result.Runtime = Environment.Version.ToString();
        result.Framework = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription;
        result.Os = System.Runtime.InteropServices.RuntimeInformation.OSDescription;
        result.Reflection = new ReflectionResult
        {
            ConnectionInfoField = ConnectionInfoField is not null,
            TlsResumedProperty = TlsResumedProperty is not null,
        };

        string json = JsonSerializer.Serialize(result, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        });

        Console.WriteLine(json);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
        await File.WriteAllTextAsync(outputPath, json + Environment.NewLine);

        return result.Status switch
        {
            "RUNTIME_POSITIVE_REVIEW_REQUIRED" => 10,
            "INVALID_RUNTIME" => 2,
            _ => 0,
        };
    }

    private static async Task<ProtocolResult> RunProtocolAsync(SslProtocols protocol)
    {
        var trials = new List<TrialResult>();

        for (int trialNumber = 1; trialNumber <= TrialsPerProtocol; trialNumber++)
        {
            TrialResult trial;
            try
            {
                trial = await RunTrialAsync(protocol, trialNumber);
            }
            catch (Exception exception)
            {
                string description = Describe(exception);
                bool unsupported = description.Contains("protocol", StringComparison.OrdinalIgnoreCase)
                    && (description.Contains("not supported", StringComparison.OrdinalIgnoreCase)
                        || description.Contains("unsupported", StringComparison.OrdinalIgnoreCase)
                        || description.Contains("no protocols", StringComparison.OrdinalIgnoreCase));

                if (unsupported)
                {
                    return new ProtocolResult
                    {
                        Protocol = protocol.ToString(),
                        Supported = false,
                        Status = "UNSUPPORTED",
                        InvalidReason = description,
                        Trials = trials,
                    };
                }

                trials.Add(new TrialResult
                {
                    TrialNumber = trialNumber,
                    InvalidReason = description,
                });
                break;
            }

            trials.Add(trial);
        }

        bool complete = trials.Count == TrialsPerProtocol && trials.All(t => t.InvalidReason is null);
        bool controls = complete && trials.All(t => t.ControlsPassed);
        int positives = trials.Count(t => t.CandidatePositive);
        string status;
        string? invalidReason = null;

        if (!complete || !controls)
        {
            status = "INVALID_RUNTIME";
            invalidReason = !complete
                ? "The protocol matrix did not complete all trials."
                : "One or more matched controls failed.";
        }
        else if (positives == TrialsPerProtocol)
        {
            status = "RUNTIME_POSITIVE_REVIEW_REQUIRED";
        }
        else if (positives == 0)
        {
            status = "RUNTIME_NEGATIVE_CLOSED";
        }
        else
        {
            status = "INCONCLUSIVE";
            invalidReason = $"The candidate was positive in {positives}/{TrialsPerProtocol} trials.";
        }

        if (complete && trials.Any(t => !t.ResumeBaselineProved))
        {
            status = "UNTESTABLE_NO_RESUMPTION";
            invalidReason = "The anonymous public policy could not establish an observed resumed session.";
        }

        return new ProtocolResult
        {
            Protocol = protocol.ToString(),
            Supported = true,
            Status = status,
            InvalidReason = invalidReason,
            Trials = trials,
        };
    }

    private static async Task<TrialResult> RunTrialAsync(SslProtocols protocol, int trialNumber)
    {
        string prefix = $"r77-{protocol}-{trialNumber}-{Guid.NewGuid():N}";
        var trial = new TrialResult { TrialNumber = trialNumber };

        // Control A: a strict endpoint reached without any prior anonymous session must reject an anonymous client.
        using (var serverCertificate = OwnedCertificate.CreateServer($"{prefix}-fresh.local"))
        using (var runner = new EndpointRunner())
        {
            var strictPolicy = new StrictClientCertificatePolicy(expectedThumbprint: "never-matches");
            SslServerAuthenticationOptions strictOptions = CreateServerOptions(
                protocol,
                serverCertificate.Certificate,
                clientCertificateRequired: true,
                allowTlsResume: true,
                strictPolicy.Validate);
            SslClientAuthenticationOptions anonymousClient = CreateClientOptions(
                protocol,
                $"{prefix}-fresh.local",
                allowTlsResume: true,
                clientCertificate: null);

            strictPolicy.Reset();
            trial.FreshStrictAnonymous = await runner.ExchangeAsync(
                "fresh-strict-anonymous",
                strictOptions,
                anonymousClient,
                "ADMIN-FRESH");
            trial.FreshStrictAnonymous.StrictCallbackCount = strictPolicy.Calls;
            trial.FreshStrictAnonymous.StrictNullCertificateCalls = strictPolicy.NullCertificateCalls;
            trial.FreshStrictAnonymousControlPassed =
                !trial.FreshStrictAnonymous.HandshakeSucceeded &&
                !trial.FreshStrictAnonymous.ApplicationDataSucceeded;
        }

        // Control B: a valid client certificate must satisfy the same strict policy on a full handshake.
        using (var serverCertificate = OwnedCertificate.CreateServer($"{prefix}-valid.local"))
        using (var validClientCertificate = OwnedCertificate.CreateClient($"{prefix}-valid-client"))
        using (var runner = new EndpointRunner())
        {
            string expected = validClientCertificate.Certificate.GetCertHashString(HashAlgorithmName.SHA256);
            var strictPolicy = new StrictClientCertificatePolicy(expected);
            SslServerAuthenticationOptions strictOptions = CreateServerOptions(
                protocol,
                serverCertificate.Certificate,
                clientCertificateRequired: true,
                allowTlsResume: false,
                strictPolicy.Validate);
            SslClientAuthenticationOptions validClient = CreateClientOptions(
                protocol,
                $"{prefix}-valid.local",
                allowTlsResume: false,
                validClientCertificate.Certificate);

            strictPolicy.Reset();
            trial.ValidClientCertificate = await runner.ExchangeAsync(
                "strict-valid-client-certificate",
                strictOptions,
                validClient,
                "ADMIN-VALID");
            trial.ValidClientCertificate.StrictCallbackCount = strictPolicy.Calls;
            trial.ValidClientCertificate.StrictValidCertificateCalls = strictPolicy.ValidCertificateCalls;
            trial.ValidClientCertificateControlPassed =
                trial.ValidClientCertificate.HandshakeSucceeded &&
                trial.ValidClientCertificate.ApplicationDataSucceeded &&
                trial.ValidClientCertificate.ServerRemoteCertificatePresent &&
                strictPolicy.Calls >= 1 &&
                strictPolicy.ValidCertificateCalls >= 1;
        }

        // Control C: a presented but untrusted client certificate must be rejected.
        using (var serverCertificate = OwnedCertificate.CreateServer($"{prefix}-invalid.local"))
        using (var expectedClientCertificate = OwnedCertificate.CreateClient($"{prefix}-expected-client"))
        using (var invalidClientCertificate = OwnedCertificate.CreateClient($"{prefix}-invalid-client"))
        using (var runner = new EndpointRunner())
        {
            string expected = expectedClientCertificate.Certificate.GetCertHashString(HashAlgorithmName.SHA256);
            var strictPolicy = new StrictClientCertificatePolicy(expected);
            SslServerAuthenticationOptions strictOptions = CreateServerOptions(
                protocol,
                serverCertificate.Certificate,
                clientCertificateRequired: true,
                allowTlsResume: false,
                strictPolicy.Validate);
            SslClientAuthenticationOptions invalidClient = CreateClientOptions(
                protocol,
                $"{prefix}-invalid.local",
                allowTlsResume: false,
                invalidClientCertificate.Certificate);

            strictPolicy.Reset();
            trial.InvalidClientCertificate = await runner.ExchangeAsync(
                "strict-invalid-client-certificate",
                strictOptions,
                invalidClient,
                "ADMIN-INVALID");
            trial.InvalidClientCertificate.StrictCallbackCount = strictPolicy.Calls;
            trial.InvalidClientCertificate.StrictOtherCertificateCalls = strictPolicy.OtherCertificateCalls;
            trial.InvalidClientCertificateControlPassed =
                !trial.InvalidClientCertificate.HandshakeSucceeded &&
                !trial.InvalidClientCertificate.ApplicationDataSucceeded &&
                strictPolicy.Calls >= 1 &&
                strictPolicy.OtherCertificateCalls >= 1;
        }

        // Candidate: prime an anonymous session under the public policy, prove actual resumption,
        // then switch the server policy to require and validate a client certificate while keeping
        // the same server certificate, protocol, process and TLS cache scope.
        using (var serverCertificate = OwnedCertificate.CreateServer($"{prefix}-shared.local"))
        using (var expectedClientCertificate = OwnedCertificate.CreateClient($"{prefix}-shared-expected-client"))
        using (var runner = new EndpointRunner())
        {
            string host = $"{prefix}-shared.local";
            string expected = expectedClientCertificate.Certificate.GetCertHashString(HashAlgorithmName.SHA256);
            var strictPolicy = new StrictClientCertificatePolicy(expected);

            SslServerAuthenticationOptions publicOptions = CreateServerOptions(
                protocol,
                serverCertificate.Certificate,
                clientCertificateRequired: false,
                allowTlsResume: true,
                validationCallback: null);
            SslServerAuthenticationOptions strictOptions = CreateServerOptions(
                protocol,
                serverCertificate.Certificate,
                clientCertificateRequired: true,
                allowTlsResume: true,
                strictPolicy.Validate);
            SslClientAuthenticationOptions anonymousClient = CreateClientOptions(
                protocol,
                host,
                allowTlsResume: true,
                clientCertificate: null);

            trial.PublicInitial = await runner.ExchangeAsync(
                "public-initial",
                publicOptions,
                anonymousClient,
                "PUBLIC-INITIAL");

            if (!trial.PublicInitial.HandshakeSucceeded ||
                !trial.PublicInitial.ApplicationDataSucceeded ||
                trial.PublicInitial.ServerRemoteCertificatePresent)
            {
                trial.InvalidReason = "The anonymous public-policy baseline failed.";
                return trial;
            }

            for (int probe = 1; probe <= ResumeProbeLimit; probe++)
            {
                ConnectionResult connection = await runner.ExchangeAsync(
                    $"public-resume-probe-{probe}",
                    publicOptions,
                    anonymousClient,
                    $"PUBLIC-PROBE-{probe}");
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
                trial.InvalidReason = "A resumed anonymous public-policy session was not observed.";
                return trial;
            }

            strictPolicy.Reset();
            trial.CandidateStrictAfterAnonymousResume = await runner.ExchangeAsync(
                "candidate-strict-after-anonymous-resume",
                strictOptions,
                anonymousClient,
                $"ADMIN-CANARY-{trialNumber}");
            trial.CandidateStrictAfterAnonymousResume.StrictCallbackCount = strictPolicy.Calls;
            trial.CandidateStrictAfterAnonymousResume.StrictNullCertificateCalls = strictPolicy.NullCertificateCalls;

            trial.CandidatePositive =
                trial.CandidateStrictAfterAnonymousResume.HandshakeSucceeded &&
                trial.CandidateStrictAfterAnonymousResume.ApplicationDataSucceeded &&
                trial.CandidateStrictAfterAnonymousResume.ClientTlsResumed == true &&
                trial.CandidateStrictAfterAnonymousResume.ServerTlsResumed == true &&
                !trial.CandidateStrictAfterAnonymousResume.ServerRemoteCertificatePresent &&
                strictPolicy.Calls == 0;

            // Matched control: disable client resumption while retaining the same server-side
            // certificate/context cache. The strict policy must reject the anonymous full handshake.
            SslClientAuthenticationOptions anonymousNoResume = CreateClientOptions(
                protocol,
                host,
                allowTlsResume: false,
                clientCertificate: null);
            strictPolicy.Reset();
            trial.StrictNoResumeControl = await runner.ExchangeAsync(
                "strict-anonymous-no-resume-control",
                strictOptions,
                anonymousNoResume,
                "ADMIN-NO-RESUME");
            trial.StrictNoResumeControl.StrictCallbackCount = strictPolicy.Calls;
            trial.StrictNoResumeControl.StrictNullCertificateCalls = strictPolicy.NullCertificateCalls;
            trial.StrictNoResumeControlPassed =
                !trial.StrictNoResumeControl.HandshakeSucceeded &&
                !trial.StrictNoResumeControl.ApplicationDataSucceeded;
        }

        trial.ControlsPassed =
            trial.FreshStrictAnonymousControlPassed &&
            trial.ValidClientCertificateControlPassed &&
            trial.InvalidClientCertificateControlPassed &&
            trial.StrictNoResumeControlPassed &&
            trial.ResumeBaselineProved;

        return trial;
    }

    private static SslServerAuthenticationOptions CreateServerOptions(
        SslProtocols protocol,
        X509Certificate2 serverCertificate,
        bool clientCertificateRequired,
        bool allowTlsResume,
        RemoteCertificateValidationCallback? validationCallback)
    {
        return new SslServerAuthenticationOptions
        {
            EnabledSslProtocols = protocol,
            ServerCertificateContext = SslStreamCertificateContext.Create(serverCertificate, null, offline: true),
            ClientCertificateRequired = clientCertificateRequired,
            AllowTlsResume = allowTlsResume,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = validationCallback,
        };
    }

    private static SslClientAuthenticationOptions CreateClientOptions(
        SslProtocols protocol,
        string targetHost,
        bool allowTlsResume,
        X509Certificate2? clientCertificate)
    {
        var options = new SslClientAuthenticationOptions
        {
            TargetHost = targetHost,
            EnabledSslProtocols = protocol,
            AllowTlsResume = allowTlsResume,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = static (_, _, _, _) => true,
        };

        if (clientCertificate is not null)
        {
            options.ClientCertificates = new X509CertificateCollection { clientCertificate };
        }

        return options;
    }

    private static bool? GetTlsResumed(SslStream stream)
    {
        try
        {
            object? connectionInfo = ConnectionInfoField?.GetValue(stream);
            object? value = connectionInfo is null ? null : TlsResumedProperty?.GetValue(connectionInfo);
            return value is bool resumed ? resumed : null;
        }
        catch
        {
            return null;
        }
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer[offset..], cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }
            offset += read;
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
        try
        {
            await action();
        }
        catch
        {
        }
    }

    private static string Describe(Exception exception)
        => $"{exception.GetType().FullName}: {exception.Message}";

    private sealed class EndpointRunner : IDisposable
    {
        private readonly TcpListener _listener;

        public EndpointRunner()
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
        }

        public async Task<ConnectionResult> ExchangeAsync(
            string label,
            SslServerAuthenticationOptions serverOptions,
            SslClientAuthenticationOptions clientOptions,
            string responseMarker)
        {
            var result = new ConnectionResult { Label = label };
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            TcpClient? acceptedClient = null;
            SslStream? clientSsl = null;
            SslStream? serverSsl = null;

            try
            {
                Task<TcpClient> acceptTask = _listener.AcceptTcpClientAsync(cancellation.Token).AsTask();
                using var clientTcp = new TcpClient { NoDelay = true };
                int port = ((IPEndPoint)_listener.LocalEndpoint).Port;
                await clientTcp.ConnectAsync(IPAddress.Loopback, port, cancellation.Token);
                acceptedClient = await acceptTask;
                acceptedClient.NoDelay = true;

                clientSsl = new SslStream(clientTcp.GetStream(), leaveInnerStreamOpen: false);
                serverSsl = new SslStream(acceptedClient.GetStream(), leaveInnerStreamOpen: false);

                Task<Exception?> clientAuthentication = CaptureAsync(
                    () => clientSsl.AuthenticateAsClientAsync(clientOptions, cancellation.Token));
                Task<Exception?> serverAuthentication = CaptureAsync(
                    () => serverSsl.AuthenticateAsServerAsync(serverOptions, cancellation.Token));

                await Task.WhenAll(clientAuthentication, serverAuthentication).WaitAsync(cancellation.Token);
                Exception? clientException = await clientAuthentication;
                Exception? serverException = await serverAuthentication;
                result.ClientAuthenticationError = clientException is null ? null : Describe(clientException);
                result.ServerAuthenticationError = serverException is null ? null : Describe(serverException);
                result.HandshakeSucceeded =
                    clientException is null &&
                    serverException is null &&
                    clientSsl.IsAuthenticated &&
                    serverSsl.IsAuthenticated;

                result.ClientTlsResumed = GetTlsResumed(clientSsl);
                result.ServerTlsResumed = GetTlsResumed(serverSsl);

                if (result.HandshakeSucceeded)
                {
                    result.ServerRemoteCertificatePresent = serverSsl.RemoteCertificate is not null;
                    result.ClientLocalCertificatePresent = clientSsl.LocalCertificate is not null;
                    result.NegotiatedProtocol = clientSsl.SslProtocol.ToString();

                    byte[] request = Encoding.ASCII.GetBytes("PING");
                    byte[] receivedRequest = new byte[request.Length];
                    byte[] response = Encoding.UTF8.GetBytes(responseMarker);
                    byte[] receivedResponse = new byte[response.Length];

                    await clientSsl.WriteAsync(request, cancellation.Token);
                    await clientSsl.FlushAsync(cancellation.Token);
                    await ReadExactlyAsync(serverSsl, receivedRequest, cancellation.Token);
                    await serverSsl.WriteAsync(response, cancellation.Token);
                    await serverSsl.FlushAsync(cancellation.Token);
                    await ReadExactlyAsync(clientSsl, receivedResponse, cancellation.Token);

                    result.ResponseText = Encoding.UTF8.GetString(receivedResponse);
                    result.ApplicationDataSucceeded =
                        receivedRequest.AsSpan().SequenceEqual(request) &&
                        receivedResponse.AsSpan().SequenceEqual(response);

                    // TLS 1.3 session tickets are post-handshake messages. Keep the connection
                    // alive briefly after bidirectional data so the client can process the ticket.
                    await Task.Delay(500, cancellation.Token);
                    await Task.WhenAll(
                        IgnoreAsync(() => clientSsl.ShutdownAsync()),
                        IgnoreAsync(() => serverSsl.ShutdownAsync()))
                        .WaitAsync(TimeSpan.FromSeconds(3));
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
                acceptedClient?.Dispose();
            }

            return result;
        }

        public void Dispose() => _listener.Stop();
    }

    private sealed class StrictClientCertificatePolicy
    {
        private readonly string _expectedThumbprint;
        private int _calls;
        private int _nullCertificateCalls;
        private int _validCertificateCalls;
        private int _otherCertificateCalls;

        public StrictClientCertificatePolicy(string expectedThumbprint)
        {
            _expectedThumbprint = expectedThumbprint;
        }

        public int Calls => Volatile.Read(ref _calls);
        public int NullCertificateCalls => Volatile.Read(ref _nullCertificateCalls);
        public int ValidCertificateCalls => Volatile.Read(ref _validCertificateCalls);
        public int OtherCertificateCalls => Volatile.Read(ref _otherCertificateCalls);

        public bool Validate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
        {
            _ = sender;
            _ = chain;
            _ = errors;
            Interlocked.Increment(ref _calls);

            if (certificate is null)
            {
                Interlocked.Increment(ref _nullCertificateCalls);
                return false;
            }

            string actual = certificate.GetCertHashString(HashAlgorithmName.SHA256);
            if (string.Equals(actual, _expectedThumbprint, StringComparison.OrdinalIgnoreCase))
            {
                Interlocked.Increment(ref _validCertificateCalls);
                return true;
            }

            Interlocked.Increment(ref _otherCertificateCalls);
            return false;
        }

        public void Reset()
        {
            Volatile.Write(ref _calls, 0);
            Volatile.Write(ref _nullCertificateCalls, 0);
            Volatile.Write(ref _validCertificateCalls, 0);
            Volatile.Write(ref _otherCertificateCalls, 0);
        }
    }

    private sealed class OwnedCertificate : IDisposable
    {
        private OwnedCertificate(RSA key, X509Certificate2 certificate)
        {
            Key = key;
            Certificate = certificate;
        }

        private RSA Key { get; }
        public X509Certificate2 Certificate { get; }

        public static OwnedCertificate CreateServer(string dnsName)
            => Create(dnsName, server: true);

        public static OwnedCertificate CreateClient(string commonName)
            => Create(commonName, server: false);

        private static OwnedCertificate Create(string name, bool server)
        {
            RSA key = RSA.Create(2048);
            var request = new CertificateRequest(
                $"CN={name}",
                key,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                critical: true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection
                {
                    new(server ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2"),
                },
                critical: true));

            if (server)
            {
                var san = new SubjectAlternativeNameBuilder();
                san.AddDnsName(name);
                request.CertificateExtensions.Add(san.Build());
            }

            X509Certificate2 certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddDays(2));
            return new OwnedCertificate(key, certificate);
        }

        public void Dispose()
        {
            Certificate.Dispose();
            Key.Dispose();
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
    public ReflectionResult Reflection { get; set; } = new();
    public List<ProtocolResult> Protocols { get; set; } = new();
}

internal sealed class ReflectionResult
{
    public bool ConnectionInfoField { get; set; }
    public bool TlsResumedProperty { get; set; }
}

internal sealed class ProtocolResult
{
    public string Protocol { get; set; } = string.Empty;
    public bool Supported { get; set; }
    public string Status { get; set; } = string.Empty;
    public string? InvalidReason { get; set; }
    public List<TrialResult> Trials { get; set; } = new();
}

internal sealed class TrialResult
{
    public int TrialNumber { get; set; }
    public bool ControlsPassed { get; set; }
    public bool CandidatePositive { get; set; }
    public bool ResumeBaselineProved { get; set; }
    public string? InvalidReason { get; set; }
    public bool FreshStrictAnonymousControlPassed { get; set; }
    public bool ValidClientCertificateControlPassed { get; set; }
    public bool InvalidClientCertificateControlPassed { get; set; }
    public bool StrictNoResumeControlPassed { get; set; }
    public ConnectionResult FreshStrictAnonymous { get; set; } = new();
    public ConnectionResult ValidClientCertificate { get; set; } = new();
    public ConnectionResult InvalidClientCertificate { get; set; } = new();
    public ConnectionResult PublicInitial { get; set; } = new();
    public List<ConnectionResult> PublicResumeProbes { get; set; } = new();
    public ConnectionResult CandidateStrictAfterAnonymousResume { get; set; } = new();
    public ConnectionResult StrictNoResumeControl { get; set; } = new();
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
