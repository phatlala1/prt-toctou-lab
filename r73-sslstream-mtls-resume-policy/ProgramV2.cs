using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

internal static class ProgramV2
{
    private const string RevalidateSwitch = "System.Net.Security.RevalidateCertificateOnTlsResume";
    private static readonly BindingFlags Flags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
    private static readonly FieldInfo? ConnectionInfoField = typeof(SslStream).GetField("_connectionInfo", Flags);
    private static readonly Type? ConnectionInfoType = typeof(SslStream).Assembly.GetType("System.Net.Security.SslConnectionInfo");
    private static readonly PropertyInfo? TlsResumedProperty = ConnectionInfoType?.GetProperty("TlsResumed", Flags);

    public static async Task<int> Main(string[] args)
    {
        if (args.Length != 2 || (args[0] != "default" && args[0] != "revalidate"))
        {
            Console.Error.WriteLine("Usage: dotnet R73.dll <default|revalidate> <output.json>");
            return 2;
        }

        bool revalidate = args[0] == "revalidate";
        AppContext.SetSwitch(RevalidateSwitch, revalidate);

        var result = new MatrixRun
        {
            Schema = "r73-sslstream-mtls-resume-policy/v2",
            Mode = args[0],
            RevalidateCertificateOnTlsResume = revalidate,
            Runtime = Environment.Version.ToString(),
            OperatingSystem = Environment.OSVersion.ToString(),
            StartedUtc = DateTimeOffset.UtcNow,
            Reflection = new ReflectionStatus
            {
                ConnectionInfoFieldFound = ConnectionInfoField is not null,
                ConnectionInfoTypeFound = ConnectionInfoType is not null,
                TlsResumedPropertyFound = TlsResumedProperty is not null,
                ConnectionInfoFieldType = ConnectionInfoField?.FieldType.FullName,
                ConnectionInfoRuntimeType = ConnectionInfoType?.FullName,
            },
        };

        foreach (SslProtocols protocol in new[] { SslProtocols.Tls12, SslProtocols.Tls13 })
        {
            var protocolResult = new ProtocolRun { Protocol = protocol.ToString() };
            result.Protocols.Add(protocolResult);
            try
            {
                if (revalidate)
                {
                    for (int trial = 1; trial <= 3; trial++)
                    {
                        protocolResult.CandidateTrials.Add(await RunCandidateAsync(protocol, $"revalidate-{trial}"));
                    }
                }
                else
                {
                    protocolResult.StrictFirst = await RunStrictFirstAsync(protocol);
                    protocolResult.LegitimateClientCertificate = await RunLegitimateAsync(protocol);
                    protocolResult.NoResume = await RunNoResumeAsync(protocol);
                    protocolResult.DifferentTargetHost = await RunDifferentHostAsync(protocol);
                    protocolResult.DifferentServerCertificate = await RunDifferentCertificateAsync(protocol);
                    for (int trial = 1; trial <= 3; trial++)
                    {
                        protocolResult.CandidateTrials.Add(await RunCandidateAsync(protocol, $"candidate-{trial}"));
                    }
                }
            }
            catch (Exception ex)
            {
                protocolResult.FatalError = Describe(ex);
            }
        }

        result.CompletedUtc = DateTimeOffset.UtcNow;
        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Converters = { new JsonStringEnumConverter() },
        };
        string json = JsonSerializer.Serialize(result, jsonOptions) + Environment.NewLine;
        string fullOutput = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(Path.GetDirectoryName(fullOutput)!);
        await File.WriteAllTextAsync(fullOutput, json);
        Console.WriteLine(json);
        return 0;
    }

    private static async Task<PolicySequence> RunCandidateAsync(SslProtocols protocol, string name)
    {
        using CertificateBundle server = CertificateBundle.CreateServer($"{name}.r73.test");
        using CertificateBundle expectedClient = CertificateBundle.CreateClient($"R73 Expected {name}");
        var context = SslStreamCertificateContext.Create(server.Certificate, null, offline: true);
        string host = $"{name}-{Guid.NewGuid():N}.r73.test";
        var serverOptions = CreateServerOptions(context, protocol, requireClientCertificate: false, allowResume: true, probe: null);
        var clientOptions = CreateClientOptions(host, protocol, allowResume: true, clientContext: null);
        PrimeResult prime = await PrimeAsync(serverOptions, clientOptions, $"{name}-public");

        var probe = new ValidationProbe(expectedClient.Certificate);
        serverOptions.ClientCertificateRequired = true;
        serverOptions.RemoteCertificateValidationCallback = probe.Validate;
        ConnectionResult admin = await RunPairAsync($"{name}-admin", serverOptions, clientOptions, probe);
        return Sequence(name, host, host, prime, admin);
    }

    private static async Task<PolicySequence> RunNoResumeAsync(SslProtocols protocol)
    {
        using CertificateBundle server = CertificateBundle.CreateServer("no-resume.r73.test");
        using CertificateBundle expectedClient = CertificateBundle.CreateClient("R73 Expected No Resume");
        var context = SslStreamCertificateContext.Create(server.Certificate, null, offline: true);
        string host = $"no-resume-{Guid.NewGuid():N}.r73.test";
        var serverOptions = CreateServerOptions(context, protocol, false, true, null);
        var clientOptions = CreateClientOptions(host, protocol, true, null);
        PrimeResult prime = await PrimeAsync(serverOptions, clientOptions, "no-resume-public");

        var probe = new ValidationProbe(expectedClient.Certificate);
        serverOptions.ClientCertificateRequired = true;
        serverOptions.AllowTlsResume = false;
        serverOptions.RemoteCertificateValidationCallback = probe.Validate;
        ConnectionResult admin = await RunPairAsync("no-resume-admin", serverOptions, clientOptions, probe);
        return Sequence("no-resume", host, host, prime, admin);
    }

    private static async Task<PolicySequence> RunDifferentHostAsync(SslProtocols protocol)
    {
        using CertificateBundle server = CertificateBundle.CreateServer("different-host.r73.test");
        using CertificateBundle expectedClient = CertificateBundle.CreateClient("R73 Expected Different Host");
        var context = SslStreamCertificateContext.Create(server.Certificate, null, offline: true);
        string publicHost = $"public-{Guid.NewGuid():N}.r73.test";
        string adminHost = $"admin-{Guid.NewGuid():N}.r73.test";
        var serverOptions = CreateServerOptions(context, protocol, false, true, null);
        var clientOptions = CreateClientOptions(publicHost, protocol, true, null);
        PrimeResult prime = await PrimeAsync(serverOptions, clientOptions, "different-host-public");

        var probe = new ValidationProbe(expectedClient.Certificate);
        serverOptions.ClientCertificateRequired = true;
        serverOptions.RemoteCertificateValidationCallback = probe.Validate;
        clientOptions.TargetHost = adminHost;
        ConnectionResult admin = await RunPairAsync("different-host-admin", serverOptions, clientOptions, probe);
        return Sequence("different-target-host", publicHost, adminHost, prime, admin);
    }

    private static async Task<PolicySequence> RunDifferentCertificateAsync(SslProtocols protocol)
    {
        using CertificateBundle publicServer = CertificateBundle.CreateServer("public-cert.r73.test");
        using CertificateBundle adminServer = CertificateBundle.CreateServer("admin-cert.r73.test");
        using CertificateBundle expectedClient = CertificateBundle.CreateClient("R73 Expected Different Cert");
        string host = $"different-cert-{Guid.NewGuid():N}.r73.test";
        var publicOptions = CreateServerOptions(
            SslStreamCertificateContext.Create(publicServer.Certificate, null, true), protocol, false, true, null);
        var clientOptions = CreateClientOptions(host, protocol, true, null);
        PrimeResult prime = await PrimeAsync(publicOptions, clientOptions, "different-cert-public");

        var probe = new ValidationProbe(expectedClient.Certificate);
        var adminOptions = CreateServerOptions(
            SslStreamCertificateContext.Create(adminServer.Certificate, null, true), protocol, true, true, probe);
        ConnectionResult admin = await RunPairAsync("different-cert-admin", adminOptions, clientOptions, probe);
        return Sequence("different-server-certificate", host, host, prime, admin);
    }

    private static async Task<PolicySequence> RunStrictFirstAsync(SslProtocols protocol)
    {
        using CertificateBundle server = CertificateBundle.CreateServer("strict-first.r73.test");
        using CertificateBundle expectedClient = CertificateBundle.CreateClient("R73 Expected Strict First");
        string host = $"strict-first-{Guid.NewGuid():N}.r73.test";
        var probe = new ValidationProbe(expectedClient.Certificate);
        ConnectionResult admin = await RunPairAsync(
            "strict-first",
            CreateServerOptions(SslStreamCertificateContext.Create(server.Certificate, null, true), protocol, true, true, probe),
            CreateClientOptions(host, protocol, true, null),
            probe);
        return new PolicySequence { Name = "strict-first", TargetHostAdmin = host, Admin = admin };
    }

    private static async Task<PolicySequence> RunLegitimateAsync(SslProtocols protocol)
    {
        using CertificateBundle server = CertificateBundle.CreateServer("legitimate.r73.test");
        using CertificateBundle client = CertificateBundle.CreateClient("R73 Legitimate Client");
        string host = $"legitimate-{Guid.NewGuid():N}.r73.test";
        var probe = new ValidationProbe(client.Certificate);
        ConnectionResult admin = await RunPairAsync(
            "legitimate-client-certificate",
            CreateServerOptions(SslStreamCertificateContext.Create(server.Certificate, null, true), protocol, true, true, probe),
            CreateClientOptions(host, protocol, true, SslStreamCertificateContext.Create(client.Certificate, null, true)),
            probe);
        return new PolicySequence { Name = "legitimate-client-certificate", TargetHostAdmin = host, Admin = admin };
    }

    private static PolicySequence Sequence(string name, string publicHost, string adminHost, PrimeResult prime, ConnectionResult admin) =>
        new()
        {
            Name = name,
            TargetHostPublic = publicHost,
            TargetHostAdmin = adminHost,
            PrimeResumeObserved = prime.ResumeObserved,
            PublicConnections = prime.Connections,
            Admin = admin,
        };

    private static async Task<PrimeResult> PrimeAsync(
        SslServerAuthenticationOptions serverOptions,
        SslClientAuthenticationOptions clientOptions,
        string label)
    {
        var prime = new PrimeResult();
        for (int round = 1; round <= 6; round++)
        {
            ConnectionResult result = await RunPairAsync($"{label}-{round}", serverOptions, clientOptions, null);
            prime.Connections.Add(result);
            if (!result.ServerAuthenticated || !result.ClientAuthenticated || !result.ApplicationDataSucceeded)
            {
                break;
            }
            if (round > 1 && result.ServerTlsResumed == true && result.ClientTlsResumed == true)
            {
                prime.ResumeObserved = true;
                break;
            }
        }
        return prime;
    }

    private static SslServerAuthenticationOptions CreateServerOptions(
        SslStreamCertificateContext context,
        SslProtocols protocol,
        bool requireClientCertificate,
        bool allowResume,
        ValidationProbe? probe) => new()
        {
            ServerCertificateContext = context,
            EnabledSslProtocols = protocol,
            ClientCertificateRequired = requireClientCertificate,
            AllowTlsResume = allowResume,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = probe is null ? null : probe.Validate,
        };

    private static SslClientAuthenticationOptions CreateClientOptions(
        string targetHost,
        SslProtocols protocol,
        bool allowResume,
        SslStreamCertificateContext? clientContext) => new()
        {
            TargetHost = targetHost,
            EnabledSslProtocols = protocol,
            AllowTlsResume = allowResume,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = static (_, _, _, _) => true,
            ClientCertificateContext = clientContext,
        };

    private static async Task<ConnectionResult> RunPairAsync(
        string label,
        SslServerAuthenticationOptions serverOptions,
        SslClientAuthenticationOptions clientOptions,
        ValidationProbe? probe)
    {
        var result = new ConnectionResult
        {
            Label = label,
            ServerRequiresClientCertificate = serverOptions.ClientCertificateRequired,
            ServerAllowsResume = serverOptions.AllowTlsResume,
            ClientAllowsResume = clientOptions.AllowTlsResume,
            ClientCertificateSupplied = clientOptions.ClientCertificateContext is not null,
        };

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        result.Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var clientTcp = new TcpClient(AddressFamily.InterNetwork);
        TcpClient? serverTcp = null;
        SslStream? clientSsl = null;
        SslStream? serverSsl = null;

        try
        {
            Task<TcpClient> accept = listener.AcceptTcpClientAsync(timeout.Token).AsTask();
            await clientTcp.ConnectAsync(IPAddress.Loopback, result.Port, timeout.Token);
            serverTcp = await accept;
            listener.Stop();
            clientTcp.NoDelay = true;
            serverTcp.NoDelay = true;
            clientSsl = new SslStream(clientTcp.GetStream(), false);
            serverSsl = new SslStream(serverTcp.GetStream(), false);

            Task<Exception?> serverAuth = CaptureAsync(() => serverSsl.AuthenticateAsServerAsync(serverOptions, timeout.Token));
            Task<Exception?> clientAuth = CaptureAsync(() => clientSsl.AuthenticateAsClientAsync(clientOptions, timeout.Token));
            await Task.WhenAll(serverAuth, clientAuth).WaitAsync(timeout.Token);
            Exception? serverError = await serverAuth;
            Exception? clientError = await clientAuth;
            result.ServerException = serverError is null ? null : Describe(serverError);
            result.ClientException = clientError is null ? null : Describe(clientError);
            result.ServerAuthenticated = serverError is null && serverSsl.IsAuthenticated;
            result.ClientAuthenticated = clientError is null && clientSsl.IsAuthenticated;
            result.ServerTlsResumed = ReadTlsResumed(serverSsl, result.ServerReflection);
            result.ClientTlsResumed = ReadTlsResumed(clientSsl, result.ClientReflection);
            result.NegotiatedServerProtocol = result.ServerAuthenticated ? serverSsl.SslProtocol.ToString() : null;
            result.NegotiatedClientProtocol = result.ClientAuthenticated ? clientSsl.SslProtocol.ToString() : null;

            if (result.ServerAuthenticated)
            {
                X509Certificate? remote = serverSsl.RemoteCertificate;
                result.ServerRemoteCertificatePresent = remote is not null;
                result.ServerRemoteCertificateThumbprint = remote?.GetCertHashString();
            }

            if (result.ServerAuthenticated && result.ClientAuthenticated)
            {
                byte[] ping = Encoding.ASCII.GetBytes("R73_PING");
                byte[] pong = Encoding.ASCII.GetBytes("R73_PONG");
                await clientSsl.WriteAsync(ping, timeout.Token);
                await clientSsl.FlushAsync(timeout.Token);
                byte[] request = new byte[ping.Length];
                await serverSsl.ReadExactlyAsync(request, timeout.Token);
                await serverSsl.WriteAsync(pong, timeout.Token);
                await serverSsl.FlushAsync(timeout.Token);
                byte[] response = new byte[pong.Length];
                await clientSsl.ReadExactlyAsync(response, timeout.Token);
                result.ServerReceivedProtectedRequest = request.AsSpan().SequenceEqual(ping);
                result.ClientReceivedProtectedResponse = response.AsSpan().SequenceEqual(pong);
                result.ApplicationDataSucceeded = result.ServerReceivedProtectedRequest && result.ClientReceivedProtectedResponse;

                // Match the runtime's own resumption tests: exchange application data and close gracefully.
                await Task.Delay(250, timeout.Token);
                Task clientShutdown = IgnoreAsync(() => clientSsl.ShutdownAsync(timeout.Token));
                Task serverShutdown = IgnoreAsync(() => serverSsl.ShutdownAsync(timeout.Token));
                await Task.WhenAll(clientShutdown, serverShutdown).WaitAsync(timeout.Token);
            }
        }
        catch (Exception ex)
        {
            result.HarnessException = Describe(ex);
            result.TimedOut = ex is OperationCanceledException && timeout.IsCancellationRequested;
        }
        finally
        {
            result.ServerValidationCallbackCount = probe?.Count ?? 0;
            result.ServerValidationSawCertificate = probe?.SawCertificate ?? false;
            result.ServerValidationSawMissingCertificate = probe?.SawMissingCertificate ?? false;
            listener.Stop();
            clientSsl?.Dispose();
            serverSsl?.Dispose();
            serverTcp?.Dispose();
        }
        return result;
    }

    private static bool? ReadTlsResumed(SslStream stream, ReflectionObservation observation)
    {
        try
        {
            observation.ConnectionInfoFieldFound = ConnectionInfoField is not null;
            observation.TlsResumedPropertyFound = TlsResumedProperty is not null;
            if (ConnectionInfoField is null || TlsResumedProperty is null)
            {
                return null;
            }
            object? info = ConnectionInfoField.GetValue(stream);
            observation.BoxedConnectionInfoType = info?.GetType().FullName;
            object? value = info is null ? null : TlsResumedProperty.GetValue(info);
            observation.ValueType = value?.GetType().FullName;
            return value is bool resumed ? resumed : null;
        }
        catch (Exception ex)
        {
            observation.Error = Describe(ex);
            return null;
        }
    }

    private static async Task<Exception?> CaptureAsync(Func<Task> operation)
    {
        try { await operation(); return null; }
        catch (Exception ex) { return ex; }
    }

    private static async Task IgnoreAsync(Func<Task> operation)
    {
        try { await operation(); } catch { }
    }

    private static string Describe(Exception ex)
    {
        while (ex is AggregateException aggregate && aggregate.InnerExceptions.Count == 1)
        {
            ex = aggregate.InnerExceptions[0];
        }
        return $"{ex.GetType().FullName}: {ex.Message}";
    }

    private sealed class ValidationProbe
    {
        private readonly string _expectedThumbprint;
        private int _count;
        private int _sawCertificate;
        private int _sawMissing;

        public ValidationProbe(X509Certificate2 expected) => _expectedThumbprint = expected.GetCertHashString();
        public int Count => Volatile.Read(ref _count);
        public bool SawCertificate => Volatile.Read(ref _sawCertificate) != 0;
        public bool SawMissingCertificate => Volatile.Read(ref _sawMissing) != 0;

        public bool Validate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
        {
            Interlocked.Increment(ref _count);
            if (certificate is null)
            {
                Volatile.Write(ref _sawMissing, 1);
                return false;
            }
            Volatile.Write(ref _sawCertificate, 1);
            return string.Equals(certificate.GetCertHashString(), _expectedThumbprint, StringComparison.OrdinalIgnoreCase);
        }
    }

    private sealed class CertificateBundle : IDisposable
    {
        private readonly RSA _key;
        public X509Certificate2 Certificate { get; }
        private CertificateBundle(RSA key, X509Certificate2 certificate) { _key = key; Certificate = certificate; }

        public static CertificateBundle CreateServer(string dnsName) => Create(dnsName, "1.3.6.1.5.5.7.3.1", true);
        public static CertificateBundle CreateClient(string commonName) => Create(commonName, "1.3.6.1.5.5.7.3.2", false);

        private static CertificateBundle Create(string name, string ekuOid, bool server)
        {
            RSA key = RSA.Create(2048);
            var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                server ? X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment : X509KeyUsageFlags.DigitalSignature,
                true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(ekuOid) }, true));
            if (server)
            {
                var san = new SubjectAlternativeNameBuilder();
                san.AddDnsName(name);
                request.CertificateExtensions.Add(san.Build());
            }
            X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2));
            return new CertificateBundle(key, certificate);
        }

        public void Dispose() { Certificate.Dispose(); _key.Dispose(); }
    }
}

internal sealed class MatrixRun
{
    public string Schema { get; set; } = string.Empty;
    public string Mode { get; set; } = string.Empty;
    public bool RevalidateCertificateOnTlsResume { get; set; }
    public string Runtime { get; set; } = string.Empty;
    public string OperatingSystem { get; set; } = string.Empty;
    public DateTimeOffset StartedUtc { get; set; }
    public DateTimeOffset CompletedUtc { get; set; }
    public ReflectionStatus Reflection { get; set; } = new();
    public List<ProtocolRun> Protocols { get; } = [];
}
internal sealed class ReflectionStatus
{
    public bool ConnectionInfoFieldFound { get; set; }
    public bool ConnectionInfoTypeFound { get; set; }
    public bool TlsResumedPropertyFound { get; set; }
    public string? ConnectionInfoFieldType { get; set; }
    public string? ConnectionInfoRuntimeType { get; set; }
}
internal sealed class ProtocolRun
{
    public string Protocol { get; set; } = string.Empty;
    public string? FatalError { get; set; }
    public PolicySequence? StrictFirst { get; set; }
    public PolicySequence? LegitimateClientCertificate { get; set; }
    public PolicySequence? NoResume { get; set; }
    public PolicySequence? DifferentTargetHost { get; set; }
    public PolicySequence? DifferentServerCertificate { get; set; }
    public List<PolicySequence> CandidateTrials { get; } = [];
}
internal sealed class PrimeResult
{
    public bool ResumeObserved { get; set; }
    public List<ConnectionResult> Connections { get; } = [];
}
internal sealed class PolicySequence
{
    public string Name { get; set; } = string.Empty;
    public string? TargetHostPublic { get; set; }
    public string? TargetHostAdmin { get; set; }
    public bool PrimeResumeObserved { get; set; }
    public List<ConnectionResult> PublicConnections { get; set; } = [];
    public ConnectionResult? Admin { get; set; }
}
internal sealed class ReflectionObservation
{
    public bool ConnectionInfoFieldFound { get; set; }
    public bool TlsResumedPropertyFound { get; set; }
    public string? BoxedConnectionInfoType { get; set; }
    public string? ValueType { get; set; }
    public string? Error { get; set; }
}
internal sealed class ConnectionResult
{
    public string Label { get; set; } = string.Empty;
    public int Port { get; set; }
    public bool ServerRequiresClientCertificate { get; set; }
    public bool ServerAllowsResume { get; set; }
    public bool ClientAllowsResume { get; set; }
    public bool ClientCertificateSupplied { get; set; }
    public bool ServerAuthenticated { get; set; }
    public bool ClientAuthenticated { get; set; }
    public bool? ServerTlsResumed { get; set; }
    public bool? ClientTlsResumed { get; set; }
    public string? NegotiatedServerProtocol { get; set; }
    public string? NegotiatedClientProtocol { get; set; }
    public bool ServerRemoteCertificatePresent { get; set; }
    public string? ServerRemoteCertificateThumbprint { get; set; }
    public int ServerValidationCallbackCount { get; set; }
    public bool ServerValidationSawCertificate { get; set; }
    public bool ServerValidationSawMissingCertificate { get; set; }
    public bool ServerReceivedProtectedRequest { get; set; }
    public bool ClientReceivedProtectedResponse { get; set; }
    public bool ApplicationDataSucceeded { get; set; }
    public bool TimedOut { get; set; }
    public string? ServerException { get; set; }
    public string? ClientException { get; set; }
    public string? HarnessException { get; set; }
    public ReflectionObservation ServerReflection { get; set; } = new();
    public ReflectionObservation ClientReflection { get; set; } = new();
}
