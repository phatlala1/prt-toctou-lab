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

internal static class Program
{
    private const string RevalidateSwitch = "System.Net.Security.RevalidateCertificateOnTlsResume";
    private static readonly FieldInfo? ConnectionInfoField = typeof(SslStream).GetField(
        "_connectionInfo",
        BindingFlags.Instance | BindingFlags.NonPublic);

    public static async Task<int> Main(string[] args)
    {
        if (args.Length != 2 || (args[0] != "default" && args[0] != "revalidate"))
        {
            Console.Error.WriteLine("Usage: dotnet R73.dll <default|revalidate> <output.json>");
            return 2;
        }

        bool revalidate = args[0] == "revalidate";
        AppContext.SetSwitch(RevalidateSwitch, revalidate);

        var run = new MatrixRun
        {
            Schema = "r73-sslstream-mtls-resume-policy/v1",
            Mode = args[0],
            RevalidateCertificateOnTlsResume = revalidate,
            Runtime = Environment.Version.ToString(),
            OperatingSystem = Environment.OSVersion.ToString(),
            StartedUtc = DateTimeOffset.UtcNow,
        };

        foreach (SslProtocols protocol in new[] { SslProtocols.Tls12, SslProtocols.Tls13 })
        {
            var protocolRun = new ProtocolRun { Protocol = protocol.ToString() };
            run.Protocols.Add(protocolRun);

            try
            {
                if (revalidate)
                {
                    for (int trial = 1; trial <= 3; trial++)
                    {
                        protocolRun.CandidateTrials.Add(
                            await RunPublicToAdminAsync(protocol, $"revalidate-{trial}", adminAllowResume: true));
                    }
                }
                else
                {
                    protocolRun.StrictFirst = await RunStrictFirstAsync(protocol);
                    protocolRun.LegitimateClientCertificate = await RunLegitimateCertificateAsync(protocol);
                    protocolRun.NoResume = await RunNoResumeControlAsync(protocol);
                    protocolRun.DifferentTargetHost = await RunDifferentTargetHostControlAsync(protocol);
                    protocolRun.DifferentServerCertificate = await RunDifferentServerCertificateControlAsync(protocol);

                    for (int trial = 1; trial <= 3; trial++)
                    {
                        protocolRun.CandidateTrials.Add(
                            await RunPublicToAdminAsync(protocol, $"candidate-{trial}", adminAllowResume: true));
                    }
                }
            }
            catch (Exception ex)
            {
                protocolRun.FatalError = Describe(ex);
            }
        }

        run.CompletedUtc = DateTimeOffset.UtcNow;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(args[1]))!);
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Converters = { new JsonStringEnumConverter() },
        };
        string json = JsonSerializer.Serialize(run, options) + Environment.NewLine;
        await File.WriteAllTextAsync(args[1], json);
        Console.WriteLine(json);
        return 0;
    }

    private static async Task<PolicySequence> RunStrictFirstAsync(SslProtocols protocol)
    {
        using CertificateBundle server = CertificateBundle.CreateServer("strict-first.r73.test");
        using CertificateBundle expectedClient = CertificateBundle.CreateClient("R73 Expected Client");
        var serverContext = SslStreamCertificateContext.Create(server.Certificate, null, offline: true);
        var probe = new ValidationProbe(expectedClient.Certificate);
        string host = $"strict-first-{Guid.NewGuid():N}.r73.test";

        ConnectionResult admin = await RunConnectionAsync(
            label: "strict-first",
            serverOptions: CreateServerOptions(serverContext, protocol, requireClientCertificate: true, allowResume: true, probe),
            clientOptions: CreateClientOptions(host, protocol, allowResume: true, clientContext: null));

        return new PolicySequence
        {
            Name = "strict-first",
            TargetHostPublic = null,
            TargetHostAdmin = host,
            PrimeResumeObserved = false,
            Admin = admin,
        };
    }

    private static async Task<PolicySequence> RunLegitimateCertificateAsync(SslProtocols protocol)
    {
        using CertificateBundle server = CertificateBundle.CreateServer("legitimate.r73.test");
        using CertificateBundle expectedClient = CertificateBundle.CreateClient("R73 Legitimate Client");
        var serverContext = SslStreamCertificateContext.Create(server.Certificate, null, offline: true);
        var clientContext = SslStreamCertificateContext.Create(expectedClient.Certificate, null, offline: true);
        var probe = new ValidationProbe(expectedClient.Certificate);
        string host = $"legitimate-{Guid.NewGuid():N}.r73.test";

        ConnectionResult admin = await RunConnectionAsync(
            label: "legitimate-client-certificate",
            serverOptions: CreateServerOptions(serverContext, protocol, requireClientCertificate: true, allowResume: true, probe),
            clientOptions: CreateClientOptions(host, protocol, allowResume: true, clientContext));

        return new PolicySequence
        {
            Name = "legitimate-client-certificate",
            TargetHostAdmin = host,
            Admin = admin,
        };
    }

    private static async Task<PolicySequence> RunPublicToAdminAsync(
        SslProtocols protocol,
        string name,
        bool adminAllowResume)
    {
        using CertificateBundle server = CertificateBundle.CreateServer($"{name}.r73.test");
        using CertificateBundle expectedClient = CertificateBundle.CreateClient($"R73 Expected {name}");
        var serverContext = SslStreamCertificateContext.Create(server.Certificate, null, offline: true);
        string host = $"{name}-{Guid.NewGuid():N}.r73.test";

        PrimeResult prime = await PrimeAnonymousSessionAsync(protocol, host, serverContext, name);
        var probe = new ValidationProbe(expectedClient.Certificate);
        ConnectionResult admin = await RunConnectionAsync(
            label: $"{name}-admin",
            serverOptions: CreateServerOptions(serverContext, protocol, requireClientCertificate: true, allowResume: adminAllowResume, probe),
            clientOptions: CreateClientOptions(host, protocol, allowResume: true, clientContext: null));

        return new PolicySequence
        {
            Name = name,
            TargetHostPublic = host,
            TargetHostAdmin = host,
            PrimeResumeObserved = prime.ResumeObserved,
            PublicConnections = prime.Connections,
            Admin = admin,
        };
    }

    private static async Task<PolicySequence> RunNoResumeControlAsync(SslProtocols protocol)
    {
        using CertificateBundle server = CertificateBundle.CreateServer("no-resume.r73.test");
        using CertificateBundle expectedClient = CertificateBundle.CreateClient("R73 Expected No Resume");
        var serverContext = SslStreamCertificateContext.Create(server.Certificate, null, offline: true);
        string host = $"no-resume-{Guid.NewGuid():N}.r73.test";

        PrimeResult prime = await PrimeAnonymousSessionAsync(protocol, host, serverContext, "no-resume");
        var probe = new ValidationProbe(expectedClient.Certificate);
        ConnectionResult admin = await RunConnectionAsync(
            label: "no-resume-admin",
            serverOptions: CreateServerOptions(serverContext, protocol, requireClientCertificate: true, allowResume: false, probe),
            clientOptions: CreateClientOptions(host, protocol, allowResume: true, clientContext: null));

        return new PolicySequence
        {
            Name = "no-resume",
            TargetHostPublic = host,
            TargetHostAdmin = host,
            PrimeResumeObserved = prime.ResumeObserved,
            PublicConnections = prime.Connections,
            Admin = admin,
        };
    }

    private static async Task<PolicySequence> RunDifferentTargetHostControlAsync(SslProtocols protocol)
    {
        using CertificateBundle server = CertificateBundle.CreateServer("different-host.r73.test");
        using CertificateBundle expectedClient = CertificateBundle.CreateClient("R73 Expected Different Host");
        var serverContext = SslStreamCertificateContext.Create(server.Certificate, null, offline: true);
        string publicHost = $"public-{Guid.NewGuid():N}.r73.test";
        string adminHost = $"admin-{Guid.NewGuid():N}.r73.test";

        PrimeResult prime = await PrimeAnonymousSessionAsync(protocol, publicHost, serverContext, "different-host");
        var probe = new ValidationProbe(expectedClient.Certificate);
        ConnectionResult admin = await RunConnectionAsync(
            label: "different-target-host-admin",
            serverOptions: CreateServerOptions(serverContext, protocol, requireClientCertificate: true, allowResume: true, probe),
            clientOptions: CreateClientOptions(adminHost, protocol, allowResume: true, clientContext: null));

        return new PolicySequence
        {
            Name = "different-target-host",
            TargetHostPublic = publicHost,
            TargetHostAdmin = adminHost,
            PrimeResumeObserved = prime.ResumeObserved,
            PublicConnections = prime.Connections,
            Admin = admin,
        };
    }

    private static async Task<PolicySequence> RunDifferentServerCertificateControlAsync(SslProtocols protocol)
    {
        using CertificateBundle publicServer = CertificateBundle.CreateServer("public-cert.r73.test");
        using CertificateBundle adminServer = CertificateBundle.CreateServer("admin-cert.r73.test");
        using CertificateBundle expectedClient = CertificateBundle.CreateClient("R73 Expected Different Cert");
        var publicContext = SslStreamCertificateContext.Create(publicServer.Certificate, null, offline: true);
        var adminContext = SslStreamCertificateContext.Create(adminServer.Certificate, null, offline: true);
        string host = $"different-cert-{Guid.NewGuid():N}.r73.test";

        PrimeResult prime = await PrimeAnonymousSessionAsync(protocol, host, publicContext, "different-cert");
        var probe = new ValidationProbe(expectedClient.Certificate);
        ConnectionResult admin = await RunConnectionAsync(
            label: "different-server-certificate-admin",
            serverOptions: CreateServerOptions(adminContext, protocol, requireClientCertificate: true, allowResume: true, probe),
            clientOptions: CreateClientOptions(host, protocol, allowResume: true, clientContext: null));

        return new PolicySequence
        {
            Name = "different-server-certificate",
            TargetHostPublic = host,
            TargetHostAdmin = host,
            PrimeResumeObserved = prime.ResumeObserved,
            PublicConnections = prime.Connections,
            Admin = admin,
        };
    }

    private static async Task<PrimeResult> PrimeAnonymousSessionAsync(
        SslProtocols protocol,
        string targetHost,
        SslStreamCertificateContext serverContext,
        string label)
    {
        var result = new PrimeResult();
        for (int round = 1; round <= 8; round++)
        {
            ConnectionResult connection = await RunConnectionAsync(
                label: $"{label}-public-{round}",
                serverOptions: CreateServerOptions(
                    serverContext,
                    protocol,
                    requireClientCertificate: false,
                    allowResume: true,
                    validationProbe: null),
                clientOptions: CreateClientOptions(targetHost, protocol, allowResume: true, clientContext: null));

            result.Connections.Add(connection);
            if (!connection.ServerAuthenticated || !connection.ClientAuthenticated || !connection.ApplicationDataSucceeded)
            {
                break;
            }

            if (connection.ServerTlsResumed == true || connection.ClientTlsResumed == true)
            {
                result.ResumeObserved = true;
                break;
            }
        }

        return result;
    }

    private static SslServerAuthenticationOptions CreateServerOptions(
        SslStreamCertificateContext certificateContext,
        SslProtocols protocol,
        bool requireClientCertificate,
        bool allowResume,
        ValidationProbe? validationProbe)
    {
        return new SslServerAuthenticationOptions
        {
            ServerCertificateContext = certificateContext,
            EnabledSslProtocols = protocol,
            ClientCertificateRequired = requireClientCertificate,
            AllowTlsResume = allowResume,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = validationProbe?.Validate,
        };
    }

    private static SslClientAuthenticationOptions CreateClientOptions(
        string targetHost,
        SslProtocols protocol,
        bool allowResume,
        SslStreamCertificateContext? clientContext)
    {
        return new SslClientAuthenticationOptions
        {
            TargetHost = targetHost,
            EnabledSslProtocols = protocol,
            AllowTlsResume = allowResume,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = static (_, _, _, _) => true,
            ClientCertificateContext = clientContext,
        };
    }

    private static async Task<ConnectionResult> RunConnectionAsync(
        string label,
        SslServerAuthenticationOptions serverOptions,
        SslClientAuthenticationOptions clientOptions)
    {
        var result = new ConnectionResult
        {
            Label = label,
            ClientCertificateSupplied = clientOptions.ClientCertificateContext is not null,
            ServerRequiresClientCertificate = serverOptions.ClientCertificateRequired,
            ServerAllowsResume = serverOptions.AllowTlsResume,
            ClientAllowsResume = clientOptions.AllowTlsResume,
        };

        ValidationProbe? probe = serverOptions.RemoteCertificateValidationCallback?.Target as ValidationProbe;
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        result.Port = port;

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        TcpClient? clientTcp = null;
        TcpClient? serverTcp = null;
        SslStream? clientSsl = null;
        SslStream? serverSsl = null;

        try
        {
            Task<TcpClient> acceptTask = listener.AcceptTcpClientAsync(timeout.Token).AsTask();
            clientTcp = new TcpClient(AddressFamily.InterNetwork);
            await clientTcp.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
            serverTcp = await acceptTask.WaitAsync(timeout.Token);
            listener.Stop();

            clientTcp.NoDelay = true;
            serverTcp.NoDelay = true;
            clientSsl = new SslStream(clientTcp.GetStream(), leaveInnerStreamOpen: false);
            serverSsl = new SslStream(serverTcp.GetStream(), leaveInnerStreamOpen: false);

            Task<Exception?> serverAuthentication = CaptureAsync(
                () => serverSsl.AuthenticateAsServerAsync(serverOptions, timeout.Token));
            Task<Exception?> clientAuthentication = CaptureAsync(
                () => clientSsl.AuthenticateAsClientAsync(clientOptions, timeout.Token));

            await Task.WhenAll(serverAuthentication, clientAuthentication).WaitAsync(timeout.Token);
            Exception? serverError = await serverAuthentication;
            Exception? clientError = await clientAuthentication;

            result.ServerException = serverError is null ? null : Describe(serverError);
            result.ClientException = clientError is null ? null : Describe(clientError);
            result.ServerAuthenticated = serverError is null && serverSsl.IsAuthenticated;
            result.ClientAuthenticated = clientError is null && clientSsl.IsAuthenticated;
            result.ServerTlsResumed = TryGetTlsResumed(serverSsl);
            result.ClientTlsResumed = TryGetTlsResumed(clientSsl);
            result.NegotiatedServerProtocol = serverSsl.IsAuthenticated ? serverSsl.SslProtocol.ToString() : null;
            result.NegotiatedClientProtocol = clientSsl.IsAuthenticated ? clientSsl.SslProtocol.ToString() : null;

            if (result.ServerAuthenticated)
            {
                X509Certificate? peer = serverSsl.RemoteCertificate;
                result.ServerRemoteCertificatePresent = peer is not null;
                result.ServerRemoteCertificateThumbprint = peer?.GetCertHashString();
            }

            if (result.ServerAuthenticated && result.ClientAuthenticated)
            {
                byte[] request = Encoding.ASCII.GetBytes("R73_PROTECTED_REQUEST");
                byte[] response = Encoding.ASCII.GetBytes("R73_PROTECTED_RESPONSE");
                await clientSsl.WriteAsync(request, timeout.Token);
                await clientSsl.FlushAsync(timeout.Token);

                byte[] serverBuffer = new byte[request.Length];
                await serverSsl.ReadExactlyAsync(serverBuffer, timeout.Token);
                result.ServerReceivedProtectedRequest = serverBuffer.AsSpan().SequenceEqual(request);

                await serverSsl.WriteAsync(response, timeout.Token);
                await serverSsl.FlushAsync(timeout.Token);
                byte[] clientBuffer = new byte[response.Length];
                await clientSsl.ReadExactlyAsync(clientBuffer, timeout.Token);
                result.ClientReceivedProtectedResponse = clientBuffer.AsSpan().SequenceEqual(response);
                result.ApplicationDataSucceeded =
                    result.ServerReceivedProtectedRequest && result.ClientReceivedProtectedResponse;
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
            clientTcp?.Dispose();
            serverTcp?.Dispose();
        }

        return result;
    }

    private static async Task<Exception?> CaptureAsync(Func<Task> operation)
    {
        try
        {
            await operation();
            return null;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    private static bool? TryGetTlsResumed(SslStream stream)
    {
        try
        {
            object? connectionInfo = ConnectionInfoField?.GetValue(stream);
            PropertyInfo? resumedProperty = connectionInfo?.GetType().GetProperty(
                "TlsResumed",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            return resumedProperty?.GetValue(connectionInfo) as bool?;
        }
        catch
        {
            return null;
        }
    }

    private static string Describe(Exception ex)
    {
        Exception current = ex;
        while (current is AggregateException aggregate && aggregate.InnerExceptions.Count == 1)
        {
            current = aggregate.InnerExceptions[0];
        }
        return $"{current.GetType().FullName}: {current.Message}";
    }

    private sealed class ValidationProbe
    {
        private readonly string _expectedThumbprint;
        private int _count;
        private int _sawCertificate;
        private int _sawMissingCertificate;

        public ValidationProbe(X509Certificate2 expectedCertificate)
        {
            _expectedThumbprint = expectedCertificate.GetCertHashString();
        }

        public int Count => Volatile.Read(ref _count);
        public bool SawCertificate => Volatile.Read(ref _sawCertificate) != 0;
        public bool SawMissingCertificate => Volatile.Read(ref _sawMissingCertificate) != 0;

        public bool Validate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
        {
            Interlocked.Increment(ref _count);
            if (certificate is null)
            {
                Volatile.Write(ref _sawMissingCertificate, 1);
                return false;
            }

            Volatile.Write(ref _sawCertificate, 1);
            return string.Equals(
                certificate.GetCertHashString(),
                _expectedThumbprint,
                StringComparison.OrdinalIgnoreCase);
        }
    }

    private sealed class CertificateBundle : IDisposable
    {
        private readonly RSA _key;
        public X509Certificate2 Certificate { get; }

        private CertificateBundle(RSA key, X509Certificate2 certificate)
        {
            _key = key;
            Certificate = certificate;
        }

        public static CertificateBundle CreateServer(string dnsName)
        {
            RSA key = RSA.Create(2048);
            var request = new CertificateRequest(
                $"CN={dnsName}",
                key,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                true));
            var eku = new OidCollection { new("1.3.6.1.5.5.7.3.1") };
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(dnsName);
            request.CertificateExtensions.Add(san.Build());
            X509Certificate2 certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddDays(2));
            return new CertificateBundle(key, certificate);
        }

        public static CertificateBundle CreateClient(string commonName)
        {
            RSA key = RSA.Create(2048);
            var request = new CertificateRequest(
                $"CN={commonName}",
                key,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            var eku = new OidCollection { new("1.3.6.1.5.5.7.3.2") };
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
            X509Certificate2 certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddDays(2));
            return new CertificateBundle(key, certificate);
        }

        public void Dispose()
        {
            Certificate.Dispose();
            _key.Dispose();
        }
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
    public List<ProtocolRun> Protocols { get; } = [];
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
}
