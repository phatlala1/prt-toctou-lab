using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

static class Program
{
    const string SwitchName = "System.Net.Security.RevalidateCertificateOnTlsResume";
    static readonly BindingFlags BF = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
    static readonly FieldInfo? CIF = typeof(SslStream).GetField("_connectionInfo", BF);
    static readonly PropertyInfo? TRP = typeof(SslStream).Assembly
        .GetType("System.Net.Security.SslConnectionInfo")?.GetProperty("TlsResumed", BF);

    public static async Task<int> Main(string[] a)
    {
        bool revalidate = a.Length > 0 && a[0] == "revalidate";
        string output = a.Length > 1 ? a[1] : $"{(revalidate ? "revalidate" : "default")}.json";
        AppContext.SetSwitch(SwitchName, revalidate);
        var protocols = new List<object>();
        bool invalid = CIF is null || TRP is null;
        bool all = !invalid, anySupported = false;

        foreach (SslProtocols p in new[] { SslProtocols.Tls12, SslProtocols.Tls13 })
        {
            var trials = new List<object>();
            bool supported = true;
            for (int i = 1; i <= 3 && !invalid; i++)
            {
                Trial t;
                try { t = await RunTrial(p, i, revalidate); }
                catch (AuthenticationException e) when (e.ToString().Contains("protocol", StringComparison.OrdinalIgnoreCase))
                { supported = false; break; }
                catch (Exception e)
                {
                    invalid = true;
                    trials.Add(new { trial = i, fatal = Desc(e) });
                    break;
                }
                trials.Add(t);
                all &= revalidate ? t.RevalidateControl : t.Positive && t.Controls;
                invalid |= t.Invalid is not null;
            }
            anySupported |= supported && trials.Count == 3;
            protocols.Add(new { protocol = p.ToString(), supported, trials });
        }

        invalid |= !anySupported;
        string status = invalid ? "INVALID_RUNTIME" : all
            ? (revalidate ? "REVALIDATION_CONTROL_PASSED" : "RUNTIME_POSITIVE_REVIEW_REQUIRED")
            : "RUNTIME_NEGATIVE_CLOSED";
        var result = new
        {
            schema = "r73-resumed-callback-policy/v1",
            mode = revalidate ? "revalidate" : "default",
            status,
            runtime = Environment.Version.ToString(),
            framework = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
            reflection = new { connectionInfoField = CIF is not null, tlsResumedProperty = TRP is not null },
            protocols
        };
        string json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
        Console.WriteLine(json);
        await File.WriteAllTextAsync(output, json + Environment.NewLine);
        return status switch { "RUNTIME_POSITIVE_REVIEW_REQUIRED" => 10, "INVALID_RUNTIME" => 2, _ => 0 };
    }

    static async Task<Trial> RunTrial(SslProtocols p, int n, bool revalidate)
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest($"CN=r73-{n}.local", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        using X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        var sopt = new SslServerAuthenticationOptions
        {
            EnabledSslProtocols = p,
            ServerCertificateContext = SslStreamCertificateContext.Create(cert, null, true),
            AllowTlsResume = true
        };
        int reject = 0, calls = 0;
        string host = $"r73-{p}-{n}-{Guid.NewGuid():N}.local";
        var copt = new SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = p,
            AllowTlsResume = true,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = (_, _, _, _) =>
            {
                Interlocked.Increment(ref calls);
                return Volatile.Read(ref reject) == 0;
            }
        };

        Conn initial = await One("initial", sopt, copt); initial.Calls = calls;
        if (!initial.Ok || initial.Calls != 1) return new(n, false, false, false, "initial handshake/control failed", initial, [], new(), new(), new());

        var probes = new List<Conn>();
        bool resumed = false;
        for (int j = 1; j <= 6; j++)
        {
            calls = 0; Volatile.Write(ref reject, 0);
            Conn c = await One($"probe-{j}", sopt, copt); c.Calls = calls; probes.Add(c);
            if (c.Ok && c.CR == true && c.SR == true) { resumed = true; break; }
        }
        if (!resumed) return new(n, false, false, false, "resumption not proved", initial, probes, new(), new(), new());

        calls = 0; Volatile.Write(ref reject, 1);
        Conn candidate = await One("strict-same-session", sopt, copt); candidate.Calls = calls;
        bool positive = !revalidate && candidate.Ok && candidate.Data && candidate.CR == true && candidate.SR == true && candidate.Calls == 0;
        bool reval = revalidate && !candidate.Ok && candidate.Calls >= 1;

        copt.AllowTlsResume = false; calls = 0;
        Conn noResume = await One("strict-no-resume", sopt, copt); noResume.Calls = calls;
        copt.AllowTlsResume = true;
        copt.TargetHost = $"different-{Guid.NewGuid():N}.local"; calls = 0;
        Conn otherHost = await One("strict-different-host", sopt, copt); otherHost.Calls = calls;
        bool controls = !noResume.Ok && noResume.Calls >= 1 && !otherHost.Ok && otherHost.Calls >= 1;
        return new(n, positive, controls, reval, null, initial, probes, candidate, noResume, otherHost);
    }

    static async Task<Conn> One(string label, SslServerAuthenticationOptions so, SslClientAuthenticationOptions co)
    {
        var r = new Conn { Label = label };
        var l = new TcpListener(IPAddress.Loopback, 0); l.Start();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        TcpClient? st = null; SslStream? cs = null; SslStream? ss = null;
        try
        {
            Task<TcpClient> accept = l.AcceptTcpClientAsync(cts.Token).AsTask();
            using var ct = new TcpClient(); await ct.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)l.LocalEndpoint).Port, cts.Token);
            st = await accept; l.Stop();
            cs = new SslStream(ct.GetStream()); ss = new SslStream(st.GetStream());
            Task<Exception?> ca = Cap(() => cs.AuthenticateAsClientAsync(co, cts.Token));
            Task<Exception?> sa = Cap(() => ss.AuthenticateAsServerAsync(so, cts.Token));
            await Task.WhenAll(ca, sa).WaitAsync(cts.Token);
            Exception? ce = await ca, se = await sa;
            r.CE = ce is null ? null : Desc(ce); r.SE = se is null ? null : Desc(se);
            r.Ok = ce is null && se is null && cs.IsAuthenticated && ss.IsAuthenticated;
            r.CR = Resume(cs); r.SR = Resume(ss);
            if (r.Ok)
            {
                byte[] x = Encoding.ASCII.GetBytes("PING"), y = new byte[4];
                await cs.WriteAsync(x, cts.Token); await ReadAll(ss, y, cts.Token);
                await ss.WriteAsync(x, cts.Token); await ReadAll(cs, y, cts.Token);
                r.Data = y.SequenceEqual(x);
                await Task.Delay(250, cts.Token);
                await Task.WhenAll(Ignore(cs.ShutdownAsync), Ignore(ss.ShutdownAsync)).WaitAsync(cts.Token);
            }
        }
        catch (Exception e) { r.HE = Desc(e); }
        finally { l.Stop(); cs?.Dispose(); ss?.Dispose(); st?.Dispose(); }
        return r;
    }

    static bool? Resume(SslStream s)
    {
        try { object? ci = CIF?.GetValue(s); object? v = ci is null ? null : TRP?.GetValue(ci); return v is bool b ? b : null; }
        catch { return null; }
    }
    static async Task ReadAll(Stream s, byte[] b, CancellationToken c) { for (int o = 0; o < b.Length;) { int n = await s.ReadAsync(b.AsMemory(o), c); if (n == 0) throw new EndOfStreamException(); o += n; } }
    static async Task<Exception?> Cap(Func<Task> f) { try { await f(); return null; } catch (Exception e) { return e; } }
    static async Task Ignore(Func<Task> f) { try { await f(); } catch { } }
    static string Desc(Exception e) => $"{e.GetType().FullName}: {e.Message}";
}

record Trial(int TrialNo, bool Positive, bool Controls, bool RevalidateControl, string? Invalid,
    Conn Initial, List<Conn> Probes, Conn Candidate, Conn NoResume, Conn DifferentHost);
class Conn
{
    public string Label { get; set; } = "";
    public bool Ok { get; set; }
    public bool Data { get; set; }
    public bool? CR { get; set; }
    public bool? SR { get; set; }
    public int Calls { get; set; }
    public string? CE { get; set; }
    public string? SE { get; set; }
    public string? HE { get; set; }
}
