internal static partial class Program
{
    private static async Task<int> OrchestrateAsync(string[] args)
    {
        if (args.Length != 2)
        {
            throw new ArgumentException("orchestrate requires an evidence directory.");
        }

        string evidenceRoot = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(evidenceRoot);
        string assemblyPath = Assembly.GetExecutingAssembly().Location;
        string dotnetPath = Environment.ProcessPath
            ?? throw new InvalidOperationException("Environment.ProcessPath is unavailable.");

        var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        var top = new Dictionary<string, object?>
        {
            ["schema"] = "r70-workload-msi-log-junction/v1",
            ["startedAtUtc"] = DateTimeOffset.UtcNow,
            ["dotnetPath"] = dotnetPath,
            ["assemblyPath"] = assemblyPath,
            ["orchestratorSid"] = identity.User?.Value,
            ["orchestratorName"] = identity.Name,
            ["orchestratorIsAdministrator"] = principal.IsInRole(WindowsBuiltInRole.Administrator),
            ["orchestratorIntegrityRid"] = GetCurrentIntegrityRid(),
        };

        if (!(bool)top["orchestratorIsAdministrator"]!)
        {
            throw new InvalidOperationException("The workflow process is not elevated; the real workload server cannot start.");
        }

        var trials = new List<Dictionary<string, object?>>();
        for (int trialNumber = 1; trialNumber <= 3; trialNumber++)
        {
            trials.Add(await RunTrialAsync(trialNumber, evidenceRoot, dotnetPath, assemblyPath));
        }

        bool allPositive = trials.All(t => GetBool(t, "runtimePositive"));
        bool allControlsPassed = trials.All(t => GetBool(t, "controlsPassed"));
        bool allRestricted = trials.All(t => GetBool(t, "restrictedClientConfirmed"));

        top["completedAtUtc"] = DateTimeOffset.UtcNow;
        top["trials"] = trials;
        top["verdict"] = new Dictionary<string, object?>
        {
            ["allThreeRuntimePositive"] = allPositive,
            ["allControlsPassed"] = allControlsPassed,
            ["allRestrictedClientsConfirmed"] = allRestricted,
            ["status"] = allPositive && allControlsPassed && allRestricted
                ? "RUNTIME_POSITIVE_REVIEW_REQUIRED"
                : "RUNTIME_NEGATIVE_OR_INVALID",
        };

        await File.WriteAllTextAsync(
            Path.Combine(evidenceRoot, "result.json"),
            JsonSerializer.Serialize(top, s_json) + Environment.NewLine);

        Console.WriteLine(JsonSerializer.Serialize(top["verdict"], s_json));
        return allPositive && allControlsPassed && allRestricted ? 0 : 3;
    }

    private static async Task<Dictionary<string, object?>> RunTrialAsync(
        int trialNumber,
        string evidenceRoot,
        string dotnetPath,
        string assemblyPath)
    {
        string trialId = $"trial-{trialNumber}-{Guid.NewGuid():N}";
        string trialDir = Path.Combine(evidenceRoot, trialId);
        Directory.CreateDirectory(trialDir);

        string tempRoot = Path.Combine(Path.GetTempPath(), $"r70-client-{Guid.NewGuid():N}");
        string targetDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            $"r70-target-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);
        CreateAdminOwnedDirectory(targetDir);

        string canaryName = $"protected-{Guid.NewGuid():N}.log";
        string targetCanary = Path.Combine(targetDir, canaryName);
        string originalCanary = $"R70_PROTECTED_CANARY_{Guid.NewGuid():N}";
        File.WriteAllText(targetCanary, originalCanary, new UTF8Encoding(false));
        string originalHash = Sha256File(targetCanary);
        long originalLength = new FileInfo(targetCanary).Length;

        string pidFile = Path.Combine(trialDir, "server.pid");
        string serverStdout = Path.Combine(trialDir, "server.stdout.txt");
        string serverStderr = Path.Combine(trialDir, "server.stderr.txt");
        string clientResult = Path.Combine(trialDir, "client-result.json");

        Process parent = StartDotnet(
            dotnetPath,
            assemblyPath,
            ["parent", tempRoot, pidFile, serverStdout, serverStderr],
            redirect: true);

        int serverPid = await WaitForServerPidAsync(pidFile, parent, TimeSpan.FromSeconds(30));

        Process restrictedClient = StartRestrictedProcess(
            dotnetPath,
            assemblyPath,
            ["client", serverPid.ToString(), tempRoot, targetDir, targetCanary, clientResult]);

        using var clientTimeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        await restrictedClient.WaitForExitAsync(clientTimeout.Token);
        int clientExitCode = restrictedClient.ExitCode;

        if (!parent.HasExited)
        {
            try
            {
                using var parentTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
                await parent.WaitForExitAsync(parentTimeout.Token);
            }
            catch (OperationCanceledException)
            {
                parent.Kill(entireProcessTree: true);
                await parent.WaitForExitAsync();
            }
        }

        Dictionary<string, object?>? client = null;
        if (File.Exists(clientResult))
        {
            using JsonDocument doc = JsonDocument.Parse(await File.ReadAllTextAsync(clientResult));
            client = JsonToDictionary(doc.RootElement);
        }

        string afterHash = File.Exists(targetCanary) ? Sha256File(targetCanary) : "MISSING";
        long afterLength = File.Exists(targetCanary) ? new FileInfo(targetCanary).Length : -1;
        string junctionPath = Path.Combine(tempRoot, "pivot");

        await WriteCommandOutputAsync("whoami.exe", "/all", Path.Combine(trialDir, "whoami-orchestrator.txt"));
        await WriteCommandOutputAsync("icacls.exe", QuoteCmd(targetDir), Path.Combine(trialDir, "target-acl.txt"));
        if (Directory.Exists(junctionPath))
        {
            await WriteCommandOutputAsync("fsutil.exe", $"reparsepoint query {QuoteCmd(junctionPath)}", Path.Combine(trialDir, "junction-reparse.txt"));
        }

        bool runtimePositive = client is not null && GetBool(client, "junctionChangedProtectedCanary");
        bool controlsPassed = client is not null && GetBool(client, "controlsPassed");
        bool restrictedConfirmed = client is not null && GetBool(client, "restrictedClientConfirmed");

        var result = new Dictionary<string, object?>
        {
            ["trialNumber"] = trialNumber,
            ["trialId"] = trialId,
            ["serverPid"] = serverPid,
            ["parentExitCode"] = parent.ExitCode,
            ["clientExitCode"] = clientExitCode,
            ["tempRoot"] = tempRoot,
            ["targetDir"] = targetDir,
            ["targetCanary"] = targetCanary,
            ["originalCanaryLength"] = originalLength,
            ["originalCanarySha256"] = originalHash,
            ["finalCanaryLength"] = afterLength,
            ["finalCanarySha256"] = afterHash,
            ["client"] = client,
            ["runtimePositive"] = runtimePositive,
            ["controlsPassed"] = controlsPassed,
            ["restrictedClientConfirmed"] = restrictedConfirmed,
        };

        await File.WriteAllTextAsync(
            Path.Combine(trialDir, "trial-summary.json"),
            JsonSerializer.Serialize(result, s_json) + Environment.NewLine);

        return result;
    }
}
