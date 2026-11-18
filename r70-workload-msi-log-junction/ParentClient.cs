internal static partial class Program
{
    private static async Task<int> ParentAsync(string[] args)
    {
        if (args.Length != 5)
        {
            throw new ArgumentException("parent requires clientTemp, pidFile, stdoutFile, stderrFile.");
        }

        string clientTemp = Path.GetFullPath(args[1]);
        string pidFile = Path.GetFullPath(args[2]);
        string stdoutFile = Path.GetFullPath(args[3]);
        string stderrFile = Path.GetFullPath(args[4]);

        string dotnetPath = Environment.ProcessPath
            ?? throw new InvalidOperationException("Environment.ProcessPath is unavailable.");
        var psi = new ProcessStartInfo(dotnetPath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("workload");
        psi.ArgumentList.Add("elevate");
        psi.ArgumentList.Add("--client-temp");
        psi.ArgumentList.Add(clientTemp);

        using Process server = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start the workload elevation server.");
        Directory.CreateDirectory(Path.GetDirectoryName(pidFile)!);
        await File.WriteAllTextAsync(pidFile, server.Id.ToString());

        await using FileStream stdout = File.Create(stdoutFile);
        await using FileStream stderr = File.Create(stderrFile);
        Task outCopy = server.StandardOutput.BaseStream.CopyToAsync(stdout);
        Task errCopy = server.StandardError.BaseStream.CopyToAsync(stderr);
        await server.WaitForExitAsync();
        await Task.WhenAll(outCopy, errCopy);
        return server.ExitCode;
    }

    private static async Task<int> ClientAsync(string[] args)
    {
        if (args.Length != 6)
        {
            throw new ArgumentException("client requires serverPid, tempRoot, targetDir, targetCanary, resultFile.");
        }

        int serverPid = int.Parse(args[1]);
        string tempRoot = Path.GetFullPath(args[2]);
        string targetDir = Path.GetFullPath(args[3]);
        string targetCanary = Path.GetFullPath(args[4]);
        string resultFile = Path.GetFullPath(args[5]);

        var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        bool isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
        int integrityRid = GetCurrentIntegrityRid();

        string originalHash = Sha256File(targetCanary);
        long originalLength = new FileInfo(targetCanary).Length;

        bool directWriteDenied = false;
        string? directWriteError = null;
        try
        {
            using FileStream direct = new(targetCanary, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
            direct.SetLength(0);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            directWriteDenied = true;
            directWriteError = $"{ex.GetType().Name}: {ex.Message}";
        }

        if (!directWriteDenied)
        {
            throw new InvalidOperationException("Restricted client unexpectedly modified the protected canary directly.");
        }

        string junctionPath = Path.Combine(tempRoot, "pivot");
        if (Directory.Exists(junctionPath))
        {
            Directory.Delete(junctionPath);
        }

        Process junction = new()
        {
            StartInfo = new ProcessStartInfo("cmd.exe", $"/d /c mklink /J {QuoteCmd(junctionPath)} {QuoteCmd(targetDir)}")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            }
        };
        junction.Start();
        string junctionOut = await junction.StandardOutput.ReadToEndAsync();
        string junctionErr = await junction.StandardError.ReadToEndAsync();
        await junction.WaitForExitAsync();
        if (junction.ExitCode != 0 || !Directory.Exists(junctionPath))
        {
            throw new InvalidOperationException($"Restricted client failed to create junction. exit={junction.ExitCode}; out={junctionOut}; err={junctionErr}");
        }

        bool isReparsePoint = (File.GetAttributes(junctionPath) & FileAttributes.ReparsePoint) != 0;
        if (!isReparsePoint)
        {
            throw new InvalidOperationException("Created pivot is not a reparse point.");
        }

        bool junctionDirectWriteDenied = false;
        string junctionCanary = Path.Combine(junctionPath, Path.GetFileName(targetCanary));
        try
        {
            using FileStream direct = new(junctionCanary, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
            direct.SetLength(0);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            junctionDirectWriteDenied = true;
        }

        if (!junctionDirectWriteDenied)
        {
            throw new InvalidOperationException("Restricted client unexpectedly modified the protected canary through the junction directly.");
        }

        string dispatchName = CreatePipeName(serverPid);
        string logName = CreatePipeName(serverPid, "log");
        using var dispatch = new NamedPipeClientStream(".", dispatchName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var logPipe = new NamedPipeClientStream(".", logName, PipeDirection.InOut, PipeOptions.Asynchronous);

        using var connectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await Task.WhenAll(
            dispatch.ConnectAsync(connectTimeout.Token),
            logPipe.ConnectAsync(connectTimeout.Token));
        dispatch.ReadMode = PipeTransmissionMode.Message;
        logPipe.ReadMode = PipeTransmissionMode.Message;

        var logMessages = new List<string>();
        using var logCancellation = new CancellationTokenSource();
        Task logTask = DrainLogPipeAsync(logPipe, logMessages, logCancellation.Token);

        string directOutsideBefore = Sha256File(targetCanary);
        string directOutsideResponse = await SendRepairAsync(dispatch, targetCanary);
        string directOutsideAfter = Sha256File(targetCanary);
        bool directOutsideBlocked = directOutsideBefore == directOutsideAfter;

        string normalLog = Path.Combine(tempRoot, $"normal-{Guid.NewGuid():N}.log");
        string normalResponse = await SendRepairAsync(dispatch, normalLog);
        bool normalInsideCreated = File.Exists(normalLog);
        bool normalLeftCanary = Sha256File(targetCanary) == directOutsideAfter;

        string junctionBeforeHash = Sha256File(targetCanary);
        long junctionBeforeLength = new FileInfo(targetCanary).Length;
        string junctionResponse = await SendRepairAsync(dispatch, junctionCanary);
        string junctionAfterHash = Sha256File(targetCanary);
        long junctionAfterLength = new FileInfo(targetCanary).Length;
        bool junctionChanged = junctionAfterHash != junctionBeforeHash || junctionAfterLength != junctionBeforeLength;

        string shutdownResponse = await SendRequestAsync(dispatch, new Dictionary<string, object?>
        {
            ["RequestType"] = 0,
        });

        logCancellation.Cancel();
        try
        {
            await logTask;
        }
        catch (OperationCanceledException)
        {
        }
        catch (IOException)
        {
        }

        bool restrictedConfirmed = !isAdmin && integrityRid <= 8192 && directWriteDenied && junctionDirectWriteDenied;
        bool controlsPassed = directOutsideBlocked && normalInsideCreated && normalLeftCanary;

        var result = new Dictionary<string, object?>
        {
            ["clientSid"] = identity.User?.Value,
            ["clientName"] = identity.Name,
            ["clientIsAdministrator"] = isAdmin,
            ["clientIntegrityRid"] = integrityRid,
            ["restrictedClientConfirmed"] = restrictedConfirmed,
            ["directWriteDenied"] = directWriteDenied,
            ["directWriteError"] = directWriteError,
            ["junctionDirectWriteDenied"] = junctionDirectWriteDenied,
            ["junctionPath"] = junctionPath,
            ["junctionIsReparsePoint"] = isReparsePoint,
            ["junctionCommandStdout"] = junctionOut,
            ["junctionCommandStderr"] = junctionErr,
            ["serverPid"] = serverPid,
            ["dispatchPipeName"] = dispatchName,
            ["logPipeName"] = logName,
            ["originalCanarySha256"] = originalHash,
            ["originalCanaryLength"] = originalLength,
            ["directOutsideControlResponse"] = directOutsideResponse,
            ["directOutsideBlocked"] = directOutsideBlocked,
            ["normalInsideControlResponse"] = normalResponse,
            ["normalInsideCreated"] = normalInsideCreated,
            ["normalLeftCanaryUnchanged"] = normalLeftCanary,
            ["junctionResponse"] = junctionResponse,
            ["junctionBeforeSha256"] = junctionBeforeHash,
            ["junctionBeforeLength"] = junctionBeforeLength,
            ["junctionAfterSha256"] = junctionAfterHash,
            ["junctionAfterLength"] = junctionAfterLength,
            ["junctionChangedProtectedCanary"] = junctionChanged,
            ["controlsPassed"] = controlsPassed,
            ["shutdownResponse"] = shutdownResponse,
            ["serverLogMessages"] = logMessages,
        };

        Directory.CreateDirectory(Path.GetDirectoryName(resultFile)!);
        await File.WriteAllTextAsync(resultFile, JsonSerializer.Serialize(result, s_json) + Environment.NewLine);
        Console.WriteLine(JsonSerializer.Serialize(result, s_json));
        return restrictedConfirmed && controlsPassed && junctionChanged ? 0 : 4;
    }

    private static Process StartDotnet(
        string dotnetPath,
        string assemblyPath,
        IReadOnlyList<string> arguments,
        bool redirect)
    {
        var psi = new ProcessStartInfo(dotnetPath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = redirect,
            RedirectStandardError = redirect,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add(assemblyPath);
        foreach (string argument in arguments)
        {
            psi.ArgumentList.Add(argument);
        }

        Process process = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start dotnet child process.");

        if (redirect)
        {
            _ = Task.Run(async () =>
            {
                string output = await process.StandardOutput.ReadToEndAsync();
                if (output.Length > 0)
                {
                    Console.Write(output);
                }
            });
            _ = Task.Run(async () =>
            {
                string output = await process.StandardError.ReadToEndAsync();
                if (output.Length > 0)
                {
                    Console.Error.Write(output);
                }
            });
        }

        return process;
    }

    private static async Task<int> WaitForServerPidAsync(string pidFile, Process parent, TimeSpan timeout)
    {
        Stopwatch sw = Stopwatch.StartNew();
        while (sw.Elapsed < timeout)
        {
            if (File.Exists(pidFile))
            {
                string text = await File.ReadAllTextAsync(pidFile);
                if (int.TryParse(text.Trim(), out int pid))
                {
                    return pid;
                }
            }

            if (parent.HasExited)
            {
                throw new InvalidOperationException($"Parent exited before publishing server PID. exit={parent.ExitCode}");
            }

            await Task.Delay(100);
        }

        throw new TimeoutException("Timed out waiting for workload server PID.");
    }
}
