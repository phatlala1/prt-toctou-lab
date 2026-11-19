#!/usr/bin/env python3
from pathlib import Path

program = Path("r71-razor-server-cross-integrity/Program.cs")
source = program.read_text(encoding="utf-8")


def replace_once(old: str, new: str, name: str) -> None:
    global source
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{name} block count was {count}, expected exactly one")
    source = source.replace(old, new, 1)

old_client_setup = '''        string workDir = Path.GetFullPath(args[9]);
        Directory.CreateDirectory(workDir);

        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
'''
new_client_setup = '''        string workDir = Path.GetFullPath(args[9]);
        string progressFile = Path.Combine(Path.GetDirectoryName(resultFile)!, "client-progress.json");
        Directory.CreateDirectory(workDir);

        var stageHistory = new List<Dictionary<string, object?>>();
        async Task WriteClientProgressAsync(string stage, object? details = null)
        {
            stageHistory.Add(new Dictionary<string, object?>
            {
                ["stage"] = stage,
                ["recordedAtUtc"] = DateTimeOffset.UtcNow,
                ["details"] = details,
            });
            var progress = new Dictionary<string, object?>
            {
                ["marker"] = "R71_STAGE_INSTRUMENTATION_V2",
                ["clientPid"] = Environment.ProcessId,
                ["currentStage"] = stage,
                ["history"] = stageHistory,
            };
            await File.WriteAllTextAsync(
                progressFile,
                JsonSerializer.Serialize(progress, JsonOptions) + Environment.NewLine);
        }

        await WriteClientProgressAsync("client-entry", new { argsLength = args.Length, workDir });

        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
'''
replace_once(old_client_setup, new_client_setup, "client setup")

old_identity = '''        int integrity = GetProcessIntegrity(Process.GetCurrentProcess());
        string before = Hash(canary);

        bool directDenied = false;
'''
new_identity = '''        int integrity = GetProcessIntegrity(Process.GetCurrentProcess());
        string before = Hash(canary);
        await WriteClientProgressAsync("identity-captured", new
        {
            sid = identity.User?.Value,
            identity.Name,
            admin,
            integrity,
            canarySha256 = before,
        });

        bool directDenied = false;
'''
replace_once(old_identity, new_identity, "identity progress")

old_direct_end = '''        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            directDenied = true;
            directError = $"{ex.GetType().Name}:{ex.Message}";
        }

        string mediumLog = Path.Combine(workDir, "medium-extension.log");
'''
new_direct_end = '''        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            directDenied = true;
            directError = $"{ex.GetType().Name}:{ex.Message}";
        }
        await WriteClientProgressAsync("direct-write-control-finished", new { directDenied, directError });

        string mediumLog = Path.Combine(workDir, "medium-extension.log");
'''
replace_once(old_direct_end, new_direct_end, "direct control progress")

old_stage_sequence = '''        string mediumLog = Path.Combine(workDir, "medium-extension.log");
        CommandResult inProcess = await RunTaskAsync(false, true, "unused", "inproc", mediumLog);
        string afterInProcess = Hash(canary);
        string mediumText = File.Exists(mediumLog) ? await File.ReadAllTextAsync(mediumLog) : string.Empty;
        bool mediumExecuted = mediumText.Contains($"|{Environment.ProcessId}|") || mediumText.Contains("|8192|");

        CommandResult noExtension = await RunTaskAsync(true, false, pipe, "server-no-extension", Path.Combine(workDir, "client-no-extension.log"));
        string afterNoExtension = Hash(canary);

        CommandResult attack = await RunTaskAsync(true, true, pipe, "server-extension", Path.Combine(workDir, "client-attack.log"));
        string afterAttack = Hash(canary);

        bool restricted = !admin && integrity <= 8192 && directDenied;
'''
new_stage_sequence = '''        string mediumLog = Path.Combine(workDir, "medium-extension.log");
        CommandResult inProcess = await RunTaskAsync(false, true, "unused", "inproc", mediumLog);
        string afterInProcess = Hash(canary);
        string mediumText = File.Exists(mediumLog) ? await File.ReadAllTextAsync(mediumLog) : string.Empty;
        bool mediumExecuted = mediumText.Contains($"|{Environment.ProcessId}|") || mediumText.Contains("|8192|");
        await WriteClientProgressAsync("inproc-finished", new
        {
            inProcess.ExitCode,
            timedOut = IsTimedOut(inProcess),
            mediumExecuted,
            canaryUnchanged = before == afterInProcess,
        });

        CommandResult noExtension = await RunTaskAsync(true, false, pipe, "server-no-extension", Path.Combine(workDir, "client-no-extension.log"));
        string afterNoExtension = Hash(canary);
        await WriteClientProgressAsync("server-no-extension-finished", new
        {
            noExtension.ExitCode,
            timedOut = IsTimedOut(noExtension),
            canaryUnchanged = afterInProcess == afterNoExtension,
        });

        CommandResult attack = await RunTaskAsync(true, true, pipe, "server-extension", Path.Combine(workDir, "client-attack.log"));
        string afterAttack = Hash(canary);
        await WriteClientProgressAsync("server-extension-finished", new
        {
            attack.ExitCode,
            timedOut = IsTimedOut(attack),
            canaryChanged = afterAttack != afterNoExtension,
        });

        bool restricted = !admin && integrity <= 8192 && directDenied;
        bool anyStageTimedOut = IsTimedOut(inProcess) || IsTimedOut(noExtension) || IsTimedOut(attack);
'''
replace_once(old_stage_sequence, new_stage_sequence, "stage sequence")

old_result_end = '''            ["attackStderr"] = attack.Stderr,
            ["attackChangedCanary"] = afterAttack != afterNoExtension,
        };
        Directory.CreateDirectory(Path.GetDirectoryName(resultFile)!);
        await File.WriteAllTextAsync(resultFile, JsonSerializer.Serialize(result, JsonOptions) + Environment.NewLine);
        return restricted ? 0 : 4;

        async Task<CommandResult> RunTaskAsync(bool useServer, bool includeExtension, string pipeName, string label, string executionLog)
'''
new_result_end = '''            ["attackStderr"] = attack.Stderr,
            ["attackChangedCanary"] = afterAttack != afterNoExtension,
            ["inProcessTimedOut"] = IsTimedOut(inProcess),
            ["noExtensionServerTimedOut"] = IsTimedOut(noExtension),
            ["attackTimedOut"] = IsTimedOut(attack),
            ["anyStageTimedOut"] = anyStageTimedOut,
            ["stageHistory"] = stageHistory,
        };
        Directory.CreateDirectory(Path.GetDirectoryName(resultFile)!);
        await File.WriteAllTextAsync(resultFile, JsonSerializer.Serialize(result, JsonOptions) + Environment.NewLine);
        await WriteClientProgressAsync("client-result-written", new { restricted, anyStageTimedOut });
        return restricted && !anyStageTimedOut ? 0 : 4;

        static bool IsTimedOut(CommandResult result) => result.Stderr.Contains("R71_STAGE_TIMEOUT", StringComparison.Ordinal);

        async Task<CommandResult> RunTaskAsync(bool useServer, bool includeExtension, string pipeName, string label, string executionLog)
'''
replace_once(old_result_end, new_result_end, "client result timeout fields")

program.write_text(source, encoding="utf-8")
print("R71_CLIENT_INSTRUMENTATION_APPLIED")
