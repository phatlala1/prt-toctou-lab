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

old_trial_loop = '''        var trials = new List<Dictionary<string, object?>>();
        for (int trial = 1; trial <= 3; trial++)
        {
            trials.Add(await RunTrialAsync(trial, evidenceRoot, dotnetPath, rzcPath, tasksPath, extensionPath, invokeProject));
        }
'''
new_trial_loop = '''        var trials = new List<Dictionary<string, object?>>();
        for (int trial = 1; trial <= 3; trial++)
        {
            try
            {
                trials.Add(await RunTrialAsync(trial, evidenceRoot, dotnetPath, rzcPath, tasksPath, extensionPath, invokeProject));
            }
            catch (Exception ex)
            {
                trials.Add(new Dictionary<string, object?>
                {
                    ["trial"] = trial,
                    ["invalid"] = true,
                    ["runtimePositive"] = false,
                    ["controlsPassed"] = false,
                    ["identityBoundaryConfirmed"] = false,
                    ["unhandledError"] = ex.ToString(),
                });
                await File.WriteAllTextAsync(
                    Path.Combine(evidenceRoot, $"trial-{trial}-unhandled.txt"),
                    ex + Environment.NewLine);
            }
        }
'''
replace_once(old_trial_loop, new_trial_loop, "trial loop")

old_client_wait = '''        using var clientTimeout = new CancellationTokenSource(TimeSpan.FromMinutes(4));
        await client.WaitForExitAsync(clientTimeout.Token);
        int clientExit = client.ExitCode;
'''
new_client_wait = '''        bool clientTimedOut = false;
        using var clientTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(230));
        try
        {
            await client.WaitForExitAsync(clientTimeout.Token);
        }
        catch (OperationCanceledException)
        {
            clientTimedOut = true;
            try
            {
                if (!client.HasExited)
                {
                    client.Kill(entireProcessTree: true);
                }
            }
            catch (Exception killError)
            {
                await File.WriteAllTextAsync(
                    Path.Combine(trialDir, "client-kill-error.txt"),
                    killError + Environment.NewLine);
            }
            try
            {
                using var postKillTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                await client.WaitForExitAsync(postKillTimeout.Token);
            }
            catch
            {
            }
        }
        int clientExit = client.HasExited ? client.ExitCode : -999;
'''
replace_once(old_client_wait, new_client_wait, "client wait")

old_client_result_decl = '''        string clientResult = Path.Combine(trialDir, "client-result.json");
        string clientDll = typeof(Program).Assembly.Location;
'''
new_client_result_decl = '''        string clientResult = Path.Combine(trialDir, "client-result.json");
        string clientProgress = Path.Combine(trialDir, "client-progress.json");
        string clientDll = typeof(Program).Assembly.Location;
'''
replace_once(old_client_result_decl, new_client_result_decl, "client progress declaration")

old_runtime_positive = '''        bool runtimePositive = finalHash != originalHash && serverPidInCanary && highIntegrityInCanary && highLogRecorded;

        var summary = new Dictionary<string, object?>
'''
new_runtime_positive = '''        bool runtimePositive = finalHash != originalHash && serverPidInCanary && highIntegrityInCanary && highLogRecorded;
        bool anyStageTimedOut = clientData is not null && Bool(clientData, "anyStageTimedOut");
        bool invalid = clientTimedOut || clientData is null || anyStageTimedOut;
        string clientProgressText = File.Exists(clientProgress)
            ? await File.ReadAllTextAsync(clientProgress)
            : string.Empty;

        var summary = new Dictionary<string, object?>
'''
replace_once(old_runtime_positive, new_runtime_positive, "trial classification")

old_summary_tail = '''            ["clientExitCode"] = clientExit,
            ["originalCanarySha256"] = originalHash,
'''
new_summary_tail = '''            ["clientExitCode"] = clientExit,
            ["clientTimedOut"] = clientTimedOut,
            ["clientProgressPresent"] = clientProgressText.Length > 0,
            ["clientProgress"] = clientProgressText,
            ["anyStageTimedOut"] = anyStageTimedOut,
            ["invalid"] = invalid,
            ["originalCanarySha256"] = originalHash,
'''
replace_once(old_summary_tail, new_summary_tail, "summary timeout fields")

program.write_text(source, encoding="utf-8")
print("R71_TRIAL_INSTRUMENTATION_APPLIED")
