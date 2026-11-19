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

old_task_args = '''            psi.ArgumentList.Add("/v:diag");
            AddProperty("RazorTasksAssembly", tasksPath);
'''
new_task_args = '''            psi.ArgumentList.Add("/v:diag");
            psi.ArgumentList.Add("/m:1");
            psi.ArgumentList.Add("/nr:false");
            AddProperty("RazorTasksAssembly", tasksPath);
'''
replace_once(old_task_args, new_task_args, "task arguments")

old_task_env = '''            psi.Environment["DOTNET_HOST_PATH"] = dotnetPath;
            psi.Environment["R71_CANARY"] = canary;
            psi.Environment["R71_EXECUTION_LOG"] = executionLog;
            psi.Environment["DOTNET_NOLOGO"] = "1";
            using Process process = Process.Start(psi) ?? throw new InvalidOperationException("Failed to launch official Razor MSBuild task.");
            string stdout = await process.StandardOutput.ReadToEndAsync();
            string stderr = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            await File.WriteAllTextAsync(Path.Combine(runDir, "stdout.txt"), stdout);
            await File.WriteAllTextAsync(Path.Combine(runDir, "stderr.txt"), stderr);
            return new CommandResult(process.ExitCode, stdout, stderr);
'''
new_task_env = '''            string cliHome = Path.Combine(runDir, ".dotnet-home");
            Directory.CreateDirectory(cliHome);
            psi.Environment["DOTNET_HOST_PATH"] = dotnetPath;
            psi.Environment["DOTNET_CLI_HOME"] = cliHome;
            psi.Environment["R71_CANARY"] = canary;
            psi.Environment["R71_EXECUTION_LOG"] = executionLog;
            psi.Environment["DOTNET_NOLOGO"] = "1";
            psi.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
            psi.Environment["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"] = "1";
            psi.Environment["MSBUILDDISABLENODEREUSE"] = "1";

            await File.WriteAllTextAsync(
                Path.Combine(runDir, "command.json"),
                JsonSerializer.Serialize(new
                {
                    fileName = psi.FileName,
                    arguments = psi.ArgumentList.ToArray(),
                    useServer,
                    includeExtension,
                    pipeName,
                }, JsonOptions) + Environment.NewLine);
            await WriteClientProgressAsync($"{label}:starting", new { useServer, includeExtension, pipeName });

            using Process process = Process.Start(psi) ?? throw new InvalidOperationException("Failed to launch official Razor MSBuild task.");
            Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
            Task<string> stderrTask = process.StandardError.ReadToEndAsync();
            await WriteClientProgressAsync($"{label}:process-started", new { processId = process.Id });

            bool timedOut = false;
            using var stageTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            try
            {
                await process.WaitForExitAsync(stageTimeout.Token);
            }
            catch (OperationCanceledException)
            {
                timedOut = true;
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                    }
                }
                catch
                {
                }
                try
                {
                    using var postKillTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                    await process.WaitForExitAsync(postKillTimeout.Token);
                }
                catch
                {
                }
            }

            await Task.WhenAny(Task.WhenAll(stdoutTask, stderrTask), Task.Delay(TimeSpan.FromSeconds(15)));
            string stdout = stdoutTask.IsCompletedSuccessfully ? stdoutTask.Result : "R71_STDOUT_READ_TIMEOUT";
            string stderr = stderrTask.IsCompletedSuccessfully ? stderrTask.Result : "R71_STDERR_READ_TIMEOUT";
            if (timedOut)
            {
                stderr = "R71_STAGE_TIMEOUT" + Environment.NewLine + stderr;
            }
            int exitCode = process.HasExited ? process.ExitCode : -999;
            await File.WriteAllTextAsync(Path.Combine(runDir, "stdout.txt"), stdout);
            await File.WriteAllTextAsync(Path.Combine(runDir, "stderr.txt"), stderr);
            await File.WriteAllTextAsync(
                Path.Combine(runDir, "stage-result.json"),
                JsonSerializer.Serialize(new
                {
                    label,
                    processId = process.Id,
                    exitCode,
                    timedOut,
                    finishedAtUtc = DateTimeOffset.UtcNow,
                }, JsonOptions) + Environment.NewLine);
            return new CommandResult(exitCode, stdout, stderr);
'''
replace_once(old_task_env, new_task_env, "task execution")

old_quote = '''    private static string BuildCommandLine(IReadOnlyList<string> values) => string.Join(" ", values.Select(Quote));
    private static string Quote(string value) => "\\\"" + value.Replace("\\\\", "\\\\\\\\").Replace("\\\"", "\\\\\\\"") + "\\\"";
'''
new_quote = '''    private static string BuildCommandLine(IReadOnlyList<string> values) => string.Join(" ", values.Select(Quote));

    private static string Quote(string value)
    {
        var builder = new StringBuilder();
        builder.Append('"');
        int backslashes = 0;
        foreach (char character in value)
        {
            if (character == '\\\\')
            {
                backslashes++;
                continue;
            }
            if (character == '"')
            {
                builder.Append('\\\\', backslashes * 2 + 1);
                builder.Append('"');
                backslashes = 0;
                continue;
            }
            builder.Append('\\\\', backslashes);
            backslashes = 0;
            builder.Append(character);
        }
        builder.Append('\\\\', backslashes * 2);
        builder.Append('"');
        return builder.ToString();
    }
'''
replace_once(old_quote, new_quote, "command-line quote")

program.write_text(source, encoding="utf-8")
print("R71_TASK_INSTRUMENTATION_APPLIED")
