#!/usr/bin/env python3
from pathlib import Path

program = Path("r71-razor-server-cross-integrity/Program.cs")
source = program.read_text(encoding="utf-8")
old = '''        if (!WaitNamedPipe($@"\\\\.\\pipe\\{pipe}", 30_000))
        {
            throw new TimeoutException("Stock rzc server pipe did not become ready.");
        }
'''
new = '''        bool pipeReady = false;
        Stopwatch readiness = Stopwatch.StartNew();
        string pipePath = $@"\\\\.\\pipe\\{pipe}";
        while (readiness.Elapsed < TimeSpan.FromSeconds(30) && !server.HasExited)
        {
            if (WaitNamedPipe(pipePath, 250))
            {
                pipeReady = true;
                break;
            }
            await Task.Delay(100);
        }
        if (!pipeReady)
        {
            if (!server.HasExited)
            {
                server.Kill(entireProcessTree: true);
                await server.WaitForExitAsync();
            }
            throw new TimeoutException($"Stock rzc server pipe did not become ready. exit={server.ExitCode}");
        }
'''
if source.count(old) != 1:
    raise SystemExit(f"readiness block count was {source.count(old)}, expected exactly one")
program.write_text(source.replace(old, new, 1), encoding="utf-8")
print("R71_SERVER_READINESS_PATCHED")
