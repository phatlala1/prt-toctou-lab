# R71 — Razor build server cross-integrity extension loading

This owned Windows lab tests the stock .NET SDK 11 Razor build server. The hypothesis is that a medium-integrity process can connect to a high-integrity `rzc.dll` server because the server uses `PipeOptions.CurrentUserOnly` but does not verify that the client and server have the same elevation level. The official `SdkRazorGenerate` MSBuild task sends an attacker-readable extension DLL with `-e`; the stock server dependency checker shadow-copies and loads it.

## Required positive gates

Each of three independent trials must prove all of the following:

1. The orchestrator and stock `rzc.dll server` run high integrity.
2. The official Razor MSBuild client runs in a restricted medium-integrity token with the Administrators SID deny-only.
3. The medium client cannot modify an administrator-owned canary directly.
4. The same extension executes in an in-process medium Razor invocation, records medium integrity, and cannot modify the protected canary.
5. A medium request to the high server with no extension leaves the canary unchanged.
6. A medium request through the official `SdkRazorGenerate` task with the extension changes the canary.
7. The canary and extension log identify the exact high `rzc` PID and a high integrity RID.
8. Server and client retain the same Windows SID, proving a split-token integrity transition rather than a different-account test.

No product binary is modified. The extension only writes an owned canary under a disposable administrator-owned `%ProgramData%` directory. A positive remains a local Important candidate requiring exact public/private duplicate review; the workflow never submits to MSRC.
