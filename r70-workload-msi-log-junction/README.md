# R70 — .NET SDK workload MSI log-path junction validation

This is a non-destructive, owned Windows lab for a potential missed fix in the elevated .NET SDK workload installer.

## Hypothesis

The stock elevated workload server validates an IPC-supplied MSI log path with `Path.GetFullPath` and a lexical root-prefix check, then opens the accepted path with `File.Create`. A medium-integrity client may create a directory junction below its own temp directory so the lexical path remains allowed while the final file resolves into an administrator-owned directory.

## Runtime gates

A positive requires all of the following in three independent trials:

1. Stock .NET SDK `11.0.100` launches the real `dotnet workload elevate` server.
2. The IPC client runs under a restricted medium-integrity token with the Administrators SID deny-only.
3. The client cannot modify the administrator-owned canary directly or through the junction.
4. A direct outside-root log path leaves the canary unchanged.
5. A normal log path below client temp is created successfully.
6. The exact `RepairMsi` request sent through the real product named pipe changes the protected canary only when the log path passes through the junction.
7. Pipe framing and pipe-name derivation match the released SDK implementation; no product binary is patched.

The invalid product code is intentional: `ConfigureInstall` opens the log before Windows Installer rejects the repair. The test does not install software or modify an operating-system file; it uses a disposable administrator-owned canary under `%ProgramData%`.

## Interpretation limits

The GitHub-hosted runner starts the server from an already elevated parent because interactive UAC is unavailable in CI. The client is still a distinct medium-integrity same-user process, matching the split-token SID that the product pipe DACL authorizes. A positive is a runtime candidate requiring a final manual replay through the normal UAC launch path before MSRC submission.
