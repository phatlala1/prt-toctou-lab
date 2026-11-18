# R70 closure — public CVE family, invalid runtime

**Final state:** `DO-NOT-SUBMIT`  
**Fresh-root eligibility:** failed  
**Runtime verdict:** invalid; neither positive nor negative  
**MSRC report:** not created

## Why this lane is closed

The candidate attempted to bypass the current workload installer log-path validation by placing a directory junction below the trusted client temp directory. The elevated server performs a lexical `Path.GetFullPath`/prefix check and then calls `File.Create` on the accepted MSI log path.

However, the root is not fresh:

1. **CVE-2026-45490** already covers the .NET SDK workload named-pipe path where a local user causes elevated arbitrary file creation or truncation. The public servicing change added the user-specific pipe DACL, `--client-temp`, and the lexical `ValidateLogFilePath` logic that R70 attempted to bypass.
2. **CVE-2026-70190** publicly covers elevated workload-installer junction/symlink following on Windows.

Therefore R70 is, at best, a potential missed-fix variant inside two public workload-installer security families. It does not satisfy the project requirement for a new, non-public root.

## Runtime attempt

- Repository branch: `r70-workload-msi-log-junction`
- Workflow run: `44311087593`
- Tested commit: `e764f69755149df9613f3d3d18af2368f8677a7f`
- SDK: stock `11.0.100`, commit `297acf930f`
- Host: Windows Server 2025, high-integrity `runneradmin`
- Harness build: succeeded with `0` warnings and `0` errors
- Artifact ID: `14431830195`
- Artifact ZIP SHA-256: `994e31cdfc2ebdf3dc8cf48401b29422ed28871bf3f862674126559b52ab2df7`

The stock `dotnet workload elevate` server started, but both real named pipes timed out waiting for connection. The orchestrator then timed out waiting for the restricted client after three minutes. No `client-result.json`, trial summary, or final `result.json` was produced.

This is a **harness failure**, not evidence that the product is safe or vulnerable. No positive/negative security claim is made from the run.

## Preserved evidence

The artifact contains:

- exact stock SDK/runtime identity;
- high-integrity host token details;
- successful strict build logs;
- server PID;
- server error: both dispatch and logging pipes timed out;
- runtime stack showing the restricted-client wait timeout;
- SHA-256 inventory.

## Reopen rule

Do not reopen this lane for a fresh MSRC report. Reopen only to reproduce or supplement an existing CVE/missed-fix case when that is explicitly desired. Do not rename or repackage it as a new root.
