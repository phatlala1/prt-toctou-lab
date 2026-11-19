# R71 — CLOSED: UAC / SAME-DESKTOP ELEVATION IS NOT AN MSRC SECURITY BOUNDARY

## Candidate

A medium-integrity process created from the filtered token of the same local administrator account might submit an extension assembly to an already-running high-integrity Razor build server through its `CurrentUserOnly` named pipe.

## Why this is closed

The proposed trust transition is the same administrator identity's filtered token to that identity's elevated token. That is a same-desktop UAC elevation scenario, not a serviced Windows security boundary.

Microsoft's current Windows Security Servicing Criteria lists **User Account Control (UAC)** as a defense-in-depth feature with:

- Intent to service: **No**
- Bounty: **No**

Microsoft's UAC guidance also states that same-desktop elevation is not a security boundary and a protected administrator should be treated as equivalent to Administrator for security-boundary analysis.

Authoritative references:

- https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/disable-user-account-control
- https://www.microsoft.com/en-us/msrc/bounty-dot-net-core

The .NET bounty additionally requires Critical or Important impact. A same-user UAC transition cannot establish that eligibility even if the Razor server executes the supplied extension at high integrity.

## Runtime status

No positive claim is made.

- Stock SDK: `.NET SDK 11.0.100`, commit `297acf930f`
- Stock `rzc.dll` and official `SdkRazorGenerate` task were located and built into the lab successfully.
- Run `44318521349` reached the official MSBuild task but timed out before producing a complete result.
- Artifact `14434091987`, ZIP SHA-256 `66d7da002d0726b34a932528d7d39b442b4dcc567a779a548e11528e9bc2357b`.
- The incomplete runtime is classified **invalid**, not positive and not negative.

Further debugging cannot change the boundary classification and is therefore stopped.

## Disposition

- **DO NOT SUBMIT**
- No MSRC report
- No final submission ZIP
- No severity claim
- Workflow changed to manual-only for preservation
