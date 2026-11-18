# R64 — ASP.NET Core .NET 11 CSRF browser matrix

This is a **negative-first** owned lab for the stock ASP.NET Core .NET 11 automatic CSRF feature. It does not claim a vulnerability from source inspection or synthetic headers.

## Required gates

1. The same-origin browser control must mutate the protected endpoint in Chromium, Firefox, and WebKit.
2. The Origin fallback control must not mutate.
3. A synthetic client that forges `Sec-Fetch-Site: none` is recorded only as a reachability control and is excluded from the security verdict.
4. A candidate exists only when a real browser case classified as `remote-web-attacker` sends the victim cookie and mutates the protected endpoint.
5. Direct `data:` navigation is an opaque-navigation control and is not sufficient for MSRC submission.

The victim cookie is `Secure`, `HttpOnly`, and `SameSite=None` so cross-site requests are not blocked by SameSite before the ASP.NET Core security feature is exercised. All targets are loopback hostnames in the researcher-owned CI job.

## Output

`evidence/result.json` contains the complete request headers, antiforgery verdicts, authentication state, and mutations for every browser case. Expected negative status:

```text
RUNTIME_NEGATIVE_CLOSED
```
