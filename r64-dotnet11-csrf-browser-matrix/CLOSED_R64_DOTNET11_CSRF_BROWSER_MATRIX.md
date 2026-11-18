# R64 closure — ASP.NET Core .NET 11 automatic CSRF browser matrix

**Final state:** `RUNTIME_NEGATIVE_CLOSED`  
**MSRC submission:** none  
**Report package:** none

## What was tested

An owned loopback Kestrel application used stock .NET SDK `11.0.100` and `Microsoft.AspNetCore.App 11.0.0`. The protected state-changing endpoint carried `RequireAntiforgeryTokenAttribute`. The victim authentication cookie was `Secure`, `HttpOnly`, and `SameSite=None`, so browsers were allowed to attach the victim session to cross-site requests and the ASP.NET Core CSRF feature—not SameSite—made the decision.

The matrix ran real Chromium `159.0.8154.6`, Firefox `159.0`, and WebKit `27.2` through Playwright `1.65.1`.

## Decisive result

All three engines completed the required controls:

- same-origin authenticated browser POST: `200`, antiforgery valid, mutation `1`;
- cross-origin synthetic request without `Sec-Fetch-Site`: `400`, antiforgery invalid, mutation `0`;
- synthetic `Sec-Fetch-Site: none`: `200`, antiforgery valid, mutation `1`, but explicitly excluded from the security verdict because a non-browser client supplied the header.

Every real-browser attack request reached the protected endpoint with the victim authenticated. Every request carried `Sec-Fetch-Site: cross-site`, received `400`, recorded `IAntiforgeryValidationFeature.IsValid=false`, and produced no mutation.

The following cases were exercised independently in all three engines:

- cross-site auto-submitted form;
- cross-site user-click form;
- opaque sandboxed iframe with scripts and forms;
- opaque sandboxed iframe with click-only form submission;
- attacker-created `data:` iframe;
- attacker-created top-level `blob:` document;
- attacker-created `about:blank` popup with `document.write`;
- credentialed `fetch(..., mode: "no-cors")`;
- HTTP `307` method-preserving redirect;
- direct top-level `data:` navigation as a separate opaque-navigation control.

All 30 browser cases had an authenticated victim request, HTTP `400`, antiforgery rejection, and mutation count `0`. Even the direct top-level `data:` control arrived as `Sec-Fetch-Site: cross-site`; no browser case reached the framework's accepted `none` branch.

Therefore the tested hypothesis—an attacker-controlled browser context reaching the accepted `Sec-Fetch-Site: none` branch while carrying the victim session—is disproved for this matrix.

## Integrity and provenance

- Workflow run: `44306312983`
- Tested commit: `b1fe83e6696934d51080246010ab0d68c912e669`
- Artifact ID: `14428900532`
- Artifact ZIP SHA-256: `73c299f3b2b936a77dbd023316ff75b66e08262dd4ec2c465acbb88c4f7663e7`
- Original `result.json` SHA-256: `f97e4f31863b5a669517f9e68882a460cc4f710687caf6df2a5d93add595d564`
- Patched runtime `Program.cs` SHA-256: `73c37f3c0c4790bec1b17e0bb7f9d6ab393791c0d709d8a03c83f19b91dda47b`
- Build: `0` warnings, `0` errors
- Browser engine errors: `0`
- Remote-web bypass count: `0`
- Opaque-navigation signal count: `0`

The deterministic source repair and its SHA-256 are preserved in the workflow evidence. Earlier failed runs were workflow or harness failures and do not count as security results.

## Reopen condition

Reopen only with a distinct browser primitive that can cause a credentialed request to a protected endpoint to arrive as `Sec-Fetch-Site: none`, or can bypass the fallback validation, on a current supported browser/runtime. Synthetic header forging, extension-controlled requests, native clients, disabled protection, and application-specific opt-outs do not reopen this root.
