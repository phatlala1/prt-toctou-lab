# R65 — Closed as public-known exact root

## Verdict

**DO NOT SUBMIT.** The stock .NET 11 runtime result is positive, but the exact root cause and mitigation were publicly described before this research round.

## Runtime result preserved

GitHub Actions run `44268287518` on SDK `11.0.100` / `Microsoft.AspNetCore.App 11.0.0` accepted the same protected passkey ceremony cookie and byte-identical signed assertion twice. Each request issued a distinct authenticated application cookie. A fresh-challenge control and a mutated-signature control both returned `401`. The evidence artifact is `r65-passkey-replay-evidence`, artifact ID `14410149826`, SHA-256 `6d034c869f6a9b8ec78c910cc21d178e6a99dcef7abe07e2a34993c16f60aa6f`.

## Public-known match

A public article dated 2026-10-01 already explains that ASP.NET Core clears the passkey ceremony cookie only in the browser, does not record server-side challenge consumption, and therefore a copied cookie remains usable until its five-minute expiry. It also identifies the `signCount = 0` synced-passkey case and recommends keeping a server-side record of used challenges.

Public reference:

`https://blog.maartenballiauw.be/posts/2026-10-01-using-aspnet-core-passkeys-for-second-factor-authentication/`

Microsoft's documentation separately states that signing out the state limits it to a single use, but that documentation discrepancy does not restore freshness after the exact replay root was publicly disclosed.

## Duplicate tuple

- **Component / enforcement layer:** ASP.NET Core Identity passkey ceremony state in `Identity.TwoFactorUserId`
- **Attacker-controlled input:** copied protected ceremony cookie plus captured signed assertion
- **First unsafe transformation:** client-side cookie deletion is treated as server-side single-use consumption
- **Protected effect:** mint multiple authenticated application sessions from one passkey assertion
- **Minimum fix:** atomically consume a server-side ceremony identifier/replay-cache entry until expiry

No MSRC case was opened and no submission ZIP was created.
