# R84 — CLOSED: RUNTIME POSITIVE, EXACT PUBLIC ROOT / BY-DESIGN RISK

## Runtime result

The released Microsoft Artifacts Credential Provider `1.1.0`, installed by the shipping `NuGetAuthenticateV1` task, returned and transmitted a synthetic external-feed service-connection credential to an HTTPS endpoint whose path differed from the configured endpoint only by case.

Positive hosted run:

- Run: `45047785690`
- Job: `137286061409`
- Commit: `8a3fe9cbb1cbcae03447c6af354504e1e2e249e4`
- Artifact: `14764103606`
- Artifact ZIP SHA-256: `24fc6221855616286cbb0a2f54ebd7821f7d70c91f824ed5c23da7b02303f8a7`
- Result: `SUPPORTED_RELEASE_RUNTIME_POSITIVE_REVIEW_REQUIRED`
- Controls: exact endpoint received the synthetic credential; sibling path and alternate host did not; TLS 1.3 was used; the case-variant endpoint received the credential both at the service index and flat-container paths.

## Closure reason

The underlying comparison behavior is exact public prior art and was intentionally introduced by Microsoft in 2019:

- Public issue `microsoft/artifacts-credprovider#120`, **Case sensitive comparison for endpoint credentials**, requested that endpoint matching become case-insensitive.
- Commit `7f6f1acbdf9b2b39494c9987d97d192da36932d7`, **Make service endpoint URL matching case-insensitive (fix #120)**, changed the endpoint credential dictionary to `StringComparer.OrdinalIgnoreCase`.
- The public regression test deliberately changed case in URL path components (`_Packaging/TestFEED` vs `_packaging/TestFeed`) and expected the credential to be returned.

Therefore, although R84 proves a real confidentiality impact on a case-sensitive multi-principal HTTPS path deployment, it reuses the same publicly documented and deliberately tested root behavior. Under the project rule requiring a fresh root with no public duplicate/prior art, R84 is closed and must not be submitted as a new MSRC case.

## Decision

- **No MSRC submission**
- **No final submission ZIP**
- **No severity claim**
- Preserve the runtime evidence only as a security consequence of the public design decision.
