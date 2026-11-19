# R78 — CLOSED: exact public-known Base64Url AVX2 root only

## Candidate

A broad differential and sentinel matrix tested whether `System.Buffers.Text.Base64Url` contained a fresh SIMD-only memory-safety or semantic flaw distinct from the publicly fixed AVX2 destination-bounds issue.

## Public prior art excluded from the fresh-candidate gate

Microsoft runtime commit:

- `7ad74025fa5c5ea0f8e082fa318c1c91329fe3a1`
- `Fix Base64Url AVX2 destination bounds (#137655)`

The published root is the AVX2 final-block path when:

- `destinationLength == GetMaxDecodedLength(sourceLength) - 2`; and
- `sourceLength % 4` is `1` or `2`.

## Runtime matrix

Hosted run: `44589322587`

Source/comparator commit: `f8889488fb91e1660cebbb1165d52552418d87ea`

Each channel executed `67,999` cases in each of three modes:

- default hardware intrinsics;
- AVX2 disabled; and
- all hardware intrinsics disabled.

The harness covered:

- UTF-8, UTF-16, and in-place decoding;
- final and non-final blocks;
- source and destination vector boundaries;
- destination alignments `0`, `1`, and `31`;
- whitespace, invalid characters, invalid padding, and non-ASCII inputs;
- prefix and suffix guard regions outside the destination span; and
- acceptance and successful decoded-output comparison across SIMD/scalar and UTF-8/UTF-16 paths.

## Corrected verdict

The first comparator was deliberately rejected because it incorrectly treated SIMD scratch writes inside the caller-provided destination, ordinary Base64 validity assumptions, and non-success partial-progress differences as vulnerability signals. The corrected comparator limits fresh signals to:

- writes outside the destination span;
- out-of-range `consumed` or `written` values;
- exception-versus-result divergence;
- `Done`-versus-non-`Done` divergence; or
- different successful decoded bytes.

Results:

| Channel | Result | Out-of-span writes | Public-known | Fresh | Bounds | Acceptance/output divergence |
|---|---|---:|---:|---:|---:|---:|
| .NET 10.0.15 | `RUNTIME_NEGATIVE_CLOSED` | 0 | 0 | 0 | 0 | 0 |
| .NET 11.0.0 | `PUBLIC_KNOWN_CONTROL_ONLY` | 72 | 72 | 0 | 0 | 0 |
| .NET 12 daily `12.0.100-alpha.1.26569.103` | `PUBLIC_KNOWN_CONTROL_ONLY` | 72 | 72 | 0 | 0 | 0 |

Every one of the 72 out-of-span writes matched the exact published condition above. There was no out-of-span write outside that root, no public API bounds violation, no SIMD/scalar acceptance divergence, no successful-output divergence, and no UTF-8/UTF-16 acceptance or decoded-output divergence.

The daily SDK predates or does not yet contain the published fix; reproduction there does not create a distinct root cause.

## Evidence

- Supported .NET 10 artifact `14563040928`; uploaded ZIP SHA-256 `0551e3a85df37e2408ce6296abdb469e056206d8553a4ef4b1cbaaa9f1d5f0b7`
- Supported .NET 11 artifact `14563571054`; uploaded ZIP SHA-256 `ab36629501904aa1c0f0261ce38f2c143abb75e7f9ceafe8e2dac6105fe1ebad`
- .NET 12 daily artifact `14562066823`; uploaded ZIP SHA-256 `01fc2273974b765d36496923eafd1e028bd15819aa824a35030e639b90a98ee1`

All uploaded evidence manifests verified successfully.

## Decision

- Fresh vulnerability: **NO**
- Distinct root cause: **NO**
- Public duplicate/prior art: **YES — exact root**
- MSRC report: **DO NOT CREATE**
- Submission ZIP: **DO NOT CREATE**
- Portal submission: **NO**
