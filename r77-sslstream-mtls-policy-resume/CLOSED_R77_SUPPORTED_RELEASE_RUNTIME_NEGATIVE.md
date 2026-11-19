# R77 — CLOSED: supported-release runtime negative

## Candidate

An anonymous TLS session established while `ClientCertificateRequired=false` might resume after the server switches the same certificate, host, protocol, process, and cache scope to a strict mTLS policy, allowing application data without a client certificate or callback validation.

## Controlled runtime result

Hosted run: `44585817213`

Commit: `f698d7430bcf035bb6c5a76b0bea5c1e758f9817`

The Linux matrix used stock supported releases:

- .NET `10.0.15`, built with SDK `10.0.404`
- .NET `11.0.0`, built with SDK `11.0.100`
- TLS 1.2 and TLS 1.3
- three independent trials per protocol
- native `CryptoNative_SslSessionReused(SSL*)` proof on both client and server

Every anonymous public-policy baseline established a genuinely resumed TLS session. After switching to strict mTLS, every candidate connection was rejected. The server validation callback was invoked with `certificate=null`; protected application data was never returned. The matched no-resumption control also rejected the anonymous client. Expected client certificates passed and wrong client certificates failed.

Therefore the hypothesized anonymous-session-to-mTLS authorization bypass is disproved on the tested supported Linux releases.

## Windows disposition

Windows Server 2025 / Schannel runs are classified **invalid**, not positive or negative. All baseline handshakes timed out before authentication, including the public anonymous and expected-client-certificate controls. They cannot affect the Linux negative verdict and are preserved only as invalid evidence.

## Evidence

- Ubuntu .NET 10 artifact `14559703482`; ZIP SHA-256 `dfb0b61fc412dcb829089042ed19ce5691756ddbf87e411b4a8c691aae98a904`
- Ubuntu .NET 11 artifact `14559788395`; ZIP SHA-256 `9806a91362a71c4362aa47cac65c1e468eacf4d8b31cff806d9c7e5b07639d3f`
- Windows .NET 10 invalid artifact `14561259211`; ZIP SHA-256 `ccaa04ea7ff94022e0a2d96f6cb14f55194cdf39606f133341d3877cfd54a218`
- Windows .NET 11 invalid artifact `14561681247`; ZIP SHA-256 `102d6ff4250d54ee9670099a2c47ec5e00e10cf78a622d4e7ac5b8dce31d1bc6`

## Decision

- Runtime vulnerability: **NO on tested supported Linux releases**
- Windows result: **INVALID / not evidence of a vulnerability**
- MSRC report: **DO NOT CREATE**
- Submission ZIP: **DO NOT CREATE**
- Portal submission: **NO**
