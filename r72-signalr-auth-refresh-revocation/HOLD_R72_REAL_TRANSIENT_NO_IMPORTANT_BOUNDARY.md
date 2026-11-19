# R72 — REAL RUNTIME BEHAVIOR / HOLD / DO NOT SUBMIT AS A STANDALONE MSRC CASE

## Candidate

ASP.NET Core SignalR authentication refresh can return before the Hub principal used for method authorization has published the refreshed claims. A method protected by a removed scope can therefore execute transiently with the previous principal.

## Exact runtime

- Stock `.NET SDK 11.0.100`, runtime `Microsoft.AspNetCore.App 11.0.0`.
- `Microsoft.AspNetCore.SignalR.Client 11.0.0`.
- Hosted run `44476474296`, commit `c77c9d23798e7713fe92c2bf8db6681e3f037dc2`.
- Evidence artifact `14506551693`.
- Artifact ZIP SHA-256 `77921825b82732ad02850481129f66f6468150b983e0961b59f14e5399c6cf55`.

The owned lab used the same authenticated `NameIdentifier` with two tokens:

- `high`: includes `scope=signalr:invoke`.
- `low`: omits that scope.

The Hub method was protected by `[Authorize("HighScope")]`. Three transports were tested with 75 high-to-low refresh cycles per transport and eight immediate protected invocations after each low refresh.

## Observed behavior

| Transport | Immediate calls after low refresh | Executed with previous high principal |
|---|---:|---:|
| WebSockets | 600 | 0 |
| Server-Sent Events | 600 | 0 |
| Long Polling | 600 | 83 |

Additional evidence:

- 18 of 75 Long Polling cycles produced at least one stale-high execution.
- Every stale-high execution reached the protected handler and recorded `token_mode=high` with the required scope present.
- Fresh low-scope connections were denied on all transports.
- Initial high-scope connections were allowed on all transports.
- Every delayed invocation after low refresh was denied: 225/225.
- There were zero invalid invocation observations.
- Every positive cycle began from a previously verified high-scope state.
- The race is bidirectional: six immediate Long Polling invocations after a high refresh were denied with the previous low principal.

The original harness emitted `RUNTIME_INVALID`, not because the stale-high observations were invalid, but because its deliberately strict control required every immediate high refresh to publish synchronously. The six inverse stale-low observations violated that control and independently confirm the same principal-publication ordering race.

## Root and duplicate comparison

This is not the same attacker input or minimum fix as `VULN-236935` / case `158571`:

- Existing case: a lower-privilege user controls or reuses another connection's connection token / identity binding.
- R72: the same user's accepted refresh loses a scope, while Hub method authorization transiently observes the prior principal.
- R72 minimum fix would require ordering refresh completion after Hub-principal publication or otherwise synchronizing authorization with the accepted refresh.

However, R72 does not currently prove a stronger standalone bounty boundary.

## Why this is HOLD

The actor already possessed the high scope on the same connection immediately before voluntarily refreshing to the low-scope token. The runtime proves delayed revocation/publication, but not a new low-privilege actor gaining an administrator identity or crossing a tenant/user boundary. The observable window is transient and converges to the low principal; all delayed low controls were denied.

That is insufficient evidence for the Critical/Important bar required by the .NET bounty program. It should not be represented as an Important elevation of privilege without an independent actor/precondition that makes the removed authorization unavailable before the attack.

## Disposition

- Real product behavior: **YES**.
- Complete standalone Important/Critical security boundary: **NO**.
- Submit new MSRC case: **NO**.
- Supplement `VULN-236935`: **NO**, unless a future chain proves a distinct low-privilege attacker can trigger this ordering flaw against a protected connection without already holding the removed scope.
- Final submission ZIP: **NOT CREATED**.
