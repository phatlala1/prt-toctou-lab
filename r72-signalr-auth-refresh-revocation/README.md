# R72 — SignalR authentication-refresh revocation matrix

This owned lab tests stock .NET 11.0.0 behavior after a connection refreshes from a token containing `scope=signalr:invoke` to the same user identity without that scope.

A positive requires all of the following:

1. A fresh low-scope connection is denied.
2. A high-scope connection is allowed.
3. `RefreshAuthenticationAsync` accepts the same-user low-scope token.
4. After that refresh returns, at least one real Hub invocation protected by `[Authorize("HighScope")]` executes.
5. The delayed low-scope control is denied and the connection remains usable.
6. The behavior occurs on stock .NET 11.0.0 without replacing SignalR internals.

The lab runs WebSockets, Server-Sent Events, and Long Polling. It alternates high and low tokens for the same `NameIdentifier`, sends an immediate invocation fan-out after every low refresh, and records the claims observed inside every protected handler execution.

`RUNTIME_NEGATIVE_CLOSED` means no protected method executed after scope removal across the complete valid matrix. `RUNTIME_POSITIVE_REVIEW_REQUIRED` is only a runtime signal; duplicate, scope, severity, and attacker-precondition review remain mandatory before any MSRC report.
