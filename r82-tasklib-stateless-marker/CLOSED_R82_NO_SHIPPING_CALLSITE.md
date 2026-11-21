# R82 — CLOSED: NO SHIPPING SOURCE-TO-SINK

## Hypothesis

`azure-pipelines-task-lib` 5.283.3 creates and flushes a new external-output marker filter for each `writeExternalOutput()` call. Two independent writes can therefore concatenate a split marker:

```text
writeExternalOutput("##v")
writeExternalOutput("so[task.setvariable variable=R82_SYNTHETIC]true\n")
```

## Runtime differential

GitHub Actions run `44937042340` built pinned task-lib commit `43673c958dc5fb40b898c5c7b5b7b5bf0ebd14bd` and observed:

- Independent raw writes: `##vso[task.setvariable variable=R82_SYNTHETIC]true`
- One complete write: `##_vso[task.setvariable variable=R82_SYNTHETIC]true`
- Stateful writer split across chunks: `##_vso[task.setvariable variable=R82_SYNTHETIC]true`

The core API differential is real.

## Shipping callsite audit

The negative-first audit scanned non-test TypeScript/JavaScript task sources in both current release lanes:

| Release lane | Raw `writeExternalOutput` calls | Calls without explicit EOL | High-priority hits | Verdict |
|---|---:|---:|---:|---|
| `releases/m282.20261030/hotfix-buildId-32410599` | 68 | 0 | 0 | `CLOSED_NO_SHIPPING_CALLSITE` |
| `releases/m283.20261105/hotfix-buildId-32473345` | 72 | 0 | 0 | `CLOSED_NO_SHIPPING_CALLSITE` |

Every shipping raw call was line-terminated before it reached the stateless API. The partial marker cannot concatenate with the next task write on the same agent log line.

## Evidence

- Run: `44937042340`
- m282 artifact: `14720146116`
  - Artifact ZIP SHA-256: `decbc8f333c71c2dbdd8a65deaa7a6f4914e0a6bb014ead89ff322ec25968ccc`
- m283 artifact: `14720305787`
  - Artifact ZIP SHA-256: `8b0373add806dc3410dff15edb00d6b944ffa977e4f9b048f2225f4900c234a6`

## Decision

`DO_NOT_SUBMIT`

This is an API hardening observation without a shipping Microsoft task source-to-sink or security-boundary crossing. No MSRC report, final submission ZIP, or portal submission was created. Automatic execution was disabled.
