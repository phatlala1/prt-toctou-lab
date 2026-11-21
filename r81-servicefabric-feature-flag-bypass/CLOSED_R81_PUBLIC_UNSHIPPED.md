# R81 — CLOSED: PUBLIC PRIOR ART / SHIPPED-VERSION GATE NOT MET

## Candidate

A normal Azure Pipelines variable named
`DistributedTask.Tasks.ServiceFabricDeploy.DisableRegistryAuthorityCheck`
can activate the `ServiceFabricDeploy@1` rollback path and disable the registry
authority check before registry credentials are written into a Service Fabric
application manifest.

## What real runtime proved

Two independent pinned Microsoft-code gates passed:

1. **Task code gate** — `ServiceFabricDeployV1` from
   `microsoft/azure-pipelines-tasks` commit
   `8d1cc28eac0736f98c898bccfb4f3fe422c69631` rejected a foreign registry by
   default but, with the feature variable enabled through the pinned task-lib,
   accepted the same foreign image and wrote a synthetic registry username and
   password into `RepositoryCredentials`.
2. **Agent variable gate** — `microsoft/azure-pipelines-agent` commit
   `af087fe2880e468e02b8974adc25c26399b78d98` passed 4/4 compiled L0 tests.
   An unrestricted task could create the exact variable. With the rollout knob
   disabled, it could also overwrite an existing read-only value. Explicit
   `settableVariables` restrictions and read-only enforcement blocked the
   matched controls.

The runtime results are valid. This closure does **not** reclassify them as
negative.

## Why this is not an MSRC submission

- The registry-authority change and its rollback variable are already public in
  Azure Pipelines Tasks PR `#22816`. The PR explicitly states that enabling the
  feature flag restores the previous behavior.
- The tested code is task version `1.284.1` on `master`. At closure time, no
  public `m284` release branch was present. The latest public release branch
  inspected, `releases/m283.20261105/hotfix-buildId-32473345`, contains
  `ServiceFabricDeployV1` version `1.283.0` and does not establish deployment of
  the authority check or its kill switch to Azure DevOps Services.
- Therefore the candidate fails both the **non-public prior-art** gate and the
  **current shipped affected build** gate. A real restricted-user/service-
  connection matrix would not repair those failures.
- The broader same-job variable model also has documented controls:
  `target.settableVariables`, read-only variables, and queue-variable
  restrictions. That adds substantial user-configuration risk to the bounty
  theory.

## Decision

`DO_NOT_SUBMIT`

No MSRC report, final submission ZIP, or portal submission was created.
