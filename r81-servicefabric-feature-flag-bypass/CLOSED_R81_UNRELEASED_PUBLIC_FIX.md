# R81 — CLOSED: UNRELEASED HARDENING / PUBLIC FIX

## Candidate

A pipeline-controlled variable named `DistributedTask.Tasks.ServiceFabricDeploy.DisableRegistryAuthorityCheck` can make `ServiceFabricDeployV1` skip its registry-authority validation and apply the selected registry credential to an image hosted by another registry.

## Runtime result

The official-code matrix on Windows Server 2025 passed all controls against:

- `microsoft/azure-pipelines-tasks` commit `8d1cc28eac0736f98c898bccfb4f3fe422c69631`
- `ServiceFabricDeployV1` task version `1.283.1`
- `microsoft/azure-pipelines-task-lib` commit `43673c958dc5fb40b898c5c7b5b7b5bf0ebd14bd`

GitHub Actions run `44887678402`, job `136796423833`:

- Default foreign image: rejected with `RegistryAuthorityMismatch`; no synthetic secret added.
- Default matching image: accepted; synthetic registry credential added.
- Feature variable set to `true`: foreign image accepted; synthetic registry credential added.
- Uploaded evidence artifact `14700925664`; artifact ZIP SHA-256 `3923f290bec0228c30eb1633ceb7cbe53755ee61f7d04678c7bfdfc46c7fb8fc`.

This proves the behavior in the pinned master source. It does **not** establish a currently serviced Azure DevOps security boundary.

## Servicing failure

The current published release line inspected was:

- Branch: `releases/m283.20261105/hotfix-buildId-32473345`
- Task version: `1.283.0`

That release does not contain the registry-authority validation or the `ServiceFabricDeploy.DisableRegistryAuthorityCheck` feature flag. The positive matrix therefore exercised an unreleased task change, not the deployed release under test.

## Public prior art / duplicate risk

The underlying foreign-registry credential-binding problem is already publicly addressed by:

- `microsoft/azure-pipelines-tasks` PR `#22816`
- Commit `8d1cc28eac0736f98c898bccfb4f3fe422c69631`
- Commit title: `ServiceFabricDeployV1: apply registry credentials only to images of the selected registry`

The new validation and its compatibility kill switch were introduced together in that public fix. A report based on the legacy behavior would be public prior art / likely duplicate. A report based on bypassing the kill switch would depend on an unreleased security feature.

## Decision

`DO_NOT_SUBMIT`

No Azure DevOps portal submission, MSRC report, or final submission ZIP was created. Automatic workflow execution was disabled. The optional shipping-agent actor test remains source material only because the servicing gate failed first.
