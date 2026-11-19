[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $TasksRoot,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$packageRoot = Join-Path $OutputDirectory 'AppPkg'
$serviceRoot = Join-Path $packageRoot 'SvcPkg'
New-Item -ItemType Directory -Force -Path $serviceRoot | Out-Null

$applicationManifest = @'
<?xml version="1.0" encoding="utf-8"?>
<ApplicationManifest ApplicationTypeName="R79Type" ApplicationTypeVersion="1.0.0" xmlns="http://schemas.microsoft.com/2011/01/fabric">
  <ServiceManifestImport>
    <ServiceManifestRef ServiceManifestName="SvcPkg" ServiceManifestVersion="1.0.0" />
    <Policies>
      <ContainerHostPolicies CodePackageRef="Code" Isolation="process">
      </ContainerHostPolicies>
      <ContainerHostPolicies CodePackageRef="code" Isolation="process">
        <ImageOverrides>
          <Image Name="trusted.azurecr.io/override:1" />
        </ImageOverrides>
      </ContainerHostPolicies>
    </Policies>
  </ServiceManifestImport>
</ApplicationManifest>
'@

$serviceManifest = @'
<?xml version="1.0" encoding="utf-8"?>
<ServiceManifest Name="SvcPkg" Version="1.0.0" xmlns="http://schemas.microsoft.com/2011/01/fabric">
  <ServiceTypes>
    <StatelessServiceType ServiceTypeName="R79ServiceType" />
  </ServiceTypes>
  <CodePackage Name="Code" Version="1.0.0">
    <EntryPoint>
      <ContainerHost>
        <ImageName>evil.invalid/base:1</ImageName>
      </ContainerHost>
    </EntryPoint>
  </CodePackage>
</ServiceManifest>
'@

Set-Content -LiteralPath (Join-Path $packageRoot 'ApplicationManifest.xml') -Value $applicationManifest -Encoding utf8
Set-Content -LiteralPath (Join-Path $serviceRoot 'ServiceManifest.xml') -Value $serviceManifest -Encoding utf8
Copy-Item -LiteralPath (Join-Path $packageRoot 'ApplicationManifest.xml') -Destination (Join-Path $OutputDirectory 'ApplicationManifest.before.xml')

# Minimal VSTS task SDK surface needed by the exact shipping module. No secret is
# emitted to stdout; the synthetic marker is searched only in the resulting XML.
$script:SecretMarker = 'R79_SYNTHETIC_REGISTRY_SECRET_6C8D0CA8'
$script:UsernameMarker = 'R79_SYNTHETIC_REGISTRY_USER'

function global:Trace-VstsEnteringInvocation { param($Invocation) }
function global:Trace-VstsLeavingInvocation { param($Invocation) }
function global:Get-VstsPipelineFeature {
    param([string] $FeatureName)
    if ($FeatureName -ne 'ServiceFabricDeploy.DisableRegistryAuthorityCheck') {
        throw "Unexpected feature query: $FeatureName"
    }
    return $false
}
function global:Get-VstsInput {
    param([string] $Name, [switch] $Require)
    switch ($Name) {
        'registryCredentials' { return 'ContainerRegistryEndpoint' }
        'dockerRegistryEndpoint' { return 'r79-registry-connection' }
        default { throw "Unexpected task input: $Name" }
    }
}
function global:Get-VstsEndpoint {
    param([string] $Name, [switch] $Require)
    if ($Name -ne 'r79-registry-connection') {
        throw "Unexpected endpoint: $Name"
    }
    return @{
        Url = 'https://trusted.azurecr.io/'
        Data = @{ registrytype = 'Others' }
        Auth = @{
            Scheme = 'UsernamePassword'
            Parameters = @{
                registry = 'https://trusted.azurecr.io/'
                UserName = $script:UsernameMarker
                Password = $script:SecretMarker
            }
        }
    }
}
function global:Get-VstsLocString {
    param([string] $Key, [object[]] $ArgumentList)
    if ($ArgumentList) {
        return "$Key :: $($ArgumentList -join ' | ')"
    }
    return $Key
}

$modulePath = Join-Path $TasksRoot 'Tasks/ServiceFabricDeployV1/Update-DockerSettings.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    throw "Shipping module not found: $modulePath"
}

$module = Import-Module -Name $modulePath -Force -PassThru
try {
    & $module {
        param($Package)
        Update-DockerSettings -ApplicationPackagePath $Package -ClusterConnectionParameters @{}
    } $packageRoot
}
finally {
    Remove-Module $module -Force -ErrorAction SilentlyContinue
}

$afterPath = Join-Path $packageRoot 'ApplicationManifest.xml'
Copy-Item -LiteralPath $afterPath -Destination (Join-Path $OutputDirectory 'ApplicationManifest.after.xml')
[xml] $afterXml = Get-Content -LiteralPath $afterPath -Raw

$imports = @($afterXml.ApplicationManifest.ServiceManifestImport)
$policyRecords = @()
foreach ($import in $imports) {
    foreach ($policy in @($import.Policies.ContainerHostPolicies)) {
        $repositoryCredentials = @($policy.RepositoryCredentials)
        $policyRecords += [ordered]@{
            codePackageRef = [string]$policy.CodePackageRef
            overrideNames = @($policy.ImageOverrides.Image | ForEach-Object { [string]$_.Name })
            repositoryCredentialCount = $repositoryCredentials.Count
            containsSyntheticUsername = [bool](@($repositoryCredentials | Where-Object { [string]$_.AccountName -eq $script:UsernameMarker }).Count)
            containsSyntheticSecret = [bool](@($repositoryCredentials | Where-Object { [string]$_.Password -eq $script:SecretMarker }).Count)
        }
    }
}

$exactPolicy = @($policyRecords | Where-Object { $_.codePackageRef -ceq 'Code' })
$collisionPolicy = @($policyRecords | Where-Object { $_.codePackageRef -ceq 'code' })

$result = [ordered]@{
    schema = 'r79-servicefabric-policy-case-confusion/v1'
    taskCommit = '8d1cc28eac0736f98c898bccfb4f3fe422c69631'
    package = [ordered]@{
        codePackageName = 'Code'
        baseImage = 'evil.invalid/base:1'
        exactPolicyRef = 'Code'
        caseCollisionPolicyRef = 'code'
        caseCollisionDefaultOverride = 'trusted.azurecr.io/override:1'
        selectedRegistry = 'trusted.azurecr.io:443'
    }
    taskResult = [ordered]@{
        completed = $true
        policies = $policyRecords
        exactPolicyReceivedSecret = [bool](@($exactPolicy | Where-Object { $_.containsSyntheticSecret }).Count)
        collisionPolicyReceivedSecret = [bool](@($collisionPolicy | Where-Object { $_.containsSyntheticSecret }).Count)
        taskAcceptedForeignBaseWithoutValidation = [bool](
            @($exactPolicy | Where-Object { $_.containsSyntheticSecret }).Count -and
            @($collisionPolicy | Where-Object { $_.containsSyntheticSecret }).Count
        )
    }
}

$resultPath = Join-Path $OutputDirectory 'task-result.json'
$result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $resultPath -Encoding utf8
$result | ConvertTo-Json -Depth 20

if (-not $result.taskResult.taskAcceptedForeignBaseWithoutValidation) {
    throw 'R79 source-model gate was negative: the exact policy did not receive the synthetic secret.'
}
