#requires -Version 7.0
<#
.SYNOPSIS
  Safely previews, deploys, or removes the lab's two Microsoft Sentinel rules.

.DESCRIPTION
  Uses fixed GUID rule IDs, exact display names, per-deployment ownership
  markers, and a local provenance manifest. Before any write or delete, every
  rule ID and display-name collision is inspected. Existing deterministic IDs
  are never adopted without the matching manifest.

  The default run is read-only. Pass -Execute for a deployment or removal.
  Rules deploy disabled unless -EnableRules is explicitly supplied.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory = $false)]
  [string]$ResourceGroup = $env:SENTINEL_RESOURCE_GROUP,

  [Parameter(Mandatory = $false)]
  [string]$WorkspaceName = $env:SENTINEL_WORKSPACE_NAME,

  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId = $env:AZURE_SUBSCRIPTION_ID,

  [Parameter(Mandatory = $false)]
  [ValidateSet('Deploy', 'Remove')]
  [string]$Action = 'Deploy',

  [Parameter(Mandatory = $false)]
  [switch]$EnableRules,

  [Parameter(Mandatory = $false)]
  [switch]$Execute,

  [Parameter(Mandatory = $false)]
  [string]$StatePath = (Join-Path (Split-Path -Parent $PSScriptRoot) '.device-code-sentinel-state.json')
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$apiVersion = '2024-03-01'
$ownerMarker = 'nine-lives-zero-trust:entra-device-code-phishing-sentinel:v1'
$templatePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'infra/sentinel-rules.bicep'
$ruleDefinitions = @(
  [pscustomobject]@{
    Id          = '45543375-c81a-56ab-b020-b3cc3bcf652e'
    Key         = 'device-code-50199-to-success'
    DisplayName = 'LAB - Device Code - 50199 Followed by Success'
  },
  [pscustomobject]@{
    Id          = '0d879be9-2084-5bee-bf5b-8effbf4d8c64'
    Key         = 'device-code-unapproved-client'
    DisplayName = 'LAB - Device Code - Unapproved Client'
  }
)

function Assert-NonEmpty {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $false)]
    [string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    throw ('{0} is required.' -f $Name)
  }
  return $Value
}

function Assert-GuidValue {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $false)]
    [string]$Value
  )

  $Value = Assert-NonEmpty -Name $Name -Value $Value
  $parsed = [guid]::Empty
  if (-not [guid]::TryParse($Value, [ref]$parsed) -or $parsed -eq [guid]::Empty) {
    throw ('{0} must be a non-empty GUID; received "{1}".' -f $Name, $Value)
  }
  return $parsed.ToString()
}

function Invoke-AzCli {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  $output = & az @Arguments 2>&1
  $exitCode = $LASTEXITCODE
  $text = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
  if ($exitCode -ne 0) {
    throw ('Azure CLI failed (az {0}): {1}' -f ($Arguments -join ' '), $text)
  }
  return $text
}

function Invoke-AzCliJson {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  $text = Invoke-AzCli -Arguments $Arguments
  if ([string]::IsNullOrWhiteSpace($text)) {
    throw ('Azure CLI returned an empty JSON response (az {0}).' -f ($Arguments -join ' '))
  }
  try {
    return $text | ConvertFrom-Json
  }
  catch {
    throw ('Azure CLI returned invalid JSON (az {0}): {1}' -f ($Arguments -join ' '), $_.Exception.Message)
  }
}

function Get-OwnershipSuffix {
  param(
    [Parameter(Mandatory = $true)]
    [string]$DeploymentId,

    [Parameter(Mandatory = $true)]
    [string]$RuleKey
  )

  return '[Owner: {0}; Deployment: {1}; Rule: {2}]' -f $ownerMarker, $DeploymentId, $RuleKey
}

function Get-AllSentinelRules {
  param(
    [Parameter(Mandatory = $true)]
    [string]$InitialUrl
  )

  $allRules = [System.Collections.Generic.List[object]]::new()
  $nextUrl = $InitialUrl
  while ($nextUrl) {
    if (-not $nextUrl.StartsWith('https://management.azure.com/', [System.StringComparison]::OrdinalIgnoreCase)) {
      throw ('Sentinel returned an unexpected pagination URL: {0}' -f $nextUrl)
    }

    $page = Invoke-AzCliJson -Arguments @('rest', '--method', 'GET', '--url', $nextUrl, '--only-show-errors', '-o', 'json')
    if (-not ($page.PSObject.Properties.Name -contains 'value')) {
      throw 'Sentinel rule inventory response did not contain a value array.'
    }
    foreach ($rule in @($page.value)) {
      $allRules.Add($rule)
    }

    $nextUrl = $null
    if ($page.PSObject.Properties.Name -contains 'nextLink' -and $page.nextLink) {
      $nextUrl = [string]$page.nextLink
    }
  }

  return @($allRules)
}

function New-StateObject {
  param(
    [Parameter(Mandatory = $true)]
    [string]$DeploymentId,

    [Parameter(Mandatory = $true)]
    [object]$Context,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceResourceId
  )

  return [ordered]@{
    schemaVersion       = 1
    status              = 'planned'
    rulesEnabled        = $false
    lastVerifiedUtc     = $null
    ownerMarker         = $ownerMarker
    deploymentId        = $DeploymentId
    tenantId            = ([guid]$Context.tenantId).ToString()
    subscriptionId      = ([guid]$Context.id).ToString()
    resourceGroup       = $ResourceGroup
    workspaceName       = $WorkspaceName
    workspaceResourceId = $WorkspaceResourceId
    ruleIds             = @($ruleDefinitions.Id)
    ruleDisplayNames    = @($ruleDefinitions.DisplayName)
    createdUtc          = (Get-Date).ToUniversalTime().ToString('o')
  }
}

function Save-State {
  param(
    [Parameter(Mandatory = $true)]
    [object]$State
  )

  $fullPath = [System.IO.Path]::GetFullPath($StatePath)
  $directory = Split-Path -Parent $fullPath
  if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
    throw ('State-file directory does not exist: {0}' -f $directory)
  }

  $temporaryPath = '{0}.tmp.{1}' -f $fullPath, $PID
  try {
    $json = $State | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($temporaryPath, $json, [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporaryPath -Destination $fullPath -Force
  }
  finally {
    if (Test-Path -LiteralPath $temporaryPath) {
      Remove-Item -LiteralPath $temporaryPath -Force
    }
  }
}

function Read-And-ValidateState {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Context,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceResourceId
  )

  if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
    return $null
  }

  try {
    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
  }
  catch {
    throw ('Provenance manifest is unreadable or invalid JSON: {0}' -f $_.Exception.Message)
  }

  if ($state.schemaVersion -ne 1) {
    throw ('Unsupported provenance schemaVersion "{0}".' -f $state.schemaVersion)
  }
  if ($state.ownerMarker -ne $ownerMarker) {
    throw 'Provenance manifest owner marker does not match this lab.'
  }

  $stateDeploymentId = Assert-GuidValue -Name 'manifest deploymentId' -Value ([string]$state.deploymentId)
  $stateTenantId = Assert-GuidValue -Name 'manifest tenantId' -Value ([string]$state.tenantId)
  $stateSubscriptionId = Assert-GuidValue -Name 'manifest subscriptionId' -Value ([string]$state.subscriptionId)
  if (-not $stateTenantId.Equals(([guid]$Context.tenantId).ToString(), [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Provenance manifest tenant does not match the active Azure subscription context.'
  }
  if (-not $stateSubscriptionId.Equals(([guid]$Context.id).ToString(), [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Provenance manifest subscription does not match the requested subscription.'
  }
  if ($state.resourceGroup -cne $ResourceGroup -or $state.workspaceName -cne $WorkspaceName) {
    throw 'Provenance manifest resource group or workspace does not match this request.'
  }
  if (-not ([string]$state.workspaceResourceId).Equals($WorkspaceResourceId, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Provenance manifest workspace resource ID does not match this request.'
  }

  $expectedIds = @($ruleDefinitions.Id)
  $actualIds = @($state.ruleIds)
  $expectedNames = @($ruleDefinitions.DisplayName)
  $actualNames = @($state.ruleDisplayNames)
  if ($actualIds.Count -ne $expectedIds.Count -or ($actualIds -join '|') -cne ($expectedIds -join '|')) {
    throw 'Provenance manifest rule IDs do not match this lab version.'
  }
  if ($actualNames.Count -ne $expectedNames.Count -or ($actualNames -join '|') -cne ($expectedNames -join '|')) {
    throw 'Provenance manifest rule display names do not match this lab version.'
  }

  $state.deploymentId = $stateDeploymentId
  return $state
}

function Assert-RuleInventory {
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [object[]]$Rules,

    [Parameter(Mandatory = $true)]
    [string]$DeploymentId,

    [Parameter(Mandatory = $true)]
    [bool]$ManifestVerified,

    [Parameter(Mandatory = $false)]
    [switch]$RequireAll,

    [Parameter(Mandatory = $false)]
    [Nullable[bool]]$ExpectedEnabled
  )

  foreach ($definition in $ruleDefinitions) {
    $idMatches = @($Rules | Where-Object {
      ([string]$_.name).Equals($definition.Id, [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($idMatches.Count -gt 1) {
      throw ('Sentinel returned duplicate resources for deterministic rule ID {0}.' -f $definition.Id)
    }

    $nameCollisions = @($Rules | Where-Object {
      ([string]$_.properties.displayName).Equals($definition.DisplayName, [System.StringComparison]::OrdinalIgnoreCase) -and
      -not ([string]$_.name).Equals($definition.Id, [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($nameCollisions.Count -gt 0) {
      throw ('A different Sentinel rule already uses display name "{0}". Refusing to shadow or delete it.' -f $definition.DisplayName)
    }

    if ($idMatches.Count -eq 0) {
      if ($RequireAll) {
        throw ('Deployment did not return expected deterministic rule ID {0}.' -f $definition.Id)
      }
      continue
    }

    if (-not $ManifestVerified) {
      throw ('Sentinel rule ID {0} already exists without the exact local provenance manifest. Refusing to adopt it.' -f $definition.Id)
    }

    $rule = $idMatches[0]
    if ([string]$rule.properties.displayName -cne $definition.DisplayName) {
      throw ('Rule ID {0} has an unexpected display name. Refusing to overwrite or delete it.' -f $definition.Id)
    }
    if ([string]$rule.kind -cne 'Scheduled') {
      throw ('Rule ID {0} has unexpected kind "{1}".' -f $definition.Id, $rule.kind)
    }

    $expectedSuffix = Get-OwnershipSuffix -DeploymentId $DeploymentId -RuleKey $definition.Key
    $description = [string]$rule.properties.description
    if (-not $description.EndsWith($expectedSuffix, [System.StringComparison]::Ordinal)) {
      throw ('Rule ID {0} is missing this deployment''s exact ownership suffix.' -f $definition.Id)
    }

    if ($null -ne $ExpectedEnabled) {
      if (-not ($rule.properties.PSObject.Properties.Name -contains 'enabled')) {
        throw ('Rule ID {0} did not return an enabled property.' -f $definition.Id)
      }
      $actualEnabled = [bool]$rule.properties.enabled
      $expectedEnabledValue = [bool]$ExpectedEnabled
      if ($actualEnabled -ne $expectedEnabledValue) {
        throw ('Rule ID {0} enabled state is {1}, expected {2}.' -f $definition.Id, $actualEnabled, $expectedEnabledValue)
      }
    }
  }
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
  throw 'Azure CLI was not found. Install Azure CLI and sign in before managing Sentinel rules.'
}
if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
  throw ('Sentinel template not found: {0}' -f $templatePath)
}

$ResourceGroup = Assert-NonEmpty -Name 'ResourceGroup' -Value $ResourceGroup
$WorkspaceName = Assert-NonEmpty -Name 'WorkspaceName' -Value $WorkspaceName
if ($ResourceGroup.Length -gt 90 -or $ResourceGroup -notmatch '^[A-Za-z0-9_.()\-]+$') {
  throw ('ResourceGroup has an invalid Azure resource-group name: "{0}".' -f $ResourceGroup)
}
if ($WorkspaceName.Length -gt 90 -or $WorkspaceName -notmatch '^[A-Za-z0-9][A-Za-z0-9\-]+[A-Za-z0-9]$') {
  throw ('WorkspaceName has an invalid Log Analytics workspace name: "{0}".' -f $WorkspaceName)
}
if ($Action -eq 'Remove' -and $EnableRules) {
  throw '-EnableRules is only valid with -Action Deploy.'
}

$accountArguments = @('account', 'show', '--only-show-errors', '-o', 'json')
if ($SubscriptionId) {
  $SubscriptionId = Assert-GuidValue -Name 'SubscriptionId' -Value $SubscriptionId
  $accountArguments += @('--subscription', $SubscriptionId)
}
$context = Invoke-AzCliJson -Arguments $accountArguments
$SubscriptionId = Assert-GuidValue -Name 'active subscription ID' -Value ([string]$context.id)
$null = Assert-GuidValue -Name 'active tenant ID' -Value ([string]$context.tenantId)

$encodedSubscription = [System.Uri]::EscapeDataString($SubscriptionId)
$encodedResourceGroup = [System.Uri]::EscapeDataString($ResourceGroup)
$encodedWorkspace = [System.Uri]::EscapeDataString($WorkspaceName)
$workspaceResourceId = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}' -f $SubscriptionId, $ResourceGroup, $WorkspaceName
$rulesUrl = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}/providers/Microsoft.SecurityInsights/alertRules?api-version={3}' -f $encodedSubscription, $encodedResourceGroup, $encodedWorkspace, $apiVersion

$state = Read-And-ValidateState -Context $context -WorkspaceResourceId $workspaceResourceId
$manifestVerified = $null -ne $state
if ($Action -eq 'Remove' -and -not $manifestVerified) {
  throw 'Exact provenance manifest is required for Sentinel cleanup. No rules were deleted.'
}
$deploymentId = if ($manifestVerified) { [string]$state.deploymentId } else { [guid]::NewGuid().ToString() }

$rules = @(Get-AllSentinelRules -InitialUrl $rulesUrl)
Assert-RuleInventory -Rules $rules -DeploymentId $deploymentId -ManifestVerified $manifestVerified

$existingOwnedRules = @($rules | Where-Object {
  $candidateName = [string]$_.name
  @($ruleDefinitions | Where-Object {
    $candidateName.Equals($_.Id, [System.StringComparison]::OrdinalIgnoreCase)
  }).Count -gt 0
})

Write-Host ''
Write-Host '=== Sentinel rule lifecycle plan ===' -ForegroundColor Cyan
Write-Host ('Action:          {0}' -f $Action)
Write-Host ('Subscription:    {0}' -f $SubscriptionId)
Write-Host ('Workspace:       {0}' -f $workspaceResourceId)
Write-Host ('State manifest:  {0} ({1})' -f ([System.IO.Path]::GetFullPath($StatePath)), $(if ($manifestVerified) { 'verified' } else { 'not created' }))
Write-Host ('Deployment ID:   {0}' -f $deploymentId)
Write-Host ('Deterministic IDs: {0}' -f (($ruleDefinitions.Id) -join ', '))
if ($Action -eq 'Deploy') {
  Write-Host ('Resulting state:  rules {0}' -f $(if ($EnableRules) { 'ENABLED by explicit request' } else { 'DISABLED (safe default)' }))
}
else {
  Write-Host ('Owned rules found: {0} of {1}' -f $existingOwnedRules.Count, $ruleDefinitions.Count)
}

if (-not $Execute) {
  Write-Host ''
  Write-Host 'Read-only preflight passed. No manifest or Sentinel rule was changed. Add -Execute to perform this plan.' -ForegroundColor Yellow
  return
}

$target = '{0}; rules {1}' -f $workspaceResourceId, (($ruleDefinitions.Id) -join ', ')
$operation = if ($Action -eq 'Deploy') {
  'Deploy the two exact owner-marked Sentinel rules'
}
else {
  'Delete only the exact owner-marked Sentinel rules'
}
if (-not $PSCmdlet.ShouldProcess($target, $operation)) {
  return
}

if ($Action -eq 'Deploy') {
  if (-not $manifestVerified) {
    $state = New-StateObject -DeploymentId $deploymentId -Context $context -WorkspaceResourceId $workspaceResourceId
    Save-State -State $state
    $manifestVerified = $true
  }

  $enabledValue = if ($EnableRules) { 'true' } else { 'false' }
  $deploymentName = 'nlzt-device-code-rules-{0}' -f $deploymentId.Substring(0, 8)
  $null = Invoke-AzCli -Arguments @(
    'deployment', 'group', 'create',
    '--name', $deploymentName,
    '--resource-group', $ResourceGroup,
    '--subscription', $SubscriptionId,
    '--template-file', $templatePath,
    '--parameters',
    ('workspaceName={0}' -f $WorkspaceName),
    ('deploymentId={0}' -f $deploymentId),
    ('enableRules={0}' -f $enabledValue),
    '--only-show-errors',
    '-o', 'json'
  )

  $rulesAfter = @(Get-AllSentinelRules -InitialUrl $rulesUrl)
  Assert-RuleInventory -Rules $rulesAfter -DeploymentId $deploymentId -ManifestVerified $true -RequireAll -ExpectedEnabled ([bool]$EnableRules)
  $state.status = 'deployed'
  $state.rulesEnabled = [bool]$EnableRules
  $state.lastVerifiedUtc = (Get-Date).ToUniversalTime().ToString('o')
  Save-State -State $state
  Write-Host ('Verified two exact owner-marked Sentinel rules; enabled={0}.' -f ([bool]$EnableRules)) -ForegroundColor Green
  return
}

foreach ($definition in $ruleDefinitions) {
  $match = @($existingOwnedRules | Where-Object {
    ([string]$_.name).Equals($definition.Id, [System.StringComparison]::OrdinalIgnoreCase)
  })
  if ($match.Count -eq 0) {
    Write-Host ('Rule {0} is already absent.' -f $definition.Id)
    continue
  }

  $deleteUrl = '{0}/{1}?api-version={2}' -f $rulesUrl.Split('?')[0], [System.Uri]::EscapeDataString($definition.Id), $apiVersion
  $null = Invoke-AzCli -Arguments @('rest', '--method', 'DELETE', '--url', $deleteUrl, '--only-show-errors')
  Write-Host ('Deleted exact owned Sentinel rule {0}.' -f $definition.Id)
}

$rulesAfterRemoval = @(Get-AllSentinelRules -InitialUrl $rulesUrl)
Assert-RuleInventory -Rules $rulesAfterRemoval -DeploymentId $deploymentId -ManifestVerified $true
$remainingIds = @($rulesAfterRemoval | Where-Object {
  $candidateName = [string]$_.name
  @($ruleDefinitions | Where-Object {
    $candidateName.Equals($_.Id, [System.StringComparison]::OrdinalIgnoreCase)
  }).Count -gt 0
})
if ($remainingIds.Count -ne 0) {
  throw 'Sentinel cleanup postcondition failed: one or more deterministic rule IDs still exist.'
}

$state.status = 'removed'
$state.rulesEnabled = $false
$state.lastVerifiedUtc = (Get-Date).ToUniversalTime().ToString('o')
Save-State -State $state
Write-Host 'Verified that both exact owned Sentinel rule IDs are absent.' -ForegroundColor Green
