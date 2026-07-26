#requires -Version 7.0
<#
.SYNOPSIS
  Checks Log Analytics and optional Sentinel incidents for one lab identity.

.DESCRIPTION
  Runs a raw SigninLogs summary plus scoped previews derived from the exact
  tracked Sentinel KQL files. The checker requires the immutable lab client ID
  and the lab user UPN, so it never falls back to an unscoped tenant-wide hunt.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$WorkspaceId = $env:SENTINEL_WORKSPACE_ID,

  [Parameter(Mandatory = $false)]
  [string]$ResourceGroup = $env:SENTINEL_RESOURCE_GROUP,

  [Parameter(Mandatory = $false)]
  [string]$WorkspaceName = $env:SENTINEL_WORKSPACE_NAME,

  [Parameter(Mandatory = $false)]
  [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$')]
  [string]$RunId,

  [Parameter(Mandatory = $false)]
  [string]$ClientId = $env:DEVICE_CODE_LAB_CLIENT_ID,

  [Parameter(Mandatory = $false)]
  [ValidatePattern('^[^\r\n]{3,320}$')]
  [string]$UserPrincipalName = $env:DEVICE_CODE_LAB_USER,

  [Parameter(Mandatory = $false)]
  [ValidateRange(1, 48)]
  [int]$LookbackHours = 2
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$ruleIds = @(
  '45543375-c81a-56ab-b020-b3cc3bcf652e',
  '0d879be9-2084-5bee-bf5b-8effbf4d8c64'
)
$labRoot = Split-Path -Parent $PSScriptRoot

function Assert-GuidValue {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $false)]
    [string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    throw ('{0} is required.' -f $Name)
  }
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

function Escape-KqlString {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Value
  )
  return $Value.Replace("'", "''")
}

function Invoke-LogAnalyticsTable {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Query
  )

  # Keep line breaks intact: the tracked KQL contains // comments, which would
  # comment out the rest of a query if mechanically flattened to one line.
  $text = Invoke-AzCli -Arguments @(
    'monitor', 'log-analytics', 'query',
    '--workspace', $WorkspaceId,
    '--analytics-query', $Query,
    '--only-show-errors',
    '-o', 'table'
  )
  if (-not [string]::IsNullOrWhiteSpace($text)) {
    Write-Host $text
  }
}

function Get-ScopedRuleQuery {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [string]$ScopePredicate
  )

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw ('Tracked Sentinel KQL file not found: {0}' -f $Path)
  }
  $source = Get-Content -LiteralPath $Path -Raw
  $lookbackMatches = [regex]::Matches($source, '(?m)^let Lookback = (15m|1h);\r?$')
  if ($lookbackMatches.Count -ne 1) {
    throw ('Expected exactly one supported Lookback declaration in {0}; found {1}.' -f $Path, $lookbackMatches.Count)
  }

  $source = [regex]::Replace($source, '(?m)^let Lookback = (15m|1h);\r?$', ('let Lookback = {0}h;' -f $LookbackHours))
  $source = [regex]::Replace($source, '\bSigninLogs\b', 'ScopedSigninLogs')
  $prefix = @(
    'let ScopedSigninLogs = SigninLogs',
    ('| where TimeGenerated > ago({0}h)' -f $LookbackHours),
    ('| where {0};' -f $ScopePredicate)
  ) -join [Environment]::NewLine
  return $prefix + [Environment]::NewLine + $source
}

function Get-AllIncidentPages {
  param(
    [Parameter(Mandatory = $true)]
    [string]$InitialUrl
  )

  $incidents = [System.Collections.Generic.List[object]]::new()
  $nextUrl = $InitialUrl
  while ($nextUrl) {
    if (-not $nextUrl.StartsWith('https://management.azure.com/', [System.StringComparison]::OrdinalIgnoreCase)) {
      throw ('Sentinel returned an unexpected incident pagination URL: {0}' -f $nextUrl)
    }
    $page = Invoke-AzCliJson -Arguments @('rest', '--method', 'GET', '--url', $nextUrl, '--only-show-errors', '-o', 'json')
    if (-not ($page.PSObject.Properties.Name -contains 'value')) {
      throw 'Sentinel incident response did not contain a value array.'
    }
    foreach ($incident in @($page.value)) {
      $incidents.Add($incident)
    }
    $nextUrl = $null
    if ($page.PSObject.Properties.Name -contains 'nextLink' -and $page.nextLink) {
      $nextUrl = [string]$page.nextLink
    }
  }
  return @($incidents)
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
  throw 'Azure CLI was not found.'
}

$WorkspaceId = Assert-GuidValue -Name 'WorkspaceId' -Value $WorkspaceId
$ClientId = Assert-GuidValue -Name 'ClientId' -Value $ClientId
if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
  throw 'UserPrincipalName is required. Set DEVICE_CODE_LAB_USER or pass the exact lab user UPN.'
}
if (($ResourceGroup -and -not $WorkspaceName) -or ($WorkspaceName -and -not $ResourceGroup)) {
  throw 'ResourceGroup and WorkspaceName must be supplied together for exact incident lookup.'
}

$escapedClientId = Escape-KqlString -Value $ClientId
$escapedUserPrincipalName = Escape-KqlString -Value $UserPrincipalName
$identityPredicate = "(AppId == '$escapedClientId' and UserPrincipalName =~ '$escapedUserPrincipalName')"
$scopePredicate = $identityPredicate
if ($RunId) {
  $escapedRunId = Escape-KqlString -Value $RunId
  $scopePredicate = "(UserAgent contains '$escapedRunId' or $identityPredicate)"
}

Write-Host ''
Write-Host '=== Query scope ===' -ForegroundColor Cyan
Write-Host ('Workspace ID: {0}' -f $WorkspaceId)
Write-Host ('Lab identity: AppId="{0}", UserPrincipalName="{1}"' -f $ClientId, $UserPrincipalName)
if ($RunId) {
  Write-Host ('RunId user-agent fallback: {0}' -f $RunId)
}

$signinQuery = @(
  'SigninLogs',
  ('| where TimeGenerated > ago({0}h)' -f $LookbackHours),
  ('| where {0}' -f $scopePredicate),
  '| extend AuthProtocol = tostring(column_ifexists("AuthenticationProtocol", ""))',
  '| extend Result = tostring(ResultType)',
  '| where AuthProtocol =~ "deviceCode" or ResultDescription has "device code" or Result in ("50199", "0")',
  '| summarize Events=count(), Results=make_set(ResultType), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated),',
  '    Apps=make_set(AppDisplayName, 10), AppIds=make_set(AppId, 10),',
  '    Users=make_set(UserPrincipalName, 10), IPs=make_set(IPAddress, 10),',
  '    UserAgents=make_set(UserAgent, 5)',
  '    by CorrelationId',
  '| order by LastSeen desc'
) -join [Environment]::NewLine

Write-Host ''
Write-Host '=== SigninLogs telemetry ===' -ForegroundColor Cyan
Invoke-LogAnalyticsTable -Query $signinQuery

$rule1Path = Join-Path $labRoot 'kql/sentinel/01-device-code-50199-to-success.kql'
$rule1Query = Get-ScopedRuleQuery -Path $rule1Path -ScopePredicate $scopePredicate
Write-Host ''
Write-Host '=== Exact Rule 1 logic, scoped to this lab run ===' -ForegroundColor Cyan
Invoke-LogAnalyticsTable -Query $rule1Query

$rule2Path = Join-Path $labRoot 'kql/sentinel/02-unapproved-device-code-client.kql'
$rule2Query = Get-ScopedRuleQuery -Path $rule2Path -ScopePredicate $scopePredicate
Write-Host ''
Write-Host '=== Exact Rule 2 logic, scoped to this lab run ===' -ForegroundColor Cyan
Invoke-LogAnalyticsTable -Query $rule2Query

if ($ResourceGroup -and $WorkspaceName) {
  $context = Invoke-AzCliJson -Arguments @('account', 'show', '--only-show-errors', '-o', 'json')
  $subscriptionId = Assert-GuidValue -Name 'active subscription ID' -Value ([string]$context.id)
  $encodedSubscription = [System.Uri]::EscapeDataString($subscriptionId)
  $encodedResourceGroup = [System.Uri]::EscapeDataString($ResourceGroup)
  $encodedWorkspace = [System.Uri]::EscapeDataString($WorkspaceName)
  $incidentsUrl = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}/providers/Microsoft.SecurityInsights/incidents?api-version=2024-09-01' -f $encodedSubscription, $encodedResourceGroup, $encodedWorkspace
  $incidentCutoff = (Get-Date).ToUniversalTime().AddHours(-1 * $LookbackHours)
  $incidents = @(Get-AllIncidentPages -InitialUrl $incidentsUrl)
  $matchingIncidents = @(
    $incidents | Where-Object {
      $created = [datetime]::MinValue
      $createdOk = [datetime]::TryParse([string]$_.properties.createdTimeUtc, [ref]$created)
      $relatedIds = @($_.properties.relatedAnalyticRuleIds)
      $related = @($relatedIds | Where-Object {
        $candidate = [string]$_
        @($ruleIds | Where-Object {
          $candidate.EndsWith(('/alertRules/{0}' -f $_), [System.StringComparison]::OrdinalIgnoreCase)
        }).Count -gt 0
      }).Count -gt 0
      $createdOk -and $created.ToUniversalTime() -ge $incidentCutoff -and $related
    }
  )

  Write-Host ''
  Write-Host '=== Incidents linked to the exact deterministic rule IDs ===' -ForegroundColor Cyan
  if ($matchingIncidents.Count -eq 0) {
    Write-Host 'No related incidents returned yet. Empty incident output does not invalidate raw telemetry or preview hits.' -ForegroundColor Yellow
  }
  else {
    $matchingIncidents | ForEach-Object {
      [pscustomobject]@{
        IncidentNumber = $_.properties.incidentNumber
        Title          = $_.properties.title
        Severity       = $_.properties.severity
        Status         = $_.properties.status
        CreatedTimeUtc = $_.properties.createdTimeUtc
      }
    } | Format-Table -AutoSize
  }
}
else {
  Write-Host ''
  Write-Host 'Exact incident lookup skipped. Supply both ResourceGroup and WorkspaceName to enable it.' -ForegroundColor Yellow
}
