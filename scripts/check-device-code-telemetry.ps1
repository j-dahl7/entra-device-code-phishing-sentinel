#requires -Version 7.0
<#
.SYNOPSIS
  Checks Sentinel/Log Analytics for a device-code telemetry test run.

.DESCRIPTION
  Wraps az monitor log-analytics query and optional Sentinel incident lookup so
  lab readers can confirm whether the generated device-code ceremony landed in
  SigninLogs and whether the scheduled analytics rules produced incidents.
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
  [string]$RunId,

  [Parameter(Mandatory = $false)]
  [string]$ClientId = $env:DEVICE_CODE_LAB_CLIENT_ID,

  [Parameter(Mandatory = $false)]
  [string]$UserPrincipalName = $env:DEVICE_CODE_LAB_USER,

  [Parameter(Mandatory = $false)]
  [ValidateRange(1, 48)]
  [int]$LookbackHours = 2
)

$ErrorActionPreference = 'Stop'

if (-not $WorkspaceId) {
  throw 'WorkspaceId was not provided. Set SENTINEL_WORKSPACE_ID or pass -WorkspaceId.'
}

function ConvertTo-SingleLineKql {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Query
  )

  return (($Query -split "`r?`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ' '
}

function Invoke-LogAnalyticsTable {
  param(
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceId,

    [Parameter(Mandatory = $true)]
    [string]$Query
  )

  $singleLineQuery = (ConvertTo-SingleLineKql -Query $Query).Replace('"', "'")
  $output = & az monitor log-analytics query "--workspace=$WorkspaceId" "--analytics-query=$singleLineQuery" -o table 2>&1
  $exitCode = $LASTEXITCODE
  $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"

  if ($exitCode -ne 0) {
    throw $text
  }

  if (-not [string]::IsNullOrWhiteSpace($text)) {
    Write-Host $text
  }
}

$scopeClauses = @()
if ($RunId) {
  $escapedRunId = $RunId.Replace("'", "''")
  $scopeClauses += "UserAgent contains '$escapedRunId'"
}

$identityClauses = @()
if ($ClientId) {
  $escapedClientId = $ClientId.Replace("'", "''")
  $identityClauses += "AppId == '$escapedClientId'"
}
if ($UserPrincipalName) {
  $escapedUserPrincipalName = $UserPrincipalName.Replace("'", "''")
  $identityClauses += "UserPrincipalName =~ '$escapedUserPrincipalName'"
}
if ($identityClauses.Count -gt 0) {
  $scopeClauses += '(' + ($identityClauses -join ' and ') + ')'
}

$scopeFilter = ''
if ($scopeClauses.Count -gt 0) {
  $scopeFilter = '| where ' + ($scopeClauses -join ' or ')
}

Write-Host ''
Write-Host '=== Query scope ===' -ForegroundColor Cyan
if ($RunId) {
  Write-Host ('RunId user-agent match: {0}' -f $RunId)
}
if ($ClientId -or $UserPrincipalName) {
  Write-Host ('Lab identity fallback: AppId="{0}", UserPrincipalName="{1}"' -f $ClientId, $UserPrincipalName)
  Write-Host 'The browser approval row may keep the browser user-agent instead of the script RunId, so the checker also scopes to the lab app/user when provided.' -ForegroundColor Yellow
}

$signinQuery = @"
SigninLogs
| where TimeGenerated > ago(${LookbackHours}h)
$scopeFilter
| extend AuthProtocol = tostring(column_ifexists("AuthenticationProtocol", ""))
| extend Result = tostring(ResultType)
| where AuthProtocol =~ "deviceCode" or ResultDescription has "device code" or Result in ("50199", "0") or UserAgent has "NineLivesLab/1.0"
| summarize Events=count(), Results=make_set(ResultType), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated),
    Apps=make_set(AppDisplayName, 10), AppIds=make_set(AppId, 10),
    Users=make_set(UserPrincipalName, 10), IPs=make_set(IPAddress, 10),
    UserAgents=make_set(UserAgent, 5)
    by CorrelationId
| order by LastSeen desc
"@

Write-Host ''
Write-Host '=== SigninLogs telemetry ===' -ForegroundColor Cyan
Invoke-LogAnalyticsTable -WorkspaceId $WorkspaceId -Query $signinQuery

$rule1Query = @"
let Lookback = ${LookbackHours}h;
let Window = 5m;
let Interrupts =
    SigninLogs
    | where TimeGenerated > ago(Lookback)
    $scopeFilter
    | extend Result = tostring(ResultType)
    | where Result == "50199" or ResultDescription has "50199"
    | project InterruptTime = TimeGenerated, UserPrincipalName, CorrelationId, SessionId=tostring(column_ifexists("SessionId", "")), IPAddress, AppDisplayName, AppId, UserAgent;
let Successes =
    SigninLogs
    | where TimeGenerated > ago(Lookback)
    $scopeFilter
    | extend Result = tostring(ResultType)
    | where Result == "0"
    | project SuccessTime = TimeGenerated, UserPrincipalName, CorrelationId, SessionId=tostring(column_ifexists("SessionId", "")), SuccessIP=IPAddress, SuccessApp=AppDisplayName, SuccessAppId=AppId, SuccessUserAgent=UserAgent;
Interrupts
| join kind=inner Successes on UserPrincipalName, CorrelationId
| where SuccessTime between (InterruptTime .. InterruptTime + Window)
| project TimeGenerated = SuccessTime, InterruptTime, UserPrincipalName, AppDisplayName, AppId, IPAddress, SuccessIP, CorrelationId, SessionId
| order by TimeGenerated desc
"@

Write-Host ''
Write-Host '=== Rule 1 correlation preview ===' -ForegroundColor Cyan
Invoke-LogAnalyticsTable -WorkspaceId $WorkspaceId -Query $rule1Query

$rule2Query = @"
let ApprovedDeviceCodeApps = dynamic([
    "Microsoft Azure CLI",
    "Azure CLI",
    "Microsoft Azure PowerShell",
    "Microsoft Teams Rooms"
]);
let ApprovedDeviceCodeAppIds = dynamic([
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "1950a258-227b-4e31-a9cf-717495945fc2"
]);
let Lookback = ${LookbackHours}h;
let Window = 5m;
let DirectDeviceCodeEvents =
    SigninLogs
    | where TimeGenerated > ago(Lookback)
    $scopeFilter
    | extend AuthProtocol = tostring(column_ifexists("AuthenticationProtocol", ""))
    | where AuthProtocol =~ "deviceCode" or ResultDescription has "device code" or UserAgent has "NineLivesLab/1.0"
    | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, AppId;
let Interrupts =
    SigninLogs
    | where TimeGenerated > ago(Lookback)
    $scopeFilter
    | extend Result = tostring(ResultType)
    | where Result == "50199" or ResultDescription has "50199"
    | project InterruptTime = TimeGenerated, UserPrincipalName, CorrelationId;
let CorrelatedSuccesses =
    SigninLogs
    | where TimeGenerated > ago(Lookback)
    $scopeFilter
    | extend Result = tostring(ResultType)
    | where Result == "0"
    | project SuccessTime = TimeGenerated, UserPrincipalName, CorrelationId,
        IPAddress, AppDisplayName, AppId;
let DeviceCodeLikeEvents =
    Interrupts
    | join kind=inner CorrelatedSuccesses on UserPrincipalName, CorrelationId
    | where SuccessTime between (InterruptTime .. InterruptTime + Window)
    | project TimeGenerated = SuccessTime, UserPrincipalName, IPAddress, AppDisplayName, AppId;
union DirectDeviceCodeEvents, DeviceCodeLikeEvents
| where AppDisplayName !in~ (ApprovedDeviceCodeApps)
    and AppId !in~ (ApprovedDeviceCodeAppIds)
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated),
    Attempts=count(), Users=dcount(UserPrincipalName), IPs=dcount(IPAddress),
    SampleUsers=make_set(UserPrincipalName, 10), SampleIPs=make_set(IPAddress, 10)
    by AppDisplayName, AppId
| project TimeGenerated = LastSeen, FirstSeen, LastSeen, AppDisplayName, AppId, Attempts, Users, IPs, SampleUsers, SampleIPs
| order by Attempts desc
"@

Write-Host ''
Write-Host '=== Rule 2 unapproved-client preview ===' -ForegroundColor Cyan
Invoke-LogAnalyticsTable -WorkspaceId $WorkspaceId -Query $rule2Query

if ($ResourceGroup -and $WorkspaceName) {
  Write-Host ''
  Write-Host '=== Recent Sentinel incidents with Device Code in the title ===' -ForegroundColor Cyan
  Write-Host 'Incident lookup is advisory. SigninLogs and rule preview hits can appear before scheduled analytics create incidents.' -ForegroundColor Yellow
  $incidentCutoff = (Get-Date).ToUniversalTime().AddHours(-1 * $LookbackHours).ToString('yyyy-MM-ddTHH:mm:ssZ')

  $incidentOutput = & az sentinel incident list `
    --resource-group $ResourceGroup `
    --workspace-name $WorkspaceName `
    --query "[?contains(title, 'Device Code') && createdTimeUtc >= '$incidentCutoff'].{title:title,severity:severity,status:status,createdTimeUtc:createdTimeUtc,incidentNumber:incidentNumber}" `
    -o json

  if ($LASTEXITCODE -ne 0) {
    throw 'Sentinel incident lookup failed.'
  }

  $incidentText = ($incidentOutput | ForEach-Object { $_.ToString() }) -join "`n"
  $incidents = @()
  if (-not [string]::IsNullOrWhiteSpace($incidentText)) {
    $incidents = @($incidentText | ConvertFrom-Json)
  }

  if ($incidents.Count -eq 0) {
    Write-Host 'No matching Sentinel incidents returned yet. This does not invalidate the SigninLogs telemetry or rule correlation preview above.' -ForegroundColor Yellow
  }
  else {
    $incidents | Format-Table -AutoSize
  }
}
else {
  Write-Host ''
  Write-Host 'Skipping Sentinel incident lookup. Set SENTINEL_RESOURCE_GROUP and SENTINEL_WORKSPACE_NAME to enable it.' -ForegroundColor Yellow
}
