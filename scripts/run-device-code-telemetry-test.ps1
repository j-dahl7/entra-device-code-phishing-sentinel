#requires -Version 7.0
<#
.SYNOPSIS
  Generates real Entra device-code sign-in telemetry against your own lab account.

.DESCRIPTION
  This is NOT a phishing tool. It does not capture tokens, does not access mail
  or any other resource, and only signs in the running user against their own
  tenant. Tokens are discarded in memory immediately after issuance.

  The script intentionally polls before approval so Entra can emit the 50199
  CmsiInterrupt-style event observed in device-code hunts, then continues
  until the lab user approves the sign-in. Use a lab-only account.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory = $false)]
  [string]$TenantId = $env:AZURE_TENANT_ID,

  [Parameter(Mandatory = $false)]
  [string]$ClientId = $env:DEVICE_CODE_LAB_CLIENT_ID,

  [Parameter(Mandatory = $false)]
  [string]$Scope = 'openid profile',

  [Parameter(Mandatory = $false)]
  [ValidateRange(10, 180)]
  [int]$PreApprovalPollSeconds = 30,

  [Parameter(Mandatory = $false)]
  [ValidateRange(60, 900)]
  [int]$TimeoutSeconds = 300,

  [Parameter(Mandatory = $false)]
  [string]$RunId = ('LAB-DC-{0}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH-mm-ssZ')),

  [Parameter(Mandatory = $false)]
  [switch]$SkipPrivilegedRoleCheck
)

$ErrorActionPreference = 'Stop'

function Invoke-AzCliJson {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  $output = & az @Arguments 2>$null
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($output -join ''))) {
    return $null
  }

  return ($output -join "`n") | ConvertFrom-Json
}

function Get-CurrentAzContext {
  Invoke-AzCliJson -Arguments @('account', 'show', '-o', 'json')
}

function Assert-NotPrivilegedAccount {
  param(
    [Parameter(Mandatory = $false)]
    [switch]$Skip
  )

  if ($Skip) {
    Write-Warning 'Skipping privileged-role check because -SkipPrivilegedRoleCheck was supplied.'
    return
  }

  $roleResponse = Invoke-AzCliJson -Arguments @(
    'rest',
    '--method', 'GET',
    '--url', 'https://graph.microsoft.com/v1.0/me/memberOf/microsoft.graph.directoryRole?$select=displayName',
    '-o', 'json'
  )

  if (-not $roleResponse -or -not ($roleResponse.PSObject.Properties.Name -contains 'value')) {
    throw 'Could not verify the signed-in user directory roles. Rerun with Graph access available, or explicitly pass -SkipPrivilegedRoleCheck for a lab-only non-admin account.'
  }

  $blockedRoles = @(
    'Global Administrator',
    'Privileged Role Administrator',
    'Security Administrator',
    'Application Administrator',
    'Cloud Application Administrator'
  )

  $assignedBlockedRoles = @($roleResponse.value | Where-Object { $blockedRoles -contains $_.displayName } | ForEach-Object { $_.displayName })
  if ($assignedBlockedRoles.Count -gt 0) {
    throw ('Refusing to run device-code telemetry test with a privileged account. Detected role(s): {0}. Use a non-privileged lab user.' -f ($assignedBlockedRoles -join ', '))
  }
}

function Invoke-TokenPoll {
  param(
    [Parameter(Mandatory = $true)]
    [string]$TokenEndpoint,

    [Parameter(Mandatory = $true)]
    [hashtable]$Body,

    [Parameter(Mandatory = $true)]
    [hashtable]$Headers
  )

  try {
    $token = Invoke-RestMethod -Method Post -Uri $TokenEndpoint -Body $Body -ContentType 'application/x-www-form-urlencoded' -Headers $Headers
    return [pscustomobject]@{
      Complete = $true
      Error    = $null
      Token    = $token
    }
  }
  catch {
    $message = $null
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
      $message = $_.ErrorDetails.Message
    }
    elseif ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
      $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
      $message = $reader.ReadToEnd()
    }

    $errorCode = 'unknown'
    if ($message) {
      try {
        $parsed = $message | ConvertFrom-Json
        $errorCode = $parsed.error
      }
      catch {
        $errorCode = $message
      }
    }

    return [pscustomobject]@{
      Complete = $false
      Error    = $errorCode
      Token    = $null
    }
  }
}

$context = Get-CurrentAzContext
if (-not $TenantId) {
  if (-not $context -or -not $context.tenantId) {
    throw 'TenantId was not provided and az account show did not return a tenant. Set AZURE_TENANT_ID or pass -TenantId.'
  }
  $TenantId = $context.tenantId
}

if (-not $ClientId) {
  throw 'ClientId was not provided. Deploy infra/lab-app.bicep or set DEVICE_CODE_LAB_CLIENT_ID to the lab public client application ID.'
}

if ($context -and $context.user -and $context.user.name) {
  Write-Host ('Signed-in Azure CLI user: {0}' -f $context.user.name)
}

Assert-NotPrivilegedAccount -Skip:$SkipPrivilegedRoleCheck

$userAgent = 'NineLivesLab/1.0 (run:{0})' -f $RunId
$deviceEndpoint = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/devicecode' -f $TenantId
$tokenEndpoint = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $TenantId

$target = 'Generate Entra device-code telemetry in tenant {0} using client {1}. Tokens will be discarded.' -f $TenantId, $ClientId
if (-not $PSCmdlet.ShouldProcess($target, 'Start lab-owned device-code telemetry test')) {
  return
}

Write-Host ''
Write-Host '=== Nine Lives device-code telemetry test ===' -ForegroundColor Cyan
Write-Host ('RunId:     {0}' -f $RunId)
Write-Host ('UserAgent: {0}' -f $userAgent)
Write-Host ''

$device = Invoke-RestMethod `
  -Method Post `
  -Uri $deviceEndpoint `
  -Body @{ client_id = $ClientId; scope = $Scope } `
  -ContentType 'application/x-www-form-urlencoded' `
  -Headers @{ 'User-Agent' = $userAgent }

$pollInterval = [Math]::Max([int]$device.interval, 5)
$pollBody = @{
  grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
  client_id   = $ClientId
  device_code = $device.device_code
}
$headers = @{ 'User-Agent' = $userAgent }

Write-Host 'Do NOT approve yet. The script will poll first to generate 50199/CmsiInterrupt-style telemetry.' -ForegroundColor Yellow
Write-Host ('Verification URL: {0}' -f $device.verification_uri)
Write-Host ('User code:        {0}' -f $device.user_code)
Write-Host ''

$preApprovalDeadline = (Get-Date).AddSeconds($PreApprovalPollSeconds)
while ((Get-Date) -lt $preApprovalDeadline) {
  $poll = Invoke-TokenPoll -TokenEndpoint $tokenEndpoint -Body $pollBody -Headers $headers
  if ($poll.Complete) {
    Write-Warning 'The sign-in completed before the approval prompt. You may not get the expected 50199 interrupt event.'
    $poll.Token = $null
    [System.GC]::Collect()
    Write-Host ('Completed early. RunId: {0}' -f $RunId) -ForegroundColor Green
    return
  }

  Write-Host ('Polling before approval: {0}' -f $poll.Error)
  Start-Sleep -Seconds $pollInterval
}

Write-Host ''
Write-Host 'Now approve the sign-in with your LAB account only.' -ForegroundColor Green
Write-Host ('Open: {0}' -f $device.verification_uri)
Write-Host ('Code: {0}' -f $device.user_code)
Write-Host ''

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $deadline) {
  $poll = Invoke-TokenPoll -TokenEndpoint $tokenEndpoint -Body $pollBody -Headers $headers
  if ($poll.Complete) {
    $poll.Token = $null
    [System.GC]::Collect()
    Write-Host ''
    Write-Host 'Telemetry test completed. Tokens were discarded without use.' -ForegroundColor Green
    Write-Host ('RunId: {0}' -f $RunId)
    Write-Host 'Wait for Entra/Sentinel ingestion, then run scripts/check-device-code-telemetry.ps1 with the same RunId.'
    return
  }

  if ($poll.Error -and $poll.Error -notin @('authorization_pending', 'slow_down')) {
    throw ('Device-code polling failed: {0}' -f $poll.Error)
  }

  Write-Host ('Waiting for approval: {0}' -f $poll.Error)
  Start-Sleep -Seconds $pollInterval
}

throw ('Timed out waiting for approval after {0} seconds. RunId: {1}' -f $TimeoutSeconds, $RunId)
