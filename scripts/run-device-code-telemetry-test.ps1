#requires -Version 7.0
<#
.SYNOPSIS
  Generates Entra device-code sign-in telemetry for the signed-in lab user.

.DESCRIPTION
  This is not a phishing tool. It requests only the fixed OIDC scopes
  "openid profile", never accesses a workload, verifies that the approving
  identity matches the Azure CLI lab user, and discards the token response in
  memory immediately after that identity check.

  The script intentionally polls before approval so Entra can emit the 50199
  CmsiInterrupt-style event observed in device-code hunts. Use a dedicated,
  non-privileged lab account.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory = $false)]
  [string]$TenantId = $env:AZURE_TENANT_ID,

  [Parameter(Mandatory = $false)]
  [string]$ClientId = $env:DEVICE_CODE_LAB_CLIENT_ID,

  [Parameter(Mandatory = $false)]
  [ValidateRange(10, 180)]
  [int]$PreApprovalPollSeconds = 30,

  [Parameter(Mandatory = $false)]
  [ValidateRange(60, 900)]
  [int]$TimeoutSeconds = 300,

  [Parameter(Mandatory = $false)]
  [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$')]
  [string]$RunId = ('LAB-DC-{0}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH-mm-ssZ')),

  [Parameter(Mandatory = $false)]
  [switch]$SkipPrivilegedRoleCheck
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$fixedScope = 'openid profile'

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

function Get-CurrentGraphUser {
  return Invoke-AzCliJson -Arguments @(
    'rest',
    '--method', 'GET',
    '--url', 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName,displayName',
    '--only-show-errors',
    '-o', 'json'
  )
}

function Assert-NotPrivilegedAccount {
  param(
    [Parameter(Mandatory = $false)]
    [switch]$Skip
  )

  if ($Skip) {
    Write-Warning 'Skipping the active directory-role check by explicit request. Identity and tenant matching remain enforced.'
    return
  }

  $roleResponse = Invoke-AzCliJson -Arguments @(
    'rest',
    '--method', 'GET',
    '--url', 'https://graph.microsoft.com/v1.0/me/memberOf/microsoft.graph.directoryRole?$select=displayName',
    '--only-show-errors',
    '-o', 'json'
  )
  if (-not ($roleResponse.PSObject.Properties.Name -contains 'value')) {
    throw 'Microsoft Graph role response did not contain a value array.'
  }

  $assignedRoles = @(
    $roleResponse.value |
      Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.displayName) } |
      ForEach-Object { $_.displayName }
  )
  if ($assignedRoles.Count -gt 0) {
    throw ('Refusing to run with an account that has any active directory role. Detected: {0}.' -f ($assignedRoles -join ', '))
  }
}

function Get-OAuthErrorBody {
  param(
    [Parameter(Mandatory = $true)]
    [System.Management.Automation.ErrorRecord]$ErrorRecord
  )

  $message = $null
  if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
    $message = [string]$ErrorRecord.ErrorDetails.Message
  }
  elseif ($ErrorRecord.Exception.Response -and $ErrorRecord.Exception.Response.Content) {
    $message = [string]$ErrorRecord.Exception.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
  }
  elseif ($ErrorRecord.Exception.Response -and $ErrorRecord.Exception.Response.GetResponseStream) {
    $reader = [System.IO.StreamReader]::new($ErrorRecord.Exception.Response.GetResponseStream())
    try {
      $message = $reader.ReadToEnd()
    }
    finally {
      $reader.Dispose()
    }
  }

  if ([string]::IsNullOrWhiteSpace($message)) {
    throw 'Device-code token endpoint failed without a parseable OAuth error response.'
  }
  try {
    $parsed = $message | ConvertFrom-Json
  }
  catch {
    throw 'Device-code token endpoint returned a non-JSON error response.'
  }
  if ([string]::IsNullOrWhiteSpace([string]$parsed.error)) {
    throw 'Device-code token endpoint returned JSON without an OAuth error code.'
  }
  return [string]$parsed.error
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
    $tokenResponse = Invoke-RestMethod -Method Post -Uri $TokenEndpoint -Body $Body -ContentType 'application/x-www-form-urlencoded' -Headers $Headers
    return [pscustomobject]@{
      Complete = $true
      Error    = $null
      Token    = $tokenResponse
    }
  }
  catch {
    $oauthError = Get-OAuthErrorBody -ErrorRecord $_
    return [pscustomobject]@{
      Complete = $false
      Error    = $oauthError
      Token    = $null
    }
  }
}

function Update-PollInterval {
  param(
    [Parameter(Mandatory = $true)]
    [string]$OAuthError,

    [Parameter(Mandatory = $true)]
    [int]$CurrentInterval
  )

  if ($OAuthError -eq 'authorization_pending') {
    return $CurrentInterval
  }
  if ($OAuthError -eq 'slow_down') {
    return $CurrentInterval + 5
  }
  throw ('Device-code polling failed: {0}' -f $OAuthError)
}

function ConvertFrom-Base64Url {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Value
  )

  $normalized = $Value.Replace('-', '+').Replace('_', '/')
  switch ($normalized.Length % 4) {
    0 { }
    2 { $normalized += '==' }
    3 { $normalized += '=' }
    default { throw 'Issued ID token contained invalid base64url data.' }
  }
  return [System.Convert]::FromBase64String($normalized)
}

function Get-IdTokenClaims {
  param(
    [Parameter(Mandatory = $true)]
    [string]$IdToken
  )

  $segments = $IdToken.Split('.')
  if ($segments.Count -ne 3) {
    throw 'Token endpoint response contained a malformed ID token.'
  }
  try {
    $payloadBytes = ConvertFrom-Base64Url -Value $segments[1]
    $payloadJson = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
    return $payloadJson | ConvertFrom-Json
  }
  catch {
    throw ('Could not decode the issued ID-token identity claims: {0}' -f $_.Exception.Message)
  }
}

function Assert-IssuedIdentity {
  param(
    [Parameter(Mandatory = $true)]
    [object]$TokenResponse,

    [Parameter(Mandatory = $true)]
    [object]$ExpectedUser,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedTenantId,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedClientId
  )

  if (-not ($TokenResponse.PSObject.Properties.Name -contains 'id_token') -or [string]::IsNullOrWhiteSpace([string]$TokenResponse.id_token)) {
    throw 'Token endpoint completed without an ID token; approving-user identity could not be verified.'
  }
  $claims = Get-IdTokenClaims -IdToken ([string]$TokenResponse.id_token)
  $issuedTenantId = Assert-GuidValue -Name 'issued ID-token tenant claim' -Value ([string]$claims.tid)
  $issuedUserId = Assert-GuidValue -Name 'issued ID-token object claim' -Value ([string]$claims.oid)
  $expectedUserId = Assert-GuidValue -Name 'Azure CLI user object ID' -Value ([string]$ExpectedUser.id)

  if (-not $issuedTenantId.Equals($ExpectedTenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw ('Approving identity belongs to tenant {0}, not expected tenant {1}.' -f $issuedTenantId, $ExpectedTenantId)
  }
  if (-not $issuedUserId.Equals($expectedUserId, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw ('Approving identity object {0} does not match the verified Azure CLI lab user {1}.' -f $issuedUserId, $expectedUserId)
  }
  $audiences = @($claims.aud | ForEach-Object { [string]$_ })
  if ($audiences -notcontains $ExpectedClientId) {
    throw 'Issued ID-token audience does not match the exact lab client ID.'
  }
  $expectedIssuer = 'https://login.microsoftonline.com/{0}/v2.0' -f $ExpectedTenantId
  if (-not ([string]$claims.iss).Equals($expectedIssuer, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw ('Issued ID-token issuer "{0}" does not match "{1}".' -f $claims.iss, $expectedIssuer)
  }
}

function Complete-TokenResponse {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Poll,

    [Parameter(Mandatory = $true)]
    [object]$ExpectedUser,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedTenantId,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedClientId
  )

  try {
    Assert-IssuedIdentity -TokenResponse $Poll.Token -ExpectedUser $ExpectedUser -ExpectedTenantId $ExpectedTenantId -ExpectedClientId $ExpectedClientId
  }
  finally {
    $Poll.Token = $null
    [System.GC]::Collect()
  }
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
  throw 'Azure CLI was not found. Install Azure CLI and sign in with the dedicated lab user.'
}

$TenantId = Assert-GuidValue -Name 'TenantId' -Value $TenantId
$ClientId = Assert-GuidValue -Name 'ClientId' -Value $ClientId
$context = Invoke-AzCliJson -Arguments @('account', 'show', '--only-show-errors', '-o', 'json')
$contextTenantId = Assert-GuidValue -Name 'Azure CLI tenant ID' -Value ([string]$context.tenantId)
if (-not $contextTenantId.Equals($TenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
  throw ('Azure CLI is signed in to tenant {0}, not requested tenant {1}.' -f $contextTenantId, $TenantId)
}
if ($context.user -and $context.user.type -and [string]$context.user.type -ne 'user') {
  throw ('Azure CLI context is type "{0}", not an interactive user.' -f $context.user.type)
}

$graphUser = Get-CurrentGraphUser
$null = Assert-GuidValue -Name 'Azure CLI user object ID' -Value ([string]$graphUser.id)
if ([string]::IsNullOrWhiteSpace([string]$graphUser.userPrincipalName)) {
  throw 'Microsoft Graph did not return a user principal name for the Azure CLI identity.'
}
Assert-NotPrivilegedAccount -Skip:$SkipPrivilegedRoleCheck

$userAgent = 'NineLivesLab/1.0 (run:{0})' -f $RunId
$deviceEndpoint = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/devicecode' -f $TenantId
$tokenEndpoint = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $TenantId
$target = 'tenant {0}; client {1}; verified user object {2}; scopes "{3}"' -f $TenantId, $ClientId, $graphUser.id, $fixedScope
if (-not $PSCmdlet.ShouldProcess($target, 'Start lab-owned device-code telemetry test')) {
  return
}

Write-Host ''
Write-Host '=== Nine Lives device-code telemetry test ===' -ForegroundColor Cyan
Write-Host ('RunId:              {0}' -f $RunId)
Write-Host ('Azure CLI lab user: {0}' -f $graphUser.userPrincipalName)
Write-Host ('UserAgent:           {0}' -f $userAgent)
Write-Host ('Requested scopes:    {0}' -f $fixedScope)
Write-Host ''

$device = Invoke-RestMethod -Method Post -Uri $deviceEndpoint -Body @{
  client_id = $ClientId
  scope     = $fixedScope
} -ContentType 'application/x-www-form-urlencoded' -Headers @{ 'User-Agent' = $userAgent }

foreach ($requiredProperty in @('device_code', 'user_code', 'verification_uri', 'expires_in')) {
  if (-not ($device.PSObject.Properties.Name -contains $requiredProperty) -or [string]::IsNullOrWhiteSpace([string]$device.$requiredProperty)) {
    throw ('Device authorization endpoint response is missing required property "{0}".' -f $requiredProperty)
  }
}

$pollInterval = 5
if ($device.interval) {
  $pollInterval = [Math]::Max([int]$device.interval, 5)
}
$absoluteExpiry = (Get-Date).AddSeconds([int]$device.expires_in)
$pollBody = @{
  grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
  client_id   = $ClientId
  device_code = $device.device_code
}
$headers = @{ 'User-Agent' = $userAgent }

Write-Host 'Do not approve yet. The script first polls to improve visibility of the interrupt event.' -ForegroundColor Yellow
Write-Host ('Verification URL: {0}' -f $device.verification_uri)
Write-Host ('User code:        {0}' -f $device.user_code)
Write-Host ''

$preApprovalDeadline = (Get-Date).AddSeconds($PreApprovalPollSeconds)
if ($preApprovalDeadline -gt $absoluteExpiry) {
  $preApprovalDeadline = $absoluteExpiry
}
while ((Get-Date) -lt $preApprovalDeadline) {
  $poll = Invoke-TokenPoll -TokenEndpoint $tokenEndpoint -Body $pollBody -Headers $headers
  if ($poll.Complete) {
    Complete-TokenResponse -Poll $poll -ExpectedUser $graphUser -ExpectedTenantId $TenantId -ExpectedClientId $ClientId
    Write-Warning 'The verified lab sign-in completed before the approval prompt; the expected interrupt event may be absent.'
    Write-Host ('Completed early. RunId: {0}' -f $RunId) -ForegroundColor Green
    return
  }

  $pollInterval = Update-PollInterval -OAuthError $poll.Error -CurrentInterval $pollInterval
  Write-Host ('Polling before approval: {0}' -f $poll.Error)
  Start-Sleep -Seconds $pollInterval
}

if ((Get-Date) -ge $absoluteExpiry) {
  throw 'Device code expired before the approval phase.'
}

Write-Host ''
Write-Host 'Now approve with the same dedicated LAB account shown above.' -ForegroundColor Green
Write-Host ('Open: {0}' -f $device.verification_uri)
Write-Host ('Code: {0}' -f $device.user_code)
Write-Host ''

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
if ($deadline -gt $absoluteExpiry) {
  $deadline = $absoluteExpiry
}
while ((Get-Date) -lt $deadline) {
  $poll = Invoke-TokenPoll -TokenEndpoint $tokenEndpoint -Body $pollBody -Headers $headers
  if ($poll.Complete) {
    Complete-TokenResponse -Poll $poll -ExpectedUser $graphUser -ExpectedTenantId $TenantId -ExpectedClientId $ClientId
    Write-Host ''
    Write-Host 'Telemetry test completed. The approving identity matched the verified lab user; tokens were discarded without workload use.' -ForegroundColor Green
    Write-Host ('RunId: {0}' -f $RunId)
    Write-Host 'Wait for ingestion, then run scripts/check-device-code-telemetry.ps1 with this RunId and the exact app/user scope.'
    return
  }

  $pollInterval = Update-PollInterval -OAuthError $poll.Error -CurrentInterval $pollInterval
  Write-Host ('Waiting for approval: {0}' -f $poll.Error)
  Start-Sleep -Seconds $pollInterval
}

throw ('Timed out or the device code expired before verified approval. RunId: {0}' -f $RunId)
