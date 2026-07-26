#requires -Version 7.0
<#
.SYNOPSIS
  Preflights and removes the exact Entra application and service principal
  created by the device-code telemetry lab.

.DESCRIPTION
  Cleanup requires the immutable tenant ID, client ID, application object ID,
  service-principal object ID, and deployment-specific uniqueName returned by
  infra/lab-app.bicep. Every object and ownership marker is validated before
  the first delete. The script never discovers a deletion target by display
  name and never deletes user objects, because the template does not create
  users.

  The default run is read-only. -Execute authorizes deletion, and PowerShell
  ShouldProcess still supports -WhatIf and -Confirm.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory = $false)]
  [string]$TenantId = $env:AZURE_TENANT_ID,

  [Parameter(Mandatory = $false)]
  [string]$ClientId = $env:DEVICE_CODE_LAB_CLIENT_ID,

  [Parameter(Mandatory = $false)]
  [string]$AppObjectId = $env:DEVICE_CODE_LAB_APP_OBJECT_ID,

  [Parameter(Mandatory = $false)]
  [string]$ServicePrincipalObjectId = $env:DEVICE_CODE_LAB_SP_OBJECT_ID,

  [Parameter(Mandatory = $false)]
  [string]$UniqueName = $env:DEVICE_CODE_LAB_UNIQUE_NAME,

  [Parameter(Mandatory = $false)]
  [switch]$Execute
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$ownerTag = 'NineLives.Owner:EntraDeviceCodePhishingSentinel:v1'
$expectedApplicationTags = @()
$applicationSelect = 'id,appId,displayName,uniqueName,tags,signInAudience,isFallbackPublicClient,publicClient,passwordCredentials,keyCredentials'
$servicePrincipalSelect = 'id,appId,displayName,tags,servicePrincipalType,appOwnerOrganizationId'

function Assert-GuidValue {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $false)]
    [string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    throw ('{0} is required. Use the exact value returned by the lab deployment.' -f $Name)
  }

  $parsed = [guid]::Empty
  if (-not [guid]::TryParse($Value, [ref]$parsed) -or $parsed -eq [guid]::Empty) {
    throw ('{0} must be a non-empty GUID; received "{1}".' -f $Name, $Value)
  }

  return $parsed.ToString()
}

function Assert-LabUniqueName {
  param(
    [Parameter(Mandatory = $false)]
    [string]$Value
  )

  $prefix = 'nine-lives-device-code-telemetry-lab-'
  if ([string]::IsNullOrWhiteSpace($Value) -or -not $Value.StartsWith($prefix, [System.StringComparison]::Ordinal)) {
    throw ('UniqueName must use the exact lab prefix "{0}" followed by a GUID.' -f $prefix)
  }
  $suffix = $Value.Substring($prefix.Length)
  $null = Assert-GuidValue -Name 'UniqueName GUID suffix' -Value $suffix
  return $Value
}

function Invoke-AzCli {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  $output = & az @Arguments 2>&1
  $exitCode = $LASTEXITCODE
  $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"

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

function New-GraphUrl {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('applications', 'servicePrincipals')]
    [string]$Collection,

    [Parameter(Mandatory = $true)]
    [string]$ObjectId,

    [Parameter(Mandatory = $false)]
    [string]$Select
  )

  $encodedId = [System.Uri]::EscapeDataString($ObjectId)
  $url = 'https://graph.microsoft.com/v1.0/{0}/{1}' -f $Collection, $encodedId
  if ($Select) {
    $url = '{0}?{1}={2}' -f $url, [System.Uri]::EscapeDataString('$select'), [System.Uri]::EscapeDataString($Select)
  }
  return $url
}

function Get-GraphObjectById {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('applications', 'servicePrincipals')]
    [string]$Collection,

    [Parameter(Mandatory = $true)]
    [string]$ObjectId,

    [Parameter(Mandatory = $true)]
    [string]$Select
  )

  $url = New-GraphUrl -Collection $Collection -ObjectId $ObjectId -Select $Select
  return Invoke-AzCliJson -Arguments @('rest', '--method', 'GET', '--url', $url, '--only-show-errors', '-o', 'json')
}

function Assert-ExactId {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Kind,

    [Parameter(Mandatory = $true)]
    [string]$Expected,

    [Parameter(Mandatory = $false)]
    [string]$Actual
  )

  if ([string]::IsNullOrWhiteSpace($Actual) -or -not $Actual.Equals($Expected, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw ('{0} ID mismatch. Expected {1}; Microsoft Graph returned {2}.' -f $Kind, $Expected, $Actual)
  }
}

function Assert-OwnershipTags {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Kind,

    [Parameter(Mandatory = $true)]
    [object]$Object
  )

  $actualTags = @($Object.tags)
  foreach ($expectedTag in $expectedApplicationTags) {
    if ($actualTags -notcontains $expectedTag) {
      throw ('Refusing cleanup: {0} {1} is missing exact ownership tag "{2}".' -f $Kind, $Object.id, $expectedTag)
    }
  }
}

function Remove-GraphObjectById {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('applications', 'servicePrincipals')]
    [string]$Collection,

    [Parameter(Mandatory = $true)]
    [string]$ObjectId
  )

  $url = New-GraphUrl -Collection $Collection -ObjectId $ObjectId
  $null = Invoke-AzCli -Arguments @('rest', '--method', 'DELETE', '--url', $url, '--only-show-errors')
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
  throw 'Azure CLI was not found. Install Azure CLI and sign in to the exact lab tenant before cleanup.'
}

$TenantId = Assert-GuidValue -Name 'TenantId' -Value $TenantId
$ClientId = Assert-GuidValue -Name 'ClientId' -Value $ClientId
$AppObjectId = Assert-GuidValue -Name 'AppObjectId' -Value $AppObjectId
$ServicePrincipalObjectId = Assert-GuidValue -Name 'ServicePrincipalObjectId' -Value $ServicePrincipalObjectId
$UniqueName = Assert-LabUniqueName -Value $UniqueName
$expectedApplicationTags = @(
  $ownerTag
  ('NineLives.UniqueName:{0}' -f $UniqueName)
  'NineLivesZeroTrust'
  'Lab'
  'DeviceCodeTelemetry'
  'NoSecrets'
)

$context = Invoke-AzCliJson -Arguments @('account', 'show', '--only-show-errors', '-o', 'json')
if (-not $context.tenantId) {
  throw 'Azure CLI account context did not include a tenant ID.'
}
$activeTenantId = Assert-GuidValue -Name 'active Azure CLI tenant ID' -Value ([string]$context.tenantId)
if (-not $activeTenantId.Equals($TenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
  throw ('Azure CLI is signed in to tenant {0}, not requested tenant {1}. No deletes were attempted.' -f $activeTenantId, $TenantId)
}

# Two-phase cleanup: resolve and validate every immutable object before any DELETE.
$application = Get-GraphObjectById -Collection 'applications' -ObjectId $AppObjectId -Select $applicationSelect
$servicePrincipal = Get-GraphObjectById -Collection 'servicePrincipals' -ObjectId $ServicePrincipalObjectId -Select $servicePrincipalSelect

Assert-ExactId -Kind 'application object' -Expected $AppObjectId -Actual ([string]$application.id)
Assert-ExactId -Kind 'application client' -Expected $ClientId -Actual ([string]$application.appId)
Assert-OwnershipTags -Kind 'application' -Object $application
if ([string]$application.uniqueName -cne $UniqueName) {
  throw ('Refusing cleanup: application {0} has uniqueName "{1}", not "{2}".' -f $AppObjectId, $application.uniqueName, $UniqueName)
}

if ($application.signInAudience -ne 'AzureADMyOrg') {
  throw ('Refusing cleanup: application {0} is not single-tenant (signInAudience={1}).' -f $AppObjectId, $application.signInAudience)
}
if ($application.isFallbackPublicClient -ne $true) {
  throw ('Refusing cleanup: application {0} is not marked as the lab public client.' -f $AppObjectId)
}
$redirectUris = @($application.publicClient.redirectUris)
if ($redirectUris.Count -ne 1 -or $redirectUris[0] -cne 'http://localhost') {
  throw ('Refusing cleanup: application {0} does not have the exact lab public-client redirect URI.' -f $AppObjectId)
}
if (@($application.passwordCredentials).Count -ne 0 -or @($application.keyCredentials).Count -ne 0) {
  throw ('Refusing cleanup: application {0} contains credentials that the lab template never creates.' -f $AppObjectId)
}

Assert-ExactId -Kind 'service principal object' -Expected $ServicePrincipalObjectId -Actual ([string]$servicePrincipal.id)
Assert-ExactId -Kind 'service principal client' -Expected $ClientId -Actual ([string]$servicePrincipal.appId)
Assert-OwnershipTags -Kind 'service principal' -Object $servicePrincipal

if ($servicePrincipal.servicePrincipalType -and $servicePrincipal.servicePrincipalType -ne 'Application') {
  throw ('Refusing cleanup: service principal {0} has unexpected type "{1}".' -f $ServicePrincipalObjectId, $servicePrincipal.servicePrincipalType)
}
if ($servicePrincipal.appOwnerOrganizationId) {
  $ownerTenantId = Assert-GuidValue -Name 'service principal appOwnerOrganizationId' -Value ([string]$servicePrincipal.appOwnerOrganizationId)
  if (-not $ownerTenantId.Equals($TenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw ('Refusing cleanup: service principal {0} belongs to application tenant {1}, not {2}.' -f $ServicePrincipalObjectId, $ownerTenantId, $TenantId)
  }
}

Write-Host ''
Write-Host '=== Exact device-code lab cleanup plan ===' -ForegroundColor Cyan
Write-Host ('Tenant:                   {0}' -f $TenantId)
Write-Host ('Application:              displayName="{0}", clientId="{1}", objectId="{2}"' -f $application.displayName, $ClientId, $AppObjectId)
Write-Host ('Service principal:        displayName="{0}", clientId="{1}", objectId="{2}"' -f $servicePrincipal.displayName, $ClientId, $ServicePrincipalObjectId)
Write-Host ('Graph unique name:         {0}' -f $UniqueName)
Write-Host ('Verified ownership marker: {0}' -f $ownerTag)
Write-Host 'User objects:              never selected or deleted by this script'

if (-not $Execute) {
  Write-Host ''
  Write-Host 'Dry run only. No objects were deleted. Rerun with -Execute after reviewing every immutable ID.' -ForegroundColor Yellow
  return
}

$target = 'tenant {0}; servicePrincipal/{1}; applications/{2}' -f $TenantId, $ServicePrincipalObjectId, $AppObjectId
if (-not $PSCmdlet.ShouldProcess($target, 'Delete the two exact owner-marked Microsoft Graph objects')) {
  return
}

# Delete the exact service principal first. A failure is fatal and leaves the
# application registration untouched for a safe retry or manual investigation.
Remove-GraphObjectById -Collection 'servicePrincipals' -ObjectId $ServicePrincipalObjectId
Write-Host ('Deleted exact service principal object {0}.' -f $ServicePrincipalObjectId)

Remove-GraphObjectById -Collection 'applications' -ObjectId $AppObjectId
Write-Host ('Deleted exact application object {0}.' -f $AppObjectId)
Write-Host 'Cleanup completed. No user object was touched.' -ForegroundColor Green
