#requires -Version 7.0
<#
.SYNOPSIS
  Safely previews or removes Entra artifacts created for the device-code telemetry lab.

.DESCRIPTION
  Finds the lab public client application, its service principal, and optional
  lab users by explicit identifiers or exact display names. Optional users can
  include the device-code lab user and a disposable TAP provisioner account.
  The script defaults to dry-run mode and only deletes when -Execute is
  supplied. Destructive operations use ShouldProcess confirmation.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory = $false)]
  [string]$TenantId = $env:AZURE_TENANT_ID,

  [Parameter(Mandatory = $false)]
  [string]$ClientId = $env:DEVICE_CODE_LAB_CLIENT_ID,

  [Parameter(Mandatory = $false)]
  [string]$AppObjectId,

  [Parameter(Mandatory = $false)]
  [string]$AppDisplayName,

  [Parameter(Mandatory = $false)]
  [string]$ServicePrincipalObjectId,

  [Parameter(Mandatory = $false)]
  [string]$LabUserObjectId,

  [Parameter(Mandatory = $false)]
  [string]$LabUserPrincipalName,

  [Parameter(Mandatory = $false)]
  [string]$LabUserDisplayName,

  [Parameter(Mandatory = $false)]
  [string]$TapProvisionerObjectId,

  [Parameter(Mandatory = $false)]
  [string]$TapProvisionerPrincipalName,

  [Parameter(Mandatory = $false)]
  [string]$TapProvisionerDisplayName,

  [Parameter(Mandatory = $false)]
  [switch]$Execute
)

$ErrorActionPreference = 'Stop'

$applicationSelect = 'id,appId,displayName,tags'
$servicePrincipalSelect = 'id,appId,displayName'
$userSelect = 'id,userPrincipalName,displayName,accountEnabled'
$expectedApplicationTags = @('NineLivesZeroTrust', 'Lab', 'DeviceCodeTelemetry')

function Invoke-AzCli {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  $output = & az @Arguments 2>&1
  $exitCode = $LASTEXITCODE
  $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"

  if ($exitCode -ne 0) {
    throw ('az {0} failed: {1}' -f ($Arguments -join ' '), $text)
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
    return $null
  }

  return $text | ConvertFrom-Json
}

function Assert-AzCliTenant {
  param(
    [Parameter(Mandatory = $false)]
    [string]$ExpectedTenantId
  )

  if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI was not found. Install az and sign in to the lab tenant before running cleanup.'
  }

  $context = Invoke-AzCliJson -Arguments @('account', 'show', '-o', 'json')
  if (-not $context -or -not $context.tenantId) {
    throw 'Azure CLI is not signed in. Run az login against the lab tenant before running cleanup.'
  }

  if ($ExpectedTenantId -and $context.tenantId -ne $ExpectedTenantId) {
    throw ('Azure CLI is signed in to tenant {0}, but TenantId is {1}. Run az login --tenant {1} or omit -TenantId after selecting the lab tenant.' -f $context.tenantId, $ExpectedTenantId)
  }

  return $context
}

function New-GraphUrl {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $false)]
    [hashtable]$Query = @{}
  )

  $trimmedPath = $Path.TrimStart('/')
  if ($Query.Count -eq 0) {
    return 'https://graph.microsoft.com/v1.0/{0}' -f $trimmedPath
  }

  $pairs = foreach ($key in $Query.Keys) {
    '{0}={1}' -f [System.Uri]::EscapeDataString($key), [System.Uri]::EscapeDataString([string]$Query[$key])
  }

  return 'https://graph.microsoft.com/v1.0/{0}?{1}' -f $trimmedPath, ($pairs -join '&')
}

function New-ODataStringLiteral {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Value
  )

  return "'{0}'" -f $Value.Replace("'", "''")
}

function Find-GraphObjects {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('applications', 'servicePrincipals', 'users')]
    [string]$Collection,

    [Parameter(Mandatory = $true)]
    [string]$Filter,

    [Parameter(Mandatory = $true)]
    [string]$Select
  )

  $url = New-GraphUrl -Path $Collection -Query @{
    '$filter' = $Filter
    '$select' = $Select
  }
  $response = Invoke-AzCliJson -Arguments @('rest', '--method', 'GET', '--url', $url, '-o', 'json')

  if (-not $response -or -not ($response.PSObject.Properties.Name -contains 'value')) {
    return @()
  }

  return @($response.value)
}

function Get-GraphObject {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('applications', 'servicePrincipals', 'users')]
    [string]$Collection,

    [Parameter(Mandatory = $true)]
    [string]$ObjectId,

    [Parameter(Mandatory = $true)]
    [string]$Select
  )

  $path = '{0}/{1}' -f $Collection, [System.Uri]::EscapeDataString($ObjectId)
  $url = New-GraphUrl -Path $path -Query @{ '$select' = $Select }
  return Invoke-AzCliJson -Arguments @('rest', '--method', 'GET', '--url', $url, '-o', 'json')
}

function Resolve-SingleObject {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Kind,

    [Parameter(Mandatory = $true)]
    [object[]]$Objects,

    [Parameter(Mandatory = $true)]
    [string]$Lookup
  )

  if ($Objects.Count -eq 0) {
    Write-Warning ('No {0} found for {1}.' -f $Kind, $Lookup)
    return $null
  }

  if ($Objects.Count -gt 1) {
    $matches = $Objects | ForEach-Object {
      if ($_.PSObject.Properties.Name -contains 'appId') {
        'displayName="{0}", appId="{1}", objectId="{2}"' -f $_.displayName, $_.appId, $_.id
      }
      elseif ($_.PSObject.Properties.Name -contains 'userPrincipalName') {
        'displayName="{0}", userPrincipalName="{1}", objectId="{2}"' -f $_.displayName, $_.userPrincipalName, $_.id
      }
      else {
        'displayName="{0}", objectId="{1}"' -f $_.displayName, $_.id
      }
    }

    throw ('Refusing to choose between {0} {1} matches for {2}. Rerun with an object ID or client/user principal name. Matches: {3}' -f $Objects.Count, $Kind, $Lookup, ($matches -join '; '))
  }

  return $Objects[0]
}

function Test-ExpectedApplicationTags {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Application
  )

  $tags = @($Application.tags)
  foreach ($tag in $expectedApplicationTags) {
    if ($tags -notcontains $tag) {
      return $false
    }
  }

  return $true
}

function Resolve-LabApplication {
  if ($AppObjectId) {
    $application = Get-GraphObject -Collection 'applications' -ObjectId $AppObjectId -Select $applicationSelect
    if ($PSBoundParameters.ContainsKey('ClientId') -and $ClientId -and $application.appId -ne $ClientId) {
      throw ('Application object {0} has appId {1}, not ClientId {2}.' -f $AppObjectId, $application.appId, $ClientId)
    }
    if ($PSBoundParameters.ContainsKey('AppDisplayName') -and $AppDisplayName -and $application.displayName -ne $AppDisplayName) {
      throw ('Application object {0} has displayName "{1}", not "{2}".' -f $AppObjectId, $application.displayName, $AppDisplayName)
    }
    return $application
  }

  if ($ClientId) {
    $matches = Find-GraphObjects -Collection 'applications' -Filter ('appId eq {0}' -f (New-ODataStringLiteral -Value $ClientId)) -Select $applicationSelect
    $application = Resolve-SingleObject -Kind 'application' -Objects $matches -Lookup ('client ID {0}' -f $ClientId)
    if ($application -and $PSBoundParameters.ContainsKey('AppDisplayName') -and $AppDisplayName -and $application.displayName -ne $AppDisplayName) {
      throw ('Application client ID {0} has displayName "{1}", not "{2}".' -f $ClientId, $application.displayName, $AppDisplayName)
    }
    return $application
  }

  if ($AppDisplayName) {
    $matches = Find-GraphObjects -Collection 'applications' -Filter ('displayName eq {0}' -f (New-ODataStringLiteral -Value $AppDisplayName)) -Select $applicationSelect
    $application = Resolve-SingleObject -Kind 'application' -Objects $matches -Lookup ('display name "{0}"' -f $AppDisplayName)
    if ($application -and -not (Test-ExpectedApplicationTags -Application $application)) {
      throw ('Refusing to delete application "{0}" by display name because it does not have the expected lab tags: {1}.' -f $application.displayName, ($expectedApplicationTags -join ', '))
    }
    return $application
  }

  return $null
}

function Resolve-LabServicePrincipal {
  param(
    [Parameter(Mandatory = $false)]
    [object]$Application
  )

  if ($ServicePrincipalObjectId) {
    $servicePrincipal = Get-GraphObject -Collection 'servicePrincipals' -ObjectId $ServicePrincipalObjectId -Select $servicePrincipalSelect
    if ($Application -and $servicePrincipal.appId -ne $Application.appId) {
      throw ('Service principal object {0} has appId {1}, not application appId {2}.' -f $ServicePrincipalObjectId, $servicePrincipal.appId, $Application.appId)
    }
    return $servicePrincipal
  }

  if ($Application) {
    $matches = Find-GraphObjects -Collection 'servicePrincipals' -Filter ('appId eq {0}' -f (New-ODataStringLiteral -Value $Application.appId)) -Select $servicePrincipalSelect
    return Resolve-SingleObject -Kind 'service principal' -Objects $matches -Lookup ('application appId {0}' -f $Application.appId)
  }

  if ($ClientId) {
    $matches = Find-GraphObjects -Collection 'servicePrincipals' -Filter ('appId eq {0}' -f (New-ODataStringLiteral -Value $ClientId)) -Select $servicePrincipalSelect
    return Resolve-SingleObject -Kind 'service principal' -Objects $matches -Lookup ('client ID {0}' -f $ClientId)
  }

  if ($AppDisplayName) {
    $matches = Find-GraphObjects -Collection 'servicePrincipals' -Filter ('displayName eq {0}' -f (New-ODataStringLiteral -Value $AppDisplayName)) -Select $servicePrincipalSelect
    return Resolve-SingleObject -Kind 'service principal' -Objects $matches -Lookup ('display name "{0}"' -f $AppDisplayName)
  }

  return $null
}

function Resolve-UserFromSelectors {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Purpose,

    [Parameter(Mandatory = $false)]
    [string]$ObjectId,

    [Parameter(Mandatory = $false)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $false)]
    [string]$DisplayName
  )

  if ($ObjectId) {
    $user = Get-GraphObject -Collection 'users' -ObjectId $ObjectId -Select $userSelect
    if ($UserPrincipalName -and $user.userPrincipalName -ne $UserPrincipalName) {
      throw ('{0} object {1} has userPrincipalName "{2}", not "{3}".' -f $Purpose, $ObjectId, $user.userPrincipalName, $UserPrincipalName)
    }
    if ($DisplayName -and $user.displayName -ne $DisplayName) {
      throw ('{0} object {1} has displayName "{2}", not "{3}".' -f $Purpose, $ObjectId, $user.displayName, $DisplayName)
    }
    return $user
  }

  if ($UserPrincipalName) {
    $matches = Find-GraphObjects -Collection 'users' -Filter ('userPrincipalName eq {0}' -f (New-ODataStringLiteral -Value $UserPrincipalName)) -Select $userSelect
    $user = Resolve-SingleObject -Kind $Purpose -Objects $matches -Lookup ('userPrincipalName "{0}"' -f $UserPrincipalName)
    if ($user -and $DisplayName -and $user.displayName -ne $DisplayName) {
      throw ('{0} userPrincipalName "{1}" has displayName "{2}", not "{3}".' -f $Purpose, $UserPrincipalName, $user.displayName, $DisplayName)
    }
    return $user
  }

  if ($DisplayName) {
    $matches = Find-GraphObjects -Collection 'users' -Filter ('displayName eq {0}' -f (New-ODataStringLiteral -Value $DisplayName)) -Select $userSelect
    return Resolve-SingleObject -Kind $Purpose -Objects $matches -Lookup ('display name "{0}"' -f $DisplayName)
  }

  return $null
}

function Resolve-LabUser {
  Resolve-UserFromSelectors `
    -Purpose 'lab user' `
    -ObjectId $LabUserObjectId `
    -UserPrincipalName $LabUserPrincipalName `
    -DisplayName $LabUserDisplayName
}

function Resolve-TapProvisionerUser {
  Resolve-UserFromSelectors `
    -Purpose 'TAP provisioner user' `
    -ObjectId $TapProvisionerObjectId `
    -UserPrincipalName $TapProvisionerPrincipalName `
    -DisplayName $TapProvisionerDisplayName
}

function Format-ApplicationSummary {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Application
  )

  return 'displayName="{0}", clientId="{1}", objectId="{2}"' -f $Application.displayName, $Application.appId, $Application.id
}

function Format-ServicePrincipalSummary {
  param(
    [Parameter(Mandatory = $true)]
    [object]$ServicePrincipal
  )

  return 'displayName="{0}", appId="{1}", objectId="{2}"' -f $ServicePrincipal.displayName, $ServicePrincipal.appId, $ServicePrincipal.id
}

function Format-UserSummary {
  param(
    [Parameter(Mandatory = $true)]
    [object]$User
  )

  return 'displayName="{0}", userPrincipalName="{1}", objectId="{2}"' -f $User.displayName, $User.userPrincipalName, $User.id
}

function Remove-GraphObject {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('applications', 'servicePrincipals', 'users')]
    [string]$Collection,

    [Parameter(Mandatory = $true)]
    [string]$ObjectId,

    [Parameter(Mandatory = $true)]
    [string]$Kind,

    [Parameter(Mandatory = $true)]
    [string]$Summary
  )

  $url = New-GraphUrl -Path ('{0}/{1}' -f $Collection, [System.Uri]::EscapeDataString($ObjectId))
  $target = '{0}: {1}' -f $Kind, $Summary
  if (-not $PSCmdlet.ShouldProcess($target, 'Delete from Microsoft Graph')) {
    return $false
  }

  $null = Invoke-AzCli -Arguments @('rest', '--method', 'DELETE', '--url', $url, '--only-show-errors')
  Write-Host ('Deleted {0}: {1}' -f $Kind, $Summary)
  return $true
}

function Write-PlanLine {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Label,

    [Parameter(Mandatory = $true)]
    [string]$Summary
  )

  Write-Host ('- {0}: {1}' -f $Label, $Summary)
}

$hasAppSelector = $ClientId -or $AppObjectId -or $AppDisplayName -or $ServicePrincipalObjectId
$hasUserSelector = $LabUserObjectId -or $LabUserPrincipalName -or $LabUserDisplayName -or $TapProvisionerObjectId -or $TapProvisionerPrincipalName -or $TapProvisionerDisplayName

if (-not ($hasAppSelector -or $hasUserSelector)) {
  throw 'Provide at least one explicit selector: -ClientId, -AppObjectId, -AppDisplayName, -ServicePrincipalObjectId, -LabUserObjectId, -LabUserPrincipalName, -LabUserDisplayName, -TapProvisionerObjectId, -TapProvisionerPrincipalName, or -TapProvisionerDisplayName.'
}

$context = Assert-AzCliTenant -ExpectedTenantId $TenantId
$activeTenantId = if ($TenantId) { $TenantId } else { $context.tenantId }

$application = Resolve-LabApplication
$servicePrincipal = Resolve-LabServicePrincipal -Application $application
$labUser = Resolve-LabUser
$tapProvisionerUser = Resolve-TapProvisionerUser

if ($labUser -and $tapProvisionerUser -and $labUser.id -eq $tapProvisionerUser.id) {
  Write-Warning 'Lab user and TAP provisioner selectors resolved to the same user object. It will be listed and deleted once.'
  $tapProvisionerUser = $null
}

if (-not ($application -or $servicePrincipal -or $labUser -or $tapProvisionerUser)) {
  Write-Host 'No matching lab artifacts were found. Nothing to clean up.'
  return
}

Write-Host ''
Write-Host '=== Device-code lab cleanup plan ===' -ForegroundColor Cyan
Write-Host ('Tenant: {0}' -f $activeTenantId)

if ($application) {
  Write-PlanLine -Label 'Application registration' -Summary (Format-ApplicationSummary -Application $application)
  if (-not (Test-ExpectedApplicationTags -Application $application)) {
    Write-Warning ('Matched application does not contain all expected lab tags: {0}. Confirm the object details before executing cleanup.' -f ($expectedApplicationTags -join ', '))
  }
}

if ($servicePrincipal) {
  $servicePrincipalSummary = Format-ServicePrincipalSummary -ServicePrincipal $servicePrincipal
  if ($application) {
    Write-PlanLine -Label 'Service principal' -Summary ('{0} (expected to be removed with the application registration)' -f $servicePrincipalSummary)
  }
  else {
    Write-PlanLine -Label 'Service principal' -Summary $servicePrincipalSummary
  }
}

if ($labUser) {
  Write-PlanLine -Label 'Lab user' -Summary (Format-UserSummary -User $labUser)
}

if ($tapProvisionerUser) {
  Write-PlanLine -Label 'TAP provisioner user' -Summary (Format-UserSummary -User $tapProvisionerUser)
}

if (-not $Execute) {
  Write-Host ''
  Write-Host 'Dry run only. Rerun with -Execute to delete the listed artifacts; PowerShell will ask for confirmation before each delete.' -ForegroundColor Yellow
  return
}

Write-Host ''
Write-Host 'Executing cleanup. Each delete still requires PowerShell confirmation unless you explicitly suppress common-parameter prompts.' -ForegroundColor Yellow

$applicationDeleted = $false
if ($application) {
  $applicationDeleted = Remove-GraphObject `
    -Collection 'applications' `
    -ObjectId $application.id `
    -Kind 'application registration' `
    -Summary (Format-ApplicationSummary -Application $application)
}

if ($servicePrincipal) {
  if ($application) {
    if ($applicationDeleted) {
      $remainingServicePrincipal = Resolve-LabServicePrincipal -Application $application
      if ($remainingServicePrincipal) {
        $null = Remove-GraphObject `
          -Collection 'servicePrincipals' `
          -ObjectId $remainingServicePrincipal.id `
          -Kind 'service principal' `
          -Summary (Format-ServicePrincipalSummary -ServicePrincipal $remainingServicePrincipal)
      }
      else {
        Write-Host 'Service principal is no longer present after application deletion.'
      }
    }
    else {
      Write-Host 'Skipping service principal cleanup because the application registration was not deleted.'
    }
  }
  else {
    $null = Remove-GraphObject `
      -Collection 'servicePrincipals' `
      -ObjectId $servicePrincipal.id `
      -Kind 'service principal' `
      -Summary (Format-ServicePrincipalSummary -ServicePrincipal $servicePrincipal)
  }
}

if ($labUser) {
  $null = Remove-GraphObject `
    -Collection 'users' `
    -ObjectId $labUser.id `
    -Kind 'lab user' `
    -Summary (Format-UserSummary -User $labUser)
}

if ($tapProvisionerUser) {
  $null = Remove-GraphObject `
    -Collection 'users' `
    -ObjectId $tapProvisionerUser.id `
    -Kind 'TAP provisioner user' `
    -Summary (Format-UserSummary -User $tapProvisionerUser)
}
