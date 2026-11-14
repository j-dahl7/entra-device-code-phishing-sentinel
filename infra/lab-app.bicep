// Entra Device Code Phishing Detection Lab - public client app.
//
// This creates a no-secret, single-tenant public client application that can
// generate device-code sign-in telemetry for lab-owned users. It does not grant
// application permissions and it is not used to access Graph, mail, or tenant
// resources by the lab scripts.
//
// The service principal requires user assignment. Microsoft Entra ID requires
// an administrator to consent to the permissions of such an application, so
// the lab user cannot consent to the "openid profile" sign-in request alone.
// The template therefore grants "openid profile" on Microsoft Graph to the one
// dedicated lab user (consentType Principal). It never grants tenant-wide
// (AllPrincipals) consent or any other scope.
//
// Deploying Microsoft Graph Bicep resources requires Application.ReadWrite.All
// plus AppRoleAssignment.ReadWrite.All for assigning the existing dedicated
// lab user, DelegatedPermissionGrant.ReadWrite.All for that user's consent
// grant, and appropriate directory privileges.

targetScope = 'subscription'

extension graphV1

@sys.description('Immutable, deployment-specific Graph alternate key. Use the documented lab prefix plus a newly generated GUID and retain it for cleanup.')
@minLength(60)
param uniqueName string

@sys.description('Object ID of the dedicated existing lab user to assign to this application and to consent for. No user is created.')
@minLength(36)
@maxLength(36)
param labUserObjectId string

@sys.description('Display name shown in Entra sign-in logs and app registrations.')
param displayName string = 'LAB - Nine Lives Device Code Telemetry'

@sys.description('Free-text description for the app registration.')
param appDescription string = 'No-secret public client used by the Nine Lives Entra device-code phishing detection lab to generate lab-owned sign-in telemetry. Tokens are discarded by the companion script.'

var ownerTag = 'NineLives.Owner:EntraDeviceCodePhishingSentinel:v1'
var uniqueNameTag = 'NineLives.UniqueName:${uniqueName}'
var labTags = [
  ownerTag
  uniqueNameTag
  'NineLivesZeroTrust'
  'Lab'
  'DeviceCodeTelemetry'
  'NoSecrets'
]

// Microsoft Graph defines the OpenID Connect scopes. The scope list must stay
// identical to $fixedScope in scripts/run-device-code-telemetry-test.ps1 and to
// the scopes that scripts/cleanup-device-code-lab-artifacts.ps1 accepts.
var microsoftGraphAppId = '00000003-0000-0000-c000-000000000000'
var labUserDelegatedScope = 'openid profile'

resource app 'graphV1:Microsoft.Graph/applications@v1.0' = {
  uniqueName: uniqueName
  displayName: displayName
  description: appDescription
  signInAudience: 'AzureADMyOrg'
  isFallbackPublicClient: true
  publicClient: {
    redirectUris: []
  }
  tags: labTags
}

resource servicePrincipal 'graphV1:Microsoft.Graph/servicePrincipals@v1.0' = {
  appId: app.appId
  appRoleAssignmentRequired: true
  notes: 'Owned by the Nine Lives Entra device-code phishing detection lab. This template assigns no application permission. Its only delegated grant is openid profile for the dedicated lab user.'
  tags: labTags
}

resource labUserAssignment 'graphV1:Microsoft.Graph/appRoleAssignedTo@v1.0' = {
  appRoleId: '00000000-0000-0000-0000-000000000000'
  principalId: labUserObjectId
  resourceId: servicePrincipal.id
}

// Read-only lookup of the tenant's existing Microsoft Graph service principal.
resource microsoftGraph 'graphV1:Microsoft.Graph/servicePrincipals@v1.0' existing = {
  appId: microsoftGraphAppId
}

// Consent for the dedicated lab user only. A non-admin user cannot consent to
// an application that requires assignment, so without this grant the lab
// sign-in is expected to stop at an admin-approval page. Microsoft documents
// that Graph Bicep identifies a grant by its property values, so a rerun with
// the same inputs is expected to reuse this grant. A rerun for a different
// user would add a second grant, which cleanup refuses.
resource labUserConsent 'graphV1:Microsoft.Graph/oauth2PermissionGrants@v1.0' = {
  clientId: servicePrincipal.id
  consentType: 'Principal'
  principalId: labUserObjectId
  resourceId: microsoftGraph.id
  scope: labUserDelegatedScope
}

output clientId string = app.appId
output applicationObjectId string = app.id
output servicePrincipalId string = servicePrincipal.id
output delegatedPermissionGrantId string = labUserConsent.id
output delegatedPermissionGrantScope string = labUserConsent.scope
output displayName string = app.displayName
output uniqueName string = app.uniqueName
output ownerTag string = ownerTag
