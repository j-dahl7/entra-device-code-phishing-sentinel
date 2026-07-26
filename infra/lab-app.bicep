// Entra Device Code Phishing Detection Lab - public client app.
//
// This creates a no-secret, single-tenant public client application that can
// generate device-code sign-in telemetry for lab-owned users. It does not grant
// application permissions and it is not used to access Graph, mail, or tenant
// resources by the lab scripts.
//
// Deploying Microsoft Graph Bicep resources requires Application.ReadWrite.All
// or equivalent app-registration privileges for the deploying identity.

targetScope = 'subscription'

extension graphV1

@sys.description('Immutable, deployment-specific Graph alternate key. Use the documented lab prefix plus a newly generated GUID and retain it for cleanup.')
@minLength(60)
param uniqueName string

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

resource app 'graphV1:Microsoft.Graph/applications@v1.0' = {
  uniqueName: uniqueName
  displayName: displayName
  description: appDescription
  signInAudience: 'AzureADMyOrg'
  isFallbackPublicClient: true
  publicClient: {
    redirectUris: [
      'http://localhost'
    ]
  }
  tags: labTags
}

resource servicePrincipal 'graphV1:Microsoft.Graph/servicePrincipals@v1.0' = {
  appId: app.appId
  notes: 'Owned by the Nine Lives Entra device-code phishing detection lab. No workload permissions are assigned by this template.'
  tags: labTags
}

output clientId string = app.appId
output applicationObjectId string = app.id
output servicePrincipalId string = servicePrincipal.id
output displayName string = app.displayName
output uniqueName string = app.uniqueName
output ownerTag string = ownerTag
