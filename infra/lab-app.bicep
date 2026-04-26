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

@sys.description('Immutable unique name for idempotent Microsoft Graph Bicep deployments.')
param uniqueName string = 'nine-lives-device-code-telemetry-lab'

@sys.description('Display name shown in Entra sign-in logs and app registrations.')
param displayName string = 'LAB - Nine Lives Device Code Telemetry'

@sys.description('Free-text description for the app registration.')
param appDescription string = 'No-secret public client used by the Nine Lives Entra device-code phishing detection lab to generate lab-owned sign-in telemetry. Tokens are discarded by the companion script.'

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
  tags: [
    'NineLivesZeroTrust'
    'Lab'
    'DeviceCodeTelemetry'
    'NoSecrets'
  ]
}

resource servicePrincipal 'graphV1:Microsoft.Graph/servicePrincipals@v1.0' = {
  appId: app.appId
}

output clientId string = app.appId
output servicePrincipalId string = servicePrincipal.id
output displayName string = app.displayName
