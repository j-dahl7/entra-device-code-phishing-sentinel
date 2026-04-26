// Entra Device Code Phishing Detection Lab - Sentinel analytics rules.
// Deploy against your Sentinel-onboarded Log Analytics workspace.

targetScope = 'resourceGroup'

@description('Name of the Sentinel-onboarded Log Analytics workspace.')
param workspaceName string

resource ruleDeviceCode50199ToSuccess 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-02-01-preview' = {
  name: '${workspaceName}/Microsoft.SecurityInsights/device-code-50199-to-success'
  kind: 'Scheduled'
  properties: {
    displayName: 'LAB - Device Code - 50199 Followed by Success'
    description: 'Detects Entra sign-in interrupt 50199 followed by a successful sign-in for the same user and correlation ID. Use as a high-signal device-code phishing hunt after allowlist tuning.'
    severity: 'High'
    enabled: true
    query: '''
let Lookback = 15m;
let Window = 5m;
let ApprovedDeviceCodeApps = dynamic([
    "Microsoft Azure CLI",
    "Azure CLI",
    "Microsoft Azure PowerShell",
    "Microsoft Teams Rooms"
]);
let ApprovedDeviceCodeAppIds = dynamic([
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46", // Microsoft Azure CLI
    "1950a258-227b-4e31-a9cf-717495945fc2"  // Microsoft Azure PowerShell
]);
let Interrupts =
    SigninLogs
    | where TimeGenerated > ago(Lookback)
    | extend Result = tostring(ResultType)
    | where Result == "50199" or ResultDescription has "50199"
    | extend SessionId = tostring(column_ifexists("SessionId", ""))
    | project InterruptTime = TimeGenerated, UserPrincipalName,
        CorrelationId, SessionId, IPAddress, AppDisplayName, AppId, UserAgent;
let Successes =
    SigninLogs
    | where TimeGenerated > ago(Lookback)
    | extend Result = tostring(ResultType)
    | where Result == "0"
    | extend SessionId = tostring(column_ifexists("SessionId", ""))
    | project SuccessTime = TimeGenerated, UserPrincipalName,
        CorrelationId, SessionId, SuccessIP = IPAddress,
        SuccessApp = AppDisplayName, SuccessAppId = AppId, SuccessUserAgent = UserAgent;
Interrupts
| join kind=inner Successes on UserPrincipalName, CorrelationId
| where SuccessTime between (InterruptTime .. InterruptTime + Window)
| where AppDisplayName !in~ (ApprovedDeviceCodeApps)
    and SuccessApp !in~ (ApprovedDeviceCodeApps)
    and AppId !in~ (ApprovedDeviceCodeAppIds)
    and SuccessAppId !in~ (ApprovedDeviceCodeAppIds)
| project TimeGenerated = SuccessTime, InterruptTime, UserPrincipalName,
    AppDisplayName, AppId, IPAddress, SuccessIP, UserAgent, SuccessUserAgent,
    CorrelationId, SessionId
'''
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: true
    tactics: [
      'InitialAccess'
      'DefenseEvasion'
    ]
    eventGroupingSettings: {
      aggregationKind: 'SingleAlert'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'UserPrincipalName'
          }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'SuccessIP'
          }
        ]
      }
      {
        entityType: 'CloudApplication'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'AppDisplayName'
          }
        ]
      }
    ]
  }
}

resource ruleUnapprovedDeviceCodeClient 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-02-01-preview' = {
  name: '${workspaceName}/Microsoft.SecurityInsights/device-code-unapproved-client'
  kind: 'Scheduled'
  properties: {
    displayName: 'LAB - Device Code - Unapproved Client'
    description: 'Detects device-code authentication from applications outside the documented allowlist. Start in tuning mode and promote after tenant-specific exceptions are documented.'
    severity: 'Medium'
    enabled: true
    query: '''
let ApprovedDeviceCodeApps = dynamic([
    "Microsoft Azure CLI",
    "Azure CLI",
    "Microsoft Azure PowerShell",
    "Microsoft Teams Rooms"
]);
let ApprovedDeviceCodeAppIds = dynamic([
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46", // Microsoft Azure CLI
    "1950a258-227b-4e31-a9cf-717495945fc2"  // Microsoft Azure PowerShell
]);
let Lookback = 1h;
let Window = 5m;
let DirectDeviceCodeEvents =
    SigninLogs
    | where TimeGenerated > ago(Lookback)
    | extend AuthProtocol = tostring(column_ifexists("AuthenticationProtocol", ""))
    | where AuthProtocol =~ "deviceCode" or ResultDescription has "device code"
    | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, AppId;
let Interrupts =
    SigninLogs
    | where TimeGenerated > ago(Lookback)
    | extend Result = tostring(ResultType)
    | where Result == "50199" or ResultDescription has "50199"
    | project InterruptTime = TimeGenerated, UserPrincipalName, CorrelationId;
let CorrelatedSuccesses =
    SigninLogs
    | where TimeGenerated > ago(Lookback)
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
| project TimeGenerated = LastSeen, FirstSeen, LastSeen,
    AppDisplayName, AppId, Attempts, Users, IPs, SampleUsers, SampleIPs
| order by Attempts desc
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT6H'
    suppressionEnabled: true
    tactics: [
      'InitialAccess'
      'CredentialAccess'
    ]
    eventGroupingSettings: {
      aggregationKind: 'SingleAlert'
    }
    entityMappings: [
      {
        entityType: 'CloudApplication'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'AppDisplayName'
          }
        ]
      }
    ]
  }
}

output ruleCount int = 2
