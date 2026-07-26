// Entra Device Code Phishing Detection Lab - Sentinel analytics rules.
//
// The companion PowerShell lifecycle script is the supported deployment path.
// It creates and verifies a local provenance manifest before this template can
// write either deterministic rule ID.

targetScope = 'resourceGroup'

@description('Name of the existing Sentinel-onboarded Log Analytics workspace.')
param workspaceName string

@description('Unique deployment identity recorded in the local provenance manifest.')
@minLength(16)
param deploymentId string

@description('Rules are intentionally disabled until a human validates the KQL and explicitly enables them.')
param enableRules bool = false

var ownerMarker = 'nine-lives-zero-trust:entra-device-code-phishing-sentinel:v1'
var ruleDeviceCode50199ToSuccessId = '45543375-c81a-56ab-b020-b3cc3bcf652e'
var ruleUnapprovedDeviceCodeClientId = '0d879be9-2084-5bee-bf5b-8effbf4d8c64'
var ruleDeviceCode50199ToSuccessKey = 'device-code-50199-to-success'
var ruleUnapprovedDeviceCodeClientKey = 'device-code-unapproved-client'
var ruleDeviceCode50199ToSuccessOwner = '[Owner: ${ownerMarker}; Deployment: ${deploymentId}; Rule: ${ruleDeviceCode50199ToSuccessKey}]'
var ruleUnapprovedDeviceCodeClientOwner = '[Owner: ${ownerMarker}; Deployment: ${deploymentId}; Rule: ${ruleUnapprovedDeviceCodeClientKey}]'

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource ruleDeviceCode50199ToSuccess 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: workspace
  name: ruleDeviceCode50199ToSuccessId
  kind: 'Scheduled'
  properties: {
    displayName: 'LAB - Device Code - 50199 Followed by Success'
    description: 'Detects Entra sign-in interrupt 50199 followed by a successful sign-in for the same user and correlation ID. Treat this as a correlation signal, not proof of device-code abuse. ${ruleDeviceCode50199ToSuccessOwner}'
    severity: 'High'
    enabled: enableRules
    query: loadTextContent('../kql/sentinel/01-device-code-50199-to-success.kql')
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
    techniques: [
      'T1566.002'
      'T1550.001'
    ]
    eventGroupingSettings: {
      aggregationKind: 'SingleAlert'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'AccountName'
          }
          {
            identifier: 'UPNSuffix'
            columnName: 'AccountUPNSuffix'
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

resource ruleUnapprovedDeviceCodeClient 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: workspace
  name: ruleUnapprovedDeviceCodeClientId
  kind: 'Scheduled'
  properties: {
    displayName: 'LAB - Device Code - Unapproved Client'
    description: 'Detects device-code authentication from application IDs outside the documented immutable-ID allowlist. Tune in a disabled state before explicitly enabling. ${ruleUnapprovedDeviceCodeClientOwner}'
    severity: 'Medium'
    enabled: enableRules
    query: loadTextContent('../kql/sentinel/02-unapproved-device-code-client.kql')
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
    techniques: [
      'T1078'
      'T1550.001'
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

output ownerMarker string = ownerMarker
output deploymentId string = deploymentId
output rulesEnabled bool = enableRules
output ruleIds array = [
  ruleDeviceCode50199ToSuccessId
  ruleUnapprovedDeviceCodeClientId
]
output ruleCount int = 2
