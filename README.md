# Entra Device Code Phishing Detection Lab

This is the companion lab for:

`Block Device Code Phishing in Entra Without Breaking Legit Workflows`

Blog: https://nineliveszerotrust.com/blog/entra-device-code-phishing-sentinel/

The lab provides two Microsoft Sentinel analytics rules, three Defender XDR
hunts, a synthetic replay, and an optional no-secret public client that creates
lab-owned sign-in telemetry. It does not provide phishing infrastructure,
capture credentials, access mail, or use issued tokens against a workload.

## Validation boundary

The July 25, 2026 hardening revision was validated offline:

- both Bicep templates compiled with Bicep 0.45.6;
- every PowerShell entry point parsed under PowerShell 7;
- the offline safety suite exercised foreign-rule and foreign-Graph-object
  collisions and confirmed that they fail before mutation;
- the canonical and bundled lab copies were reconciled byte for byte; and
- the Sentinel template now loads the tracked KQL files directly.

No tenant object was created or deleted, no device code was approved, and no
live Entra, Sentinel, Log Analytics, or Defender query was run during that
validation.

## Safety model

The lifecycle intentionally fails closed:

- Sentinel rules use two fixed GUID resource IDs.
- Sentinel deployment and removal require
  `scripts/manage-sentinel-rules.ps1`.
- Existing rule IDs are never adopted without the exact local provenance
  manifest and ownership suffix.
- A different rule using either display name blocks all mutations.
- Rules deploy disabled unless `-EnableRules` is explicitly supplied.
- Entra cleanup requires tenant ID, client ID, application object ID, service
  principal object ID, and the deployment-specific Graph `uniqueName`.
- Entra cleanup validates every object and ownership tag before the first
  delete. Display names are informational only.
- No script deletes users. The template does not create a user, so it cannot
  prove ownership of one.
- Native-command, REST, parsing, deployment, verification, and delete failures
  are fatal. Expected OAuth polling states are the only retryable errors.

## Prerequisites and permissions

- PowerShell 7 or newer.
- Azure CLI, the Azure CLI `log-analytics` extension for the checker, and Bicep
  0.36.1 or newer.
- A Sentinel-enabled Log Analytics workspace receiving Entra `SigninLogs`.
- Permission such as Microsoft Sentinel Contributor on the target workspace
  resource group.
- For the optional app, permission to create an application and service
  principal, such as `Application.ReadWrite.All` in a dedicated lab tenant,
  plus permission to run an Azure subscription-scope deployment.
- Azure CLI access to Microsoft Graph for exact object reads, the active-role
  safety check, and optional cleanup.
- Microsoft Entra ID P2 for `EntraIdSignInEvents` and the applicable Defender
  products/connectors for `UrlClickEvents` and `CloudAppEvents`.

The Microsoft Graph Bicep extension is still documented by Microsoft as
preview. Review its current support terms before using it outside a disposable
lab tenant:
https://learn.microsoft.com/graph/templates/bicep/reference/overview

## What is included

| Surface | Files | Result |
|---|---|---|
| Sentinel | `infra/sentinel-rules.bicep` and `kql/sentinel/*.kql` | Two scheduled rules, disabled by default |
| Entra | `infra/lab-app.bicep` | Optional single-tenant public client and service principal, with no credentials |
| Telemetry | `scripts/run-device-code-telemetry-test.ps1` | One lab-user device-code ceremony; issued tokens are identity-checked and discarded |
| Verification | `scripts/check-device-code-telemetry.ps1` | Exact app/user-scoped `SigninLogs` and rule previews |
| Cleanup | `scripts/manage-sentinel-rules.ps1` and `scripts/cleanup-device-code-lab-artifacts.ps1` | Exact, owner-verified cleanup only |
| Defender XDR | `kql/defender-xdr/*.kql` | URL-click, mailbox-abuse, and device-registration hunts |
| Replay | `kql/sample-data/device-code-phishing-replay.kql` | Neutral synthetic rows for query inspection |

## Detection accuracy guardrails

- `50199 -> 0` is a correlation signal, not proof of device-code phishing.
  Join it with protocol, immutable app ID, non-empty correlation/session
  context, URL-click timing, or post-token behavior.
- Application display names are attacker-controlled. The default allowlist uses
  only the well-known Azure CLI and Azure PowerShell application IDs.
- Teams Rooms and other legitimate clients are not suppressed by display name.
  Inventory the exact application IDs in your tenant before adding exceptions.
- Microsoft Authentication Broker is not a default exception. Require a
  documented broker/device-registration use case and compensating controls.
- The Sentinel joins prefer `UserId` and fall back to normalized UPN only when
  the object ID is absent.
- The mailbox hunt joins `EntraIdSignInEvents.AccountObjectId` to
  `CloudAppEvents.AccountObjectId`. It does not assume that
  `CloudAppEvents.AccountId` is a UPN.
- `UrlClickEvents` exposes an account UPN rather than an Entra object ID, so the
  URL-click hunt must retain a UPN join. Validate aliases and guest identities.
- Device-registration raw fields vary by tenant and connector. Validate that
  `RawEventData.ObjectId` is the registering user's Entra object ID before
  operationalizing that hunt.

## Queries

### Sentinel

| File | Purpose |
|---|---|
| `kql/sentinel/01-device-code-50199-to-success.kql` | Non-empty user/correlation join from 50199 to success |
| `kql/sentinel/02-unapproved-device-code-client.kql` | Device-code-like events outside an immutable app-ID allowlist |
| `kql/sentinel/05-device-code-inventory.kql` | 30-day client inventory for tuning |

### Defender XDR

| File | Purpose |
|---|---|
| `kql/defender-xdr/01-url-click-to-device-code-auth.kql` | URL click, interrupt, and later success in bounded windows |
| `kql/defender-xdr/02-post-token-mailbox-abuse.kql` | Object-ID correlation to Exchange activity |
| `kql/defender-xdr/03-device-registration-after-device-code.kql` | Object-ID correlation to tenant-validated registration fields |

### Synthetic replay

Run `kql/sample-data/device-code-phishing-replay.kql` in a KQL-capable editor.
The replay contains documentation-only IP ranges, `contoso.com` identities, and
non-production GUIDs. It does not write data.

## Sentinel rule identities

| Rule | Immutable resource ID | Default |
|---|---|---|
| LAB - Device Code - 50199 Followed by Success | `45543375-c81a-56ab-b020-b3cc3bcf652e` | Disabled |
| LAB - Device Code - Unapproved Client | `0d879be9-2084-5bee-bf5b-8effbf4d8c64` | Disabled |

These GUIDs are scoped under the selected workspace. Do not change them to make
a collision disappear. A collision means the lifecycle script must stop so an
operator can investigate.

## Deploy Sentinel rules safely

Set the exact target:

```powershell
$env:AZURE_SUBSCRIPTION_ID = "<subscription-guid>"
$env:SENTINEL_RESOURCE_GROUP = "rg-device-code-lab"
$env:SENTINEL_WORKSPACE_NAME = "law-device-code-lab"
```

Run a read-only ownership and collision preflight:

```powershell
./scripts/manage-sentinel-rules.ps1
```

The first preflight must find neither deterministic rule ID nor either display
name. It does not create the provenance manifest.

Deploy both rules in the safe disabled state:

```powershell
./scripts/manage-sentinel-rules.ps1 -Execute -Confirm
```

The script writes `.device-code-sentinel-state.json` before the first cloud
write, deploys the two rules, then rereads Sentinel and verifies ID, kind,
display name, ownership suffix, and disabled state. Keep that file. It is the
local proof that permits an owned rerun and partial-cleanup recovery. Do not
copy it to another subscription, tenant, resource group, or workspace.

After validating `SigninLogs` availability, running both KQL files manually,
and tuning immutable app-ID exceptions, explicitly enable the rules:

```powershell
./scripts/manage-sentinel-rules.ps1 -EnableRules -Execute -Confirm
```

Omitting `-EnableRules` on a later deployment returns both rules to the safe
disabled state. `-WhatIf` can be combined with `-Execute` to exercise
ShouldProcess without writing.

Direct deployment of `infra/sentinel-rules.bicep` is unsupported because Bicep
alone cannot distinguish an owned resource from a foreign object already using
the same GUID. The lifecycle script supplies the deployment identity only after
the manifest and collision checks pass.

## Remove Sentinel rules safely

Preview exact cleanup:

```powershell
./scripts/manage-sentinel-rules.ps1 -Action Remove
```

Remove only the two manifest-owned IDs:

```powershell
./scripts/manage-sentinel-rules.ps1 -Action Remove -Execute -Confirm
```

Every existing target is validated before the first delete. Missing owned IDs
are treated as already removed so a partial prior failure can be recovered.
Foreign IDs, names, kinds, or ownership suffixes stop the entire preflight.
After cleanup, the manifest is retained with `status: removed` as an audit and
recovery record.

## Optional Entra telemetry app

### 1. Create a deployment-specific alternate key

Microsoft Graph Bicep applications are upserted by `uniqueName`. Never use a
shared static value. Generate a fresh GUID-suffixed value and retain it:

```powershell
$appDeploymentId = [guid]::NewGuid()
$labUniqueName = "nine-lives-device-code-telemetry-lab-$appDeploymentId"
$deploymentName = "nlzt-device-code-app-$($appDeploymentId.ToString('N').Substring(0, 8))"
```

### 2. Deploy and capture every immutable output

This is a live tenant write:

```powershell
$deployment = az deployment sub create `
  --name $deploymentName `
  --location eastus `
  --template-file ./infra/lab-app.bicep `
  --parameters uniqueName=$labUniqueName `
  --only-show-errors `
  -o json | ConvertFrom-Json

if ($LASTEXITCODE -ne 0) {
  throw "The Graph Bicep deployment failed."
}

$outputs = $deployment.properties.outputs
$env:DEVICE_CODE_LAB_CLIENT_ID = $outputs.clientId.value
$env:DEVICE_CODE_LAB_APP_OBJECT_ID = $outputs.applicationObjectId.value
$env:DEVICE_CODE_LAB_SP_OBJECT_ID = $outputs.servicePrincipalId.value
$env:DEVICE_CODE_LAB_UNIQUE_NAME = $outputs.uniqueName.value
$env:AZURE_TENANT_ID = "<tenant-guid>"
```

Retain the deployment name and those five values until cleanup is verified.
They are identifiers, not credentials, but they are required to prevent
name-based selection. The template stamps both Graph objects with the fixed
owner tag and the deployment-specific `uniqueName` tag.

The template creates:

- one `AzureADMyOrg` application;
- one public-client redirect URI (`http://localhost`);
- one service principal; and
- no password credential, certificate credential, application permission,
  delegated API permission, or admin consent.

### 3. Generate lab-owned telemetry

Sign Azure CLI in as the same dedicated non-admin user that will approve the
browser code:

```powershell
az login --tenant $env:AZURE_TENANT_ID
./scripts/run-device-code-telemetry-test.ps1 -Confirm
```

The generator:

1. verifies the active Azure CLI tenant and Graph user;
2. blocks any active directory-role assignment unless the operator explicitly
   uses `-SkipPrivilegedRoleCheck`;
3. requests only `openid profile`;
4. polls only through the expected `authorization_pending` and `slow_down`
   states;
5. decodes the issued ID token only to compare tenant and user object ID with
   the already verified Azure CLI lab user; and
6. clears the token response without calling mail, Graph, or another workload.

The active-role query cannot prove that the user has no inactive PIM
eligibility. The post-issuance identity comparison also cannot stop a wrong
person from entering the code; it makes that mismatch fatal and discards the
response. Use a boring, dedicated lab account.

### 4. Check ingestion

Set the exact workspace, app, and user scope:

```powershell
$env:SENTINEL_WORKSPACE_ID = "<log-analytics-workspace-guid>"
$env:DEVICE_CODE_LAB_USER = "device-code-lab-user@contoso.com"

./scripts/check-device-code-telemetry.ps1 `
  -RunId "<run-id>" `
  -LookbackHours 2
```

The checker refuses a tenant-wide fallback. It requires the client ID and user
UPN, preserves KQL line breaks so `//` comments cannot break the query, derives
both previews from the tracked Sentinel KQL, and optionally lists incidents
whose `relatedAnalyticRuleIds` contain the exact two deterministic rule IDs.
Provide both resource group and workspace name to enable incident lookup.

Empty results are not command success failures. Ingestion and scheduled-rule
execution can lag, and disabled rules never create incidents.

## Remove the optional Entra app

The cleanup helper never searches by display name, UPN, or collection filter.
It reads the exact object IDs, validates all fixed and deployment-specific
tags, validates the app/client relationship, and rejects objects containing
credentials the template never creates.

Preview:

```powershell
./scripts/cleanup-device-code-lab-artifacts.ps1
```

Execute after reviewing every ID:

```powershell
./scripts/cleanup-device-code-lab-artifacts.ps1 -Execute -Confirm
```

The exact service principal is deleted first. If that delete fails, the
application is left untouched. Any later failure is fatal and is reported
without being converted into success.

User cleanup is deliberately outside this script. If you created a disposable
user or Temporary Access Pass provisioner manually, review and remove it
manually by immutable object ID in the correct tenant. The lab cannot attach
credible provenance to an object it did not create.

## Suggested MITRE mapping

| Rule | Severity | Techniques |
|---|---|---|
| 50199 followed by success | High | T1566.002, T1550.001 |
| Unapproved device-code client | Medium | T1078, T1550.001 |

## Response checklist

1. Revoke the user's sessions.
2. Review Entra risk, Conditional Access results, and authentication details.
3. Review inbox rules, forwarding, delegates, transport rules, and mail access.
4. Review new devices, OAuth grants, app consent, and authentication methods.
5. Search finance, payroll, HR, file, and SaaS events after the sign-in.
6. Convert verified false positives into immutable app-ID exceptions with an
   owner, reason, and review date.

## Cost and licensing

The app registration has no direct compute charge. Costs come from existing Log
Analytics/Sentinel ingestion and retention, plus the Defender and Entra
licenses needed for optional advanced-hunting tables. Run the inventory query
before enabling scheduled rules and confirm the expected query volume.

## Local validation

```powershell
az bicep build --file ./infra/lab-app.bicep --stdout | Out-Null
az bicep build --file ./infra/sentinel-rules.bicep --stdout | Out-Null
python -m unittest discover -s tests -v
```

The repository workflow performs both Bicep builds, parses every PowerShell
script, and runs the offline safety suite. The suite has no third-party Python
dependency.

## Troubleshooting

- **Graph extension restore fails:** verify Bicep 0.36.1 or newer and access to
  `mcr.microsoft.com`.
- **App deployment reports a `uniqueName` conflict:** stop. Generate a new
  GUID-suffixed value for a new lab deployment; do not adopt the existing app.
- **Sentinel preflight reports an ID or display-name collision:** stop and
  inspect the foreign rule. Do not change the owned GUIDs to bypass the check.
- **Provenance manifest is missing:** deploy can proceed only when neither rule
  ID nor display name exists. Removal requires the exact manifest.
- **Role check fails:** restore Microsoft Graph read access or independently
  verify a dedicated non-admin user before explicitly using the bypass.
- **No `50199` row:** the poll-first sequence improves observability but cannot
  guarantee a particular tenant error code.
- **No incident:** rules are disabled by default. First verify raw `SigninLogs`,
  then the scoped query previews, then explicit rule enablement and scheduling.
- **Defender hunt has no rows:** verify that the named product, license,
  connector, and table are present before treating an empty result as evidence.
