# Entra Device Code Phishing Detection Lab

This companion lab supports the Nine Lives, Zero Trust blog post:

`Block Device Code Phishing in Entra Without Breaking Legit Workflows`

Blog: https://nineliveszerotrust.com/blog/entra-device-code-phishing-sentinel/

Lab page: https://nineliveszerotrust.com/labs/entra-device-code-phishing/

The lab focuses on detection engineering for Entra device code phishing without requiring you to run a real phishing flow. It also includes an optional **telemetry generator** that signs in a lab-owned user through a no-secret public client app, discards tokens immediately, and produces real Entra sign-in logs for tuning.

## Threat Model

Device code phishing abuses the OAuth device authorization flow:

1. Attacker starts a device-code flow from their client.
2. Attacker sends the user a code and a link to the legitimate Microsoft device login page.
3. User enters the code and satisfies the approval ceremony.
4. Entra ID issues tokens to the attacker's waiting client.
5. Attacker uses the token for mailbox, Graph, device registration, or SaaS access.

## Data Sources

| Platform | Tables | Requirement |
|---|---|---|
| Microsoft Sentinel | `SigninLogs` | Entra sign-in logs routed to Log Analytics/Sentinel |
| Defender for Office 365 Safe Links | `UrlClickEvents` | URL-click telemetry |
| Defender for Cloud Apps | `CloudAppEvents` | Exchange, device-registration, and SaaS activity |
| Microsoft Defender XDR | `EntraIdSignInEvents` | Microsoft Entra ID P2 data in advanced hunting |

## Queries

### Sentinel

| File | Purpose |
|---|---|
| `kql/sentinel/01-device-code-50199-to-success.kql` | Find `50199` interrupt followed by success |
| `kql/sentinel/02-unapproved-device-code-client.kql` | Inventory and alert on unapproved device-code clients |
| `kql/sentinel/05-device-code-inventory.kql` | Build the 30-day allowlist baseline |

### Defender XDR

| File | Purpose |
|---|---|
| `kql/defender-xdr/01-url-click-to-device-code-auth.kql` | Correlate URL click telemetry with device-code sign-in events |
| `kql/defender-xdr/02-post-token-mailbox-abuse.kql` | Correlate suspicious auth with Exchange mailbox activity |
| `kql/defender-xdr/03-device-registration-after-device-code.kql` | Correlate suspicious auth with device registration |

### Sample Data

| File | Purpose |
|---|---|
| `kql/sample-data/device-code-phishing-replay.kql` | Replay a synthetic chain for query validation |

### Optional Telemetry Generator

| File | Purpose |
|---|---|
| `infra/lab-app.bicep` | Creates the no-secret public client app used only for lab sign-in telemetry |
| `scripts/run-device-code-telemetry-test.ps1` | Generates a lab-owned device-code sign-in ceremony and discards tokens |
| `scripts/check-device-code-telemetry.ps1` | Checks `SigninLogs`, rule correlation output, and optional Sentinel incidents |
| `scripts/cleanup-device-code-lab-artifacts.ps1` | Safely previews or removes the lab app, service principal, optional lab user, and optional TAP provisioner |

Requires PowerShell 7+ for the telemetry scripts. Run them from `pwsh`; the scripts include `#requires -Version 7.0`.

## Suggested Analytics Rules

| Rule | Severity | MITRE |
|---|---|---|
| LAB - Device Code - 50199 Followed by Success | High | T1566.002, T1550.001 |
| LAB - Device Code - Unapproved Client | Medium | T1078, T1550.001 |
| LAB - URL Click Followed by Device Code Auth | High | T1566.002 |
| LAB - Mailbox Abuse After Device Code Auth | High | T1114, T1098 |
| LAB - Device Registration After Device Code Auth | High | T1098 |

## Deploy Sentinel Rules

The Sentinel-native rules deploy from `SigninLogs`:

```bash
az deployment group create \
  --resource-group sentinel-urbac-lab-rg \
  --template-file infra/sentinel-rules.bicep \
  --parameters workspaceName=sentinel-urbac-lab-law
```

The Defender XDR hunts remain advanced hunting queries because they rely on `UrlClickEvents`, `EntraIdSignInEvents`, and `CloudAppEvents`.

## Optional: Run It and See Telemetry

This path turns the lab from "hunt and harden" into "run it, see telemetry, tune detection."

Important safety boundaries:

- Use a lab-only, non-privileged user.
- Do not run this against a real victim.
- The script does not capture, print, store, or use access or refresh tokens.
- Tokens are discarded in memory immediately after issuance.
- The script refuses to run when it detects high-privilege directory roles such as Global Administrator or Privileged Role Administrator.
- The role check covers active directory-role membership. It does not prove a user has no inactive PIM eligibility, so keep the test account boring and non-admin.
- The script may call Microsoft Graph through your existing Azure CLI context for the active-role safety check. It does not use the issued device-code tokens to access mail, Graph, or any workload resource.

### 1. Create the lab public client app

`infra/lab-app.bicep` uses the Microsoft Graph Bicep extension dynamic types to create a no-secret, single-tenant public client application. The Graph extension uses Bicep extensibility features, so expect the experimental/extension tooling path rather than a plain ARM resource provider deployment. Creating this app changes tenant state and requires app-registration permissions such as `Application.ReadWrite.All`.

```bash
az deployment sub create \
  --location eastus \
  --template-file infra/lab-app.bicep \
  --parameters uniqueName=nine-lives-device-code-telemetry-lab \
  --query properties.outputs.clientId.value -o tsv
```

Save the output as `DEVICE_CODE_LAB_CLIENT_ID`.

```powershell
$env:DEVICE_CODE_LAB_CLIENT_ID = "<client-id-from-deployment>"
$env:DEVICE_CODE_LAB_USER = "<lab-user-upn>"
$env:AZURE_TENANT_ID = "<tenant-id>"
```

### 2. Generate lab-owned sign-in telemetry

The script intentionally polls for about 30 seconds before asking you to approve the code. That poll-first pattern is what makes Entra more likely to emit the `50199` interrupt before the successful sign-in. `50199` is a correlation signal, not device-code proof by itself; use it with protocol, app/client, session, correlation, or post-token behavior.

```powershell
cd labs/entra-device-code-phishing
.\scripts\run-device-code-telemetry-test.ps1 -Confirm
```

Expected output:

```text
RunId:     LAB-DC-2026-04-25T20-45-12Z
UserAgent: NineLivesLab/1.0 (run:LAB-DC-2026-04-25T20-45-12Z)

Do NOT approve yet. The script will poll first to generate the 50199 interrupt telemetry.
Verification URL: https://microsoft.com/devicelogin
User code:        ABCD-EFGH

Now approve the sign-in with your LAB account only.
Telemetry test completed. Tokens were discarded without use.
```

### 3. Check ingestion and rule correlation

SigninLogs and Sentinel analytics can lag. Start with a two-hour lookback and rerun after a few minutes if the first query is empty.
The generator prints a run ID for your terminal transcript, but Entra may record the browser approval user-agent instead of the script user-agent. For deterministic checks, pass the lab app client ID and lab user UPN too. The checker treats that app/user pair as a fallback scope, not as proof that every row carried the run ID.

```powershell
$env:SENTINEL_WORKSPACE_ID = "<workspace-guid>"
$env:SENTINEL_RESOURCE_GROUP = "sentinel-urbac-lab-rg"
$env:SENTINEL_WORKSPACE_NAME = "sentinel-urbac-lab-law"

.\scripts\check-device-code-telemetry.ps1 `
  -RunId "LAB-DC-2026-04-25T20-45-12Z" `
  -ClientId $env:DEVICE_CODE_LAB_CLIENT_ID `
  -UserPrincipalName $env:DEVICE_CODE_LAB_USER `
  -LookbackHours 2
```

The check script prints:

1. Raw `SigninLogs` telemetry scoped to the run ID, or to the lab app and lab user when the browser row does not retain the run ID.
2. The Rule 1 `50199 -> success` correlation preview.
3. The Rule 2 unapproved-client preview.
4. Recent Sentinel incidents with `Device Code` in the title when resource group/workspace names are set.

Incident lookup is advisory. Empty incident output means no matching incident has materialized yet; it does not invalidate a `SigninLogs` hit or the rule correlation preview.

### Cleanup the lab app

If you deployed the optional public client app, preview cleanup first:

```powershell
.\scripts\cleanup-device-code-lab-artifacts.ps1 -ClientId $env:DEVICE_CODE_LAB_CLIENT_ID
```

Then run it with explicit execution enabled. PowerShell will still ask for confirmation before each delete:

```powershell
.\scripts\cleanup-device-code-lab-artifacts.ps1 -ClientId $env:DEVICE_CODE_LAB_CLIENT_ID -Execute
```

If you also created a disposable lab user, pass an exact identifier for that user:

```powershell
.\scripts\cleanup-device-code-lab-artifacts.ps1 `
  -ClientId $env:DEVICE_CODE_LAB_CLIENT_ID `
  -LabUserPrincipalName "device-code-lab-user@contoso.com" `
  -Execute
```

If you created a temporary user only to provision a Temporary Access Pass, include that exact user too:

```powershell
.\scripts\cleanup-device-code-lab-artifacts.ps1 `
  -ClientId $env:DEVICE_CODE_LAB_CLIENT_ID `
  -LabUserPrincipalName "device-code-lab-user@contoso.com" `
  -TapProvisionerPrincipalName "tap-provisioner@contoso.com" `
  -Execute
```

The helper defaults to dry-run mode, refuses ambiguous display-name matches, and deletes the service principal only when it belongs to the matched lab app or is explicitly selected. Delete lab users only when they were created solely for this lab.

## Triage

When a rule fires:

1. Revoke sign-in sessions for the user.
2. Check Entra ID Protection user risk and sign-in risk.
3. Review mailbox rules, forwarding, delegates, and transport rules.
4. Review OAuth app grants and newly registered devices.
5. Search payroll, finance, HR, and Workday-style app events after the sign-in.
6. Convert confirmed false positives into a documented device-code allowlist.

## Notes

- Do not blindly block device code flow before inventorying legitimate dependencies.
- Use Conditional Access report-only mode first.
- `50199 -> success` is a correlation signal, not a complete verdict.
- Legitimate Azure CLI sign-ins can produce `50199 -> success`; keep both app display names and app IDs in your allowlist. In Entra logs, Azure CLI commonly appears as `Microsoft Azure CLI`.
- Treat Microsoft Authentication Broker as a sensitive exception, not a default allowlist entry. Add it only for documented brokered-auth or device-registration scenarios with extra controls and monitoring.
- Post-auth behavior is where device code phishing turns into business impact.
- The telemetry generator creates authentication telemetry only; it does not simulate URL clicks, mailbox access, or device registration.
