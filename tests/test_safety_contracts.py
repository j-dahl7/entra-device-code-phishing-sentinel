import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


LAB_ROOT = Path(__file__).resolve().parents[1]
INFRA = LAB_ROOT / "infra"
SCRIPTS = LAB_ROOT / "scripts"
KQL = LAB_ROOT / "kql"

RULE_IDS = (
    "45543375-c81a-56ab-b020-b3cc3bcf652e",
    "0d879be9-2084-5bee-bf5b-8effbf4d8c64",
)
OWNER_TAG = "NineLives.Owner:EntraDeviceCodePhishingSentinel:v1"
UNIQUE_NAME = (
    "nine-lives-device-code-telemetry-lab-"
    "11111111-1111-4111-8111-111111111111"
)
TENANT_ID = "22222222-2222-4222-8222-222222222222"
CLIENT_ID = "33333333-3333-4333-8333-333333333333"
APP_OBJECT_ID = "44444444-4444-4444-8444-444444444444"
SP_OBJECT_ID = "55555555-5555-4555-8555-555555555555"
GRAPH_SP_OBJECT_ID = "77777777-7777-4777-8777-777777777777"
LAB_USER_OBJECT_ID = "88888888-8888-4888-8888-888888888888"
OTHER_OBJECT_ID = "99999999-9999-4999-8999-999999999999"
MICROSOFT_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
GRANT_SCOPE = "openid profile"
# Opaque fixture identifiers in Microsoft Graph's URL-safe alphabet. Cleanup
# compares a grant ID exactly and never derives or parses one.
GRANT_ID = "b2ZmbGluZS1maXh0dXJl_WxhYi1ncmFudC0wMDAx-W5vdC1hLXJlYWwtb2JqZWN0"
OTHER_GRANT_ID = "b2ZmbGluZS1maXh0dXJlLW90aGVy_WdyYW50LTAwMDIt-m90LXJlYWwtb2JqZWN0"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def cleanup_arguments(*extra: str, grant: bool = True) -> list:
    arguments = [
        "-TenantId", f"'{TENANT_ID}'",
        "-ClientId", f"'{CLIENT_ID}'",
        "-AppObjectId", f"'{APP_OBJECT_ID}'",
        "-ServicePrincipalObjectId", f"'{SP_OBJECT_ID}'",
        "-UniqueName", f"'{UNIQUE_NAME}'",
    ]
    if grant:
        arguments += ["-PermissionGrantId", f"'{GRANT_ID}'"]
    return arguments + list(extra)


def flatten_error(stderr: str) -> str:
    # PowerShell wraps long error text at the console width and prefixes the
    # continuation lines, so match phrases on one normalized line.
    without_colors = re.sub(r"\x1b\[[0-9;]*m", "", stderr)
    return re.sub(r"\s*\n[ \t]*\|?[ \t]*", " ", without_colors)


class StaticSafetyContractTests(unittest.TestCase):
    def test_sentinel_rules_use_fixed_guids_provenance_and_disabled_default(self):
        source = read(INFRA / "sentinel-rules.bicep")
        for rule_id in RULE_IDS:
            self.assertIn(rule_id, source)
        self.assertIn("param enableRules bool = false", source)
        self.assertEqual(source.count("enabled: enableRules"), 2)
        self.assertIn("param deploymentId string", source)
        self.assertEqual(source.count("var ruleDeviceCode"), 3)
        self.assertEqual(source.count("[Owner:"), 2)
        self.assertIn(
            "loadTextContent('../kql/sentinel/01-device-code-50199-to-success.kql')",
            source,
        )
        self.assertIn(
            "loadTextContent('../kql/sentinel/02-unapproved-device-code-client.kql')",
            source,
        )

    def test_sentinel_rules_send_parent_technique_ids_on_the_stable_api(self):
        source = read(INFRA / "sentinel-rules.bicep")
        self.assertEqual(
            source.count("'Microsoft.SecurityInsights/alertRules@2024-03-01'"), 2
        )
        # 2024-03-01 has no subTechniques property, and Sentinel rejects a
        # dotted ID in techniques: "The expected format is 'T####'".
        self.assertNotRegex(source, r"(?m)^\s*subTechniques\s*:")
        blocks = re.findall(r"(?m)^\s*techniques:\s*\[(.*?)\]", source, re.DOTALL)
        self.assertEqual(len(blocks), 2)
        for block in blocks:
            techniques = re.findall(r"'([^']+)'", block)
            self.assertTrue(techniques)
            for technique in techniques:
                self.assertRegex(technique, r"^T\d{4}$")

        readme = read(LAB_ROOT / "README.md")
        self.assertIn("| 50199 followed by success | High | T1566, T1550 |", readme)
        self.assertIn("| Unapproved device-code client | Medium | T1078, T1550 |", readme)

    def test_sentinel_lifecycle_refuses_adoption_and_requires_exact_state(self):
        source = read(SCRIPTS / "manage-sentinel-rules.ps1")
        for rule_id in RULE_IDS:
            self.assertIn(rule_id, source)
        self.assertIn("Refusing to adopt it", source)
        self.assertIn("Exact provenance manifest is required", source)
        self.assertIn("Assert-RuleInventory", source)
        self.assertIn("description.EndsWith", source)
        self.assertNotIn("az sentinel", source)
        self.assertNotIn("|| true", source)

    def test_graph_cleanup_has_no_name_or_user_deletion_path(self):
        source = read(SCRIPTS / "cleanup-device-code-lab-artifacts.ps1")
        forbidden = (
            "Find-GraphObjects",
            "Resolve-SingleObject",
            "displayName eq",
            "userPrincipalName eq",
            "LabUserObjectId",
            "TapProvisionerObjectId",
            "ValidateSet('applications', 'servicePrincipals', 'users')",
            # The delegated grant is read by exact ID and by exact-ID
            # navigation, never through a collection filter.
            "$filter",
            "clientId eq",
            "principalId eq",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, source)
        self.assertIn("never selected or deleted by this script", source)
        self.assertIn("Two-phase cleanup", source)
        self.assertIn("AppObjectId", source)
        self.assertIn("ServicePrincipalObjectId", source)
        self.assertIn("UniqueName", source)
        self.assertIn("PermissionGrantId", source)
        self.assertIn(OWNER_TAG, source)
        self.assertEqual(
            source.count(
                "ValidateSet('applications', 'servicePrincipals', 'oauth2PermissionGrants')"
            ),
            3,
        )

    def test_graph_template_has_unique_provenance_and_no_secret(self):
        source = read(INFRA / "lab-app.bicep")
        self.assertRegex(source, r"(?m)^param uniqueName string$")
        self.assertNotIn("param uniqueName string =", source)
        self.assertIn(OWNER_TAG, source)
        self.assertIn("NineLives.UniqueName:", source)
        self.assertIn("uniqueNameTag", source)
        self.assertIn("output applicationObjectId string", source)
        self.assertIn("output servicePrincipalId string", source)
        self.assertNotIn("passwordCredentials:", source)

    def test_graph_template_consents_only_for_the_lab_user_and_requested_scopes(self):
        source = read(INFRA / "lab-app.bicep")
        runner = read(SCRIPTS / "run-device-code-telemetry-test.ps1")
        cleanup = read(SCRIPTS / "cleanup-device-code-lab-artifacts.ps1")

        # Assignment is required, which is why the non-admin lab user needs a
        # grant. Exactly one grant exists and it names one user.
        self.assertIn("appRoleAssignmentRequired: true", source)
        grants = re.findall(
            r"(?ms)^resource \w+ 'graphV1:Microsoft\.Graph/oauth2PermissionGrants@v1\.0' = \{\n(.*?)^\}",
            source,
        )
        self.assertEqual(len(grants), 1)
        properties = dict(re.findall(r"(?m)^  (\w+): (.+)$", grants[0]))
        self.assertEqual(
            properties,
            {
                "clientId": "servicePrincipal.id",
                "consentType": "'Principal'",
                "principalId": "labUserObjectId",
                "resourceId": "microsoftGraph.id",
                "scope": "labUserDelegatedScope",
            },
        )
        self.assertEqual(len(re.findall(r"(?m)^\s*consentType\s*:", source)), 1)
        self.assertNotRegex(source, r"(?m)^\s*consentType\s*:\s*'AllPrincipals'")
        # No application permission and no declared API permission.
        self.assertNotIn("requiredResourceAccess", source)
        assignments = re.findall(
            r"(?ms)^resource \w+ 'graphV1:Microsoft\.Graph/appRoleAssignedTo@v1\.0' = \{\n(.*?)^\}",
            source,
        )
        self.assertEqual(len(assignments), 1)
        self.assertIn("principalId: labUserObjectId", assignments[0])

        # The resource is the tenant's existing Microsoft Graph service principal.
        self.assertRegex(
            source,
            r"(?m)^resource microsoftGraph 'graphV1:Microsoft\.Graph/servicePrincipals@v1\.0' existing = \{\n  appId: microsoftGraphAppId\n\}$",
        )
        self.assertIn(f"var microsoftGraphAppId = '{MICROSOFT_GRAPH_APP_ID}'", source)
        self.assertIn(f"$microsoftGraphAppId = '{MICROSOFT_GRAPH_APP_ID}'", cleanup)

        # Template, generator and cleanup must agree on the exact scopes.
        granted = re.search(r"(?m)^var labUserDelegatedScope = '([^']+)'$", source)[1]
        requested = re.search(r"(?m)^\$fixedScope = '([^']+)'$", runner)[1]
        accepted = re.search(r"(?m)^\$expectedGrantScopes = @\(([^)]*)\)$", cleanup)[1]
        self.assertEqual(granted, GRANT_SCOPE)
        self.assertEqual(granted, requested)
        self.assertEqual(re.findall(r"'([^']+)'", accepted), granted.split())

        # Cleanup needs the exact grant ID, so the template must return it.
        self.assertIn(
            "output delegatedPermissionGrantId string = labUserConsent.id", source
        )

    def test_allowlists_never_trust_display_names(self):
        sentinel_files = (
            KQL / "sentinel" / "01-device-code-50199-to-success.kql",
            KQL / "sentinel" / "02-unapproved-device-code-client.kql",
            KQL / "sample-data" / "device-code-phishing-replay.kql",
        )
        for path in sentinel_files:
            source = read(path)
            with self.subTest(path=path.name):
                self.assertNotIn("ApprovedDeviceCodeApps", source)
                self.assertNotIn("ApprovedDeviceCodeAppIds", source)
                self.assertIn("Display names are attacker-controlled", source)

    def test_url_click_hunt_matches_complete_url_paths_as_substrings(self):
        source = read(
            KQL / "defender-xdr" / "01-url-click-to-device-code-auth.kql"
        )
        self.assertNotIn("has_any", source)
        self.assertEqual(source.count('contains "microsoft.com/devicelogin"'), 2)
        self.assertEqual(
            source.count(
                'contains "login.microsoftonline.com/common/oauth2/deviceauth"'
            ),
            2,
        )

    def test_defender_joins_use_immutable_object_ids_where_available(self):
        mailbox = read(KQL / "defender-xdr" / "02-post-token-mailbox-abuse.kql")
        registration = read(
            KQL / "defender-xdr" / "03-device-registration-after-device-code.kql"
        )
        self.assertIn(
            "join kind=inner DeviceCodeSuccesses on AccountObjectId, SessionId",
            mailbox,
        )
        self.assertIn(
            "join kind=inner SuspiciousDeviceCodeSessions on AccountObjectId",
            mailbox,
        )
        self.assertNotIn("extend AccountUpn = tolower(AccountId)", mailbox)
        self.assertIn(
            "$left.RegistrationUserObjectId == $right.AccountObjectId",
            registration,
        )
        self.assertNotIn(
            "join kind=inner SuspiciousDeviceCodeSessions on AccountUpn",
            registration,
        )

    def test_telemetry_scripts_keep_failures_fatal_and_scopes_fixed(self):
        runner = read(SCRIPTS / "run-device-code-telemetry-test.ps1")
        checker = read(SCRIPTS / "check-device-code-telemetry.ps1")
        self.assertIn("$fixedScope = 'openid profile'", runner)
        self.assertNotRegex(runner, r"(?m)^\s*\[string\]\$Scope")
        self.assertIn("Assert-IssuedIdentity", runner)
        self.assertIn("Device-code polling failed", runner)
        self.assertIn("UserPrincipalName is required", checker)
        self.assertIn("Keep line breaks intact", checker)
        self.assertNotIn("ConvertTo-SingleLineKql", checker)
        self.assertIn("relatedAnalyticRuleIds", checker)

    def test_documented_sentinel_path_preserves_preflight_guarantees(self):
        readme = read(LAB_ROOT / "README.md")
        self.assertIn("manage-sentinel-rules.ps1 -Execute -Confirm", readme)
        self.assertIn("manage-sentinel-rules.ps1 -Action Remove", readme)
        self.assertIn("Direct deployment of `infra/sentinel-rules.bicep` is unsupported", readme)
        self.assertNotIn("az deployment group create", readme)
        self.assertNotIn("az sentinel alert-rule delete", readme)

    def test_readme_documents_the_grant_lifecycle_and_its_untested_boundary(self):
        readme = read(LAB_ROOT / "README.md")
        for value in (
            "DelegatedPermissionGrant.ReadWrite.All",
            "$env:DEVICE_CODE_LAB_GRANT_ID = $outputs.delegatedPermissionGrantId.value",
            "`consentType` `Principal`",
            "offline checks only",
            "November 13, 2026",
        ):
            with self.subTest(value=value):
                self.assertIn(value, readme)
        # The template no longer creates "no delegated permission or consent".
        self.assertNotIn("delegated API permission, or admin consent", readme)

    def test_readme_response_checklist_matches_the_exact_context_rule_design(self):
        readme = read(LAB_ROOT / "README.md")
        rule = read(KQL / "sentinel" / "02-unapproved-device-code-client.kql")
        # Rule 2 accepts only app/user/IP tuples, so the checklist cannot
        # recommend an exception keyed on an application ID alone.
        self.assertIn(
            "datatable(ApprovedAppId:string, ApprovedUserId:string, ApprovedIPAddress:string)",
            rule,
        )
        self.assertIn(
            "6. Record verified false positives as exact app/user/IP contexts with an",
            readme,
        )
        self.assertNotIn("app-ID exceptions", readme)


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is required")
class PowerShellPreflightRuntimeTests(unittest.TestCase):
    def run_script(self, script: Path, arguments, mode: str):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            call_log = temp / "calls.log"
            state_path = temp / "sentinel-state.json"
            runner = temp / "runner.ps1"
            script_literal = str(script).replace("'", "''")
            argument_text = " ".join(arguments).replace(
                "{STATE_PATH}", str(state_path).replace("'", "''")
            )
            runner.write_text(
                textwrap.dedent(
                    f"""
                    $ErrorActionPreference = 'Stop'
                    function global:az {{
                      $line = ($args | ForEach-Object {{ [string]$_ }}) -join ' '
                      [System.IO.File]::AppendAllText(
                        $env:MOCK_CALL_LOG,
                        $line + [Environment]::NewLine
                      )
                      $global:LASTEXITCODE = 0
                      if ($args[0] -eq 'account' -and $args[1] -eq 'show') {{
                        '{{"id":"66666666-6666-4666-8666-666666666666","tenantId":"{TENANT_ID}","user":{{"type":"user","name":"lab@example.com"}}}}'
                        return
                      }}
                      if ($args[0] -eq 'rest' -and $args -contains 'GET') {{
                        $urlIndex = [array]::IndexOf($args, '--url')
                        $url = [string]$args[$urlIndex + 1]
                        if ($url -like '*Microsoft.SecurityInsights/alertRules*') {{
                          if ($env:MOCK_MODE -eq 'sentinel-collision') {{
                            '{{"value":[{{"name":"{RULE_IDS[0]}","kind":"Scheduled","properties":{{"displayName":"LAB - Device Code - 50199 Followed by Success","description":"foreign","enabled":false}}}}]}}'
                          }} elseif ($env:MOCK_MODE -eq 'sentinel-deploy' -and $global:MockDeployed) {{
                            @{{
                              value = @(
                                @{{
                                  name = '{RULE_IDS[0]}'
                                  kind = 'Scheduled'
                                  properties = @{{
                                    displayName = 'LAB - Device Code - 50199 Followed by Success'
                                    description = 'Mock [Owner: nine-lives-zero-trust:entra-device-code-phishing-sentinel:v1; Deployment: ' + $global:MockDeploymentId + '; Rule: device-code-50199-to-success]'
                                    enabled = $false
                                  }}
                                }},
                                @{{
                                  name = '{RULE_IDS[1]}'
                                  kind = 'Scheduled'
                                  properties = @{{
                                    displayName = 'LAB - Device Code - Unapproved Client'
                                    description = 'Mock [Owner: nine-lives-zero-trust:entra-device-code-phishing-sentinel:v1; Deployment: ' + $global:MockDeploymentId + '; Rule: device-code-unapproved-client]'
                                    enabled = $false
                                  }}
                                }}
                              )
                            }} | ConvertTo-Json -Compress -Depth 6
                          }} else {{
                            '{{"value":[]}}'
                          }}
                          return
                        }}
                        if ($url -like '*applications/{APP_OBJECT_ID}*') {{
                          $tags = @(
                            '{OWNER_TAG}',
                            'NineLives.UniqueName:{UNIQUE_NAME}',
                            'NineLivesZeroTrust',
                            'Lab',
                            'DeviceCodeTelemetry',
                            'NoSecrets'
                          )
                          if ($env:MOCK_MODE -eq 'graph-foreign') {{
                            $tags = @('foreign')
                          }}
                          @{{
                            id = '{APP_OBJECT_ID}'
                            appId = '{CLIENT_ID}'
                            displayName = 'LAB app'
                            uniqueName = '{UNIQUE_NAME}'
                            tags = $tags
                            signInAudience = 'AzureADMyOrg'
                            isFallbackPublicClient = $true
                            publicClient = @{{ redirectUris = @('http://localhost') }}
                            passwordCredentials = @()
                            keyCredentials = @()
                          }} | ConvertTo-Json -Compress -Depth 5
                          return
                        }}
                        if ($url -like '*servicePrincipals/{SP_OBJECT_ID}/oauth2PermissionGrants*') {{
                          $listedIds = @(switch ($env:MOCK_MODE) {{
                            'graph-legacy' {{ }}
                            'grant-absent' {{ }}
                            'grant-unlisted' {{ }}
                            'grant-absent-listed' {{ '{OTHER_GRANT_ID}' }}
                            'grant-extra' {{ '{GRANT_ID}'; '{OTHER_GRANT_ID}' }}
                            default {{ '{GRANT_ID}' }}
                          }})
                          $listed = [System.Collections.Generic.List[object]]::new()
                          foreach ($listedId in $listedIds) {{
                            $listed.Add(@{{ id = $listedId; clientId = '{SP_OBJECT_ID}' }})
                          }}
                          @{{ value = $listed.ToArray() }} | ConvertTo-Json -Compress -Depth 5
                          return
                        }}
                        if ($url -like '*oauth2PermissionGrants/{GRANT_ID}*') {{
                          if ($env:MOCK_MODE -in @('graph-partial', 'graph-replacement', 'grant-absent', 'grant-absent-listed')) {{
                            $global:LASTEXITCODE = 1
                            'ERROR: Not Found({{"error":{{"code":"Request_ResourceNotFound"}}}})'
                            return
                          }}
                          $grant = @{{
                            id = '{GRANT_ID}'
                            clientId = '{SP_OBJECT_ID}'
                            consentType = 'Principal'
                            principalId = '{LAB_USER_OBJECT_ID}'
                            resourceId = '{GRAPH_SP_OBJECT_ID}'
                            scope = '{GRANT_SCOPE}'
                          }}
                          switch ($env:MOCK_MODE) {{
                            'grant-wide-scope' {{ $grant.scope = '{GRANT_SCOPE} Mail.Read' }}
                            'grant-all-principals' {{ $grant.consentType = 'AllPrincipals'; $grant.principalId = $null }}
                            'grant-foreign-client' {{ $grant.clientId = '{OTHER_OBJECT_ID}' }}
                          }}
                          $grant | ConvertTo-Json -Compress -Depth 5
                          return
                        }}
                        if ($url -like '*servicePrincipals/{GRAPH_SP_OBJECT_ID}*') {{
                          $resourceAppId = '{MICROSOFT_GRAPH_APP_ID}'
                          if ($env:MOCK_MODE -eq 'grant-foreign-resource') {{ $resourceAppId = '{OTHER_OBJECT_ID}' }}
                          @{{ id = '{GRAPH_SP_OBJECT_ID}'; appId = $resourceAppId }} | ConvertTo-Json -Compress
                          return
                        }}
                        if ($url -like '*servicePrincipals/{SP_OBJECT_ID}*') {{
                          if ($env:MOCK_MODE -in @('graph-partial', 'graph-denied', 'graph-replacement', 'grant-orphaned')) {{
                            $global:LASTEXITCODE = 1
                            if ($env:MOCK_MODE -eq 'graph-denied') {{ 'ERROR: Forbidden({{"error":{{"code":"Authorization_RequestDenied"}}}})' }}
                            else {{ 'ERROR: Not Found({{"error":{{"code":"Request_ResourceNotFound"}}}})' }}
                            return
                          }}
                          @{{
                            id = '{SP_OBJECT_ID}'
                            appId = '{CLIENT_ID}'
                            displayName = 'LAB service principal'
                            tags = @(
                              '{OWNER_TAG}',
                              'NineLives.UniqueName:{UNIQUE_NAME}',
                              'NineLivesZeroTrust',
                              'Lab',
                              'DeviceCodeTelemetry',
                              'NoSecrets'
                            )
                            servicePrincipalType = 'Application'
                            appOwnerOrganizationId = '{TENANT_ID}'
                          }} | ConvertTo-Json -Compress -Depth 5
                          return
                        }}
                        if ($url -like '*servicePrincipals(appId=*') {{
                          if ($env:MOCK_MODE -eq 'graph-replacement') {{ '{{"id":"replacement"}}' }}
                          else {{
                            $global:LASTEXITCODE = 1
                            'ERROR: Not Found({{"error":{{"code":"Request_ResourceNotFound"}}}})'
                          }}
                          return
                        }}
                      }}
                      if ($args[0] -eq 'rest' -and $args -contains 'DELETE') {{
                        if ($env:MOCK_MODE -eq 'grant-delete-fails') {{
                          $global:LASTEXITCODE = 1
                          'ERROR: Forbidden({{"error":{{"code":"Authorization_RequestDenied"}}}})'
                        }}
                        return
                      }}
                      if ($args[0] -eq 'deployment' -and $args[1] -eq 'group' -and $args[2] -eq 'create') {{
                        $deploymentParameter = @($args | Where-Object {{ [string]$_ -like 'deploymentId=*' }})[0]
                        $global:MockDeploymentId = ([string]$deploymentParameter).Split('=', 2)[1]
                        $global:MockDeployed = $true
                        '{{"properties":{{"provisioningState":"Succeeded"}}}}'
                        return
                      }}
                      $global:LASTEXITCODE = 91
                      'unexpected mock invocation'
                    }}
                    & '{script_literal}' {argument_text}
                    """
                ),
                encoding="utf-8",
            )
            environment = {
                **os.environ,
                "MOCK_CALL_LOG": str(call_log),
                "MOCK_MODE": mode,
            }
            # The pre-grant cleanup case must not inherit a recorded grant ID.
            environment.pop("DEVICE_CODE_LAB_GRANT_ID", None)
            result = subprocess.run(
                ["pwsh", "-NoLogo", "-NoProfile", "-File", str(runner)],
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )
            calls = call_log.read_text(encoding="utf-8") if call_log.exists() else ""
            return result, calls

    def test_sentinel_collision_fails_before_mutation(self):
        result, calls = self.run_script(
            SCRIPTS / "manage-sentinel-rules.ps1",
            [
                "-ResourceGroup", "'rg-lab'",
                "-WorkspaceName", "'law-lab'",
            ],
            "sentinel-collision",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to adopt it", result.stderr)
        self.assertNotIn("deployment group create", calls)
        self.assertNotIn("DELETE", calls)

    def test_sentinel_deploy_creates_manifest_and_verifies_disabled_rules(self):
        result, calls = self.run_script(
            SCRIPTS / "manage-sentinel-rules.ps1",
            [
                "-ResourceGroup", "'rg-lab'",
                "-WorkspaceName", "'law-lab'",
                "-StatePath", "'{STATE_PATH}'",
                "-Execute",
                "-Confirm:$false",
            ],
            "sentinel-deploy",
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("deployment group create", calls)
        self.assertIn("enableRules=false", calls)
        self.assertIn("Verified two exact owner-marked Sentinel rules", result.stdout)

    def test_cleanup_dry_run_reads_exact_ids_and_never_deletes(self):
        result, calls = self.run_script(
            SCRIPTS / "cleanup-device-code-lab-artifacts.ps1",
            [
                "-TenantId", f"'{TENANT_ID}'",
                "-ClientId", f"'{CLIENT_ID}'",
                "-AppObjectId", f"'{APP_OBJECT_ID}'",
                "-ServicePrincipalObjectId", f"'{SP_OBJECT_ID}'",
                "-UniqueName", f"'{UNIQUE_NAME}'",
                "-PermissionGrantId", f"'{GRANT_ID}'",
            ],
            "graph-owned",
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn(f"applications/{APP_OBJECT_ID}", calls)
        self.assertIn(f"servicePrincipals/{SP_OBJECT_ID}", calls)
        self.assertIn(f"oauth2PermissionGrants/{GRANT_ID}", calls)
        self.assertIn(f"servicePrincipals/{GRAPH_SP_OBJECT_ID}", calls)
        self.assertIn(f"servicePrincipals/{SP_OBJECT_ID}/oauth2PermissionGrants", calls)
        self.assertNotIn("DELETE", calls)
        self.assertIn(
            f'Delegated grant:          id="{GRANT_ID}", consentType="Principal", '
            f'scope="{GRANT_SCOPE}", consented user object="{LAB_USER_OBJECT_ID}"',
            result.stdout,
        )

    def test_cleanup_foreign_marker_fails_before_delete(self):
        result, calls = self.run_script(
            SCRIPTS / "cleanup-device-code-lab-artifacts.ps1",
            [
                "-TenantId", f"'{TENANT_ID}'",
                "-ClientId", f"'{CLIENT_ID}'",
                "-AppObjectId", f"'{APP_OBJECT_ID}'",
                "-ServicePrincipalObjectId", f"'{SP_OBJECT_ID}'",
                "-UniqueName", f"'{UNIQUE_NAME}'",
                "-Execute",
                "-Confirm:$false",
            ],
            "graph-foreign",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing exact ownership tag", result.stderr)
        self.assertNotIn("DELETE", calls)

    def test_cleanup_execute_deletes_only_exact_ids_in_safe_order(self):
        result, calls = self.run_script(
            SCRIPTS / "cleanup-device-code-lab-artifacts.ps1",
            [
                "-TenantId", f"'{TENANT_ID}'",
                "-ClientId", f"'{CLIENT_ID}'",
                "-AppObjectId", f"'{APP_OBJECT_ID}'",
                "-ServicePrincipalObjectId", f"'{SP_OBJECT_ID}'",
                "-UniqueName", f"'{UNIQUE_NAME}'",
                "-PermissionGrantId", f"'{GRANT_ID}'",
                "-Execute",
                "-Confirm:$false",
            ],
            "graph-owned",
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        delete_calls = [line for line in calls.splitlines() if " DELETE " in f" {line} "]
        self.assertEqual(len(delete_calls), 3)
        self.assertIn(f"oauth2PermissionGrants/{GRANT_ID}", delete_calls[0])
        self.assertIn(f"servicePrincipals/{SP_OBJECT_ID}", delete_calls[1])
        self.assertNotIn("oauth2PermissionGrants", delete_calls[1])
        self.assertIn(f"applications/{APP_OBJECT_ID}", delete_calls[2])
        # The grant's resource and its user are read or reported, never deleted.
        for line in delete_calls:
            self.assertNotIn(GRAPH_SP_OBJECT_ID, line)
            self.assertNotIn(LAB_USER_OBJECT_ID, line)

    def test_cleanup_refuses_unrecorded_or_unexpected_delegated_grants(self):
        cases = (
            # A grant exists but the operator did not supply its recorded ID.
            ("graph-owned", False, "no PermissionGrantId was supplied"),
            # The recorded grant no longer has the shape the template creates.
            ("grant-wide-scope", True, "does not carry exactly the scopes"),
            ("grant-all-principals", True, "only grants Principal consent"),
            ("grant-foreign-client", True, "delegated permission grant client ID mismatch"),
            ("grant-foreign-resource", True, "not Microsoft Graph"),
            # Another grant is attached to the same service principal.
            ("grant-extra", True, "that the lab template never creates"),
            # The exact-ID read and the service principal's list disagree.
            ("grant-unlisted", True, "exactly once"),
        )
        for mode, with_grant, message in cases:
            with self.subTest(mode=mode):
                result, calls = self.run_script(
                    SCRIPTS / "cleanup-device-code-lab-artifacts.ps1",
                    cleanup_arguments("-Execute", "-Confirm:$false", grant=with_grant),
                    mode,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, flatten_error(result.stderr))
                self.assertNotIn(" DELETE ", calls)

    def test_cleanup_rejects_a_malformed_grant_id_before_any_cloud_call(self):
        for value in ("'not a grant id'", "'../servicePrincipals'", "'short'"):
            with self.subTest(value=value):
                result, calls = self.run_script(
                    SCRIPTS / "cleanup-device-code-lab-artifacts.ps1",
                    cleanup_arguments("-PermissionGrantId", value, "-Execute", "-Confirm:$false", grant=False),
                    "graph-owned",
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("exact delegatedPermissionGrantId value", flatten_error(result.stderr))
                self.assertEqual(calls, "")

    def test_cleanup_stops_when_the_grant_delete_fails(self):
        result, calls = self.run_script(
            SCRIPTS / "cleanup-device-code-lab-artifacts.ps1",
            cleanup_arguments("-Execute", "-Confirm:$false"),
            "grant-delete-fails",
        )
        self.assertNotEqual(result.returncode, 0)
        deletes = [line for line in calls.splitlines() if " DELETE " in line]
        self.assertEqual(len(deletes), 1)
        self.assertIn(f"oauth2PermissionGrants/{GRANT_ID}", deletes[0])
        self.assertNotIn("Cleanup completed", result.stdout)

    def test_cleanup_resume_accepts_an_absent_grant_only_with_nothing_else_attached(self):
        arguments = cleanup_arguments("-Execute", "-Confirm:$false")
        script = SCRIPTS / "cleanup-device-code-lab-artifacts.ps1"

        failed, calls = self.run_script(script, arguments, "grant-absent")
        self.assertNotEqual(failed.returncode, 0)
        self.assertNotIn(" DELETE ", calls)

        resumed, calls = self.run_script(script, arguments + ["-ResumePartial"], "grant-absent")
        self.assertEqual(resumed.returncode, 0, resumed.stderr or resumed.stdout)
        deletes = [line for line in calls.splitlines() if " DELETE " in line]
        self.assertEqual(len(deletes), 2)
        self.assertIn(f"servicePrincipals/{SP_OBJECT_ID}", deletes[0])
        self.assertIn(f"applications/{APP_OBJECT_ID}", deletes[1])
        self.assertIn("Recorded delegated permission grant is already absent.", resumed.stdout)

        blocked, calls = self.run_script(script, arguments + ["-ResumePartial"], "grant-absent-listed")
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn(
            "still holds a delegated permission grant after the recorded grant ID was absent",
            flatten_error(blocked.stderr),
        )
        self.assertNotIn(" DELETE ", calls)

    def test_cleanup_without_a_grant_id_supports_pre_grant_deployments(self):
        result, calls = self.run_script(
            SCRIPTS / "cleanup-device-code-lab-artifacts.ps1",
            cleanup_arguments("-Execute", "-Confirm:$false", grant=False),
            "graph-legacy",
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        # The service principal's own grant list is still consulted, and it
        # must be empty before the two legacy objects are removed.
        self.assertIn(f"servicePrincipals/{SP_OBJECT_ID}/oauth2PermissionGrants", calls)
        self.assertNotIn(f"oauth2PermissionGrants/{GRANT_ID}", calls)
        deletes = [line for line in calls.splitlines() if " DELETE " in line]
        self.assertEqual(len(deletes), 2)
        self.assertIn(f"servicePrincipals/{SP_OBJECT_ID}", deletes[0])
        self.assertIn(f"applications/{APP_OBJECT_ID}", deletes[1])
        self.assertIn("Delegated grant:          none recorded for this deployment", result.stdout)

    def test_partial_cleanup_requires_explicit_resume_and_definitive_absence(self):
        # Run with the recorded grant ID and as a pre-grant deployment without one.
        for with_grant in (True, False):
            arguments = cleanup_arguments('-Execute', '-Confirm:$false', grant=with_grant)
            failed, calls = self.run_script(SCRIPTS / 'cleanup-device-code-lab-artifacts.ps1', arguments, 'graph-partial')
            self.assertNotEqual(failed.returncode, 0)
            self.assertNotIn(' DELETE ', calls)
            for mode in ('graph-partial', 'graph-denied', 'graph-replacement'):
                with self.subTest(mode=mode, with_grant=with_grant):
                    result, calls = self.run_script(SCRIPTS / 'cleanup-device-code-lab-artifacts.ps1', arguments + ['-ResumePartial'], mode)
                    deletes = [line for line in calls.splitlines() if ' DELETE ' in line]
                    if mode == 'graph-partial':
                        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
                        self.assertEqual(len(deletes), 1)
                        self.assertIn(f'applications/{APP_OBJECT_ID}', deletes[0])
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(deletes, [])

    def test_resume_refuses_a_grant_whose_client_service_principal_is_gone(self):
        # Without the owner-tagged service principal the grant's ownership
        # cannot be proven, so nothing is deleted, the application included.
        result, calls = self.run_script(
            SCRIPTS / "cleanup-device-code-lab-artifacts.ps1",
            cleanup_arguments("-Execute", "-Confirm:$false", "-ResumePartial"),
            "grant-orphaned",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "its client service principal is absent",
            flatten_error(result.stderr),
        )
        self.assertNotIn(" DELETE ", calls)


if __name__ == "__main__":
    unittest.main()
