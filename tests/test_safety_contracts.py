import os
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


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


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
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, source)
        self.assertIn("never selected or deleted by this script", source)
        self.assertIn("Two-phase cleanup", source)
        self.assertIn("AppObjectId", source)
        self.assertIn("ServicePrincipalObjectId", source)
        self.assertIn("UniqueName", source)
        self.assertIn(OWNER_TAG, source)

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
                self.assertIn("ApprovedDeviceCodeAppIds", source)
                self.assertIn("Display names are attacker-controlled", source)

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
                        if ($url -like '*servicePrincipals/{SP_OBJECT_ID}*') {{
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
                      }}
                      if ($args[0] -eq 'rest' -and $args -contains 'DELETE') {{
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
            ],
            "graph-owned",
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn(f"applications/{APP_OBJECT_ID}", calls)
        self.assertIn(f"servicePrincipals/{SP_OBJECT_ID}", calls)
        self.assertNotIn("DELETE", calls)

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
                "-Execute",
                "-Confirm:$false",
            ],
            "graph-owned",
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        delete_calls = [line for line in calls.splitlines() if " DELETE " in f" {line} "]
        self.assertEqual(len(delete_calls), 2)
        self.assertIn(f"servicePrincipals/{SP_OBJECT_ID}", delete_calls[0])
        self.assertIn(f"applications/{APP_OBJECT_ID}", delete_calls[1])


if __name__ == "__main__":
    unittest.main()
