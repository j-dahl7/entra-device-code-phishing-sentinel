import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / 'scripts/check-device-code-telemetry.ps1'


@unittest.skipUnless(shutil.which('pwsh'), 'PowerShell 7 is required')
class CheckerQueryTests(unittest.TestCase):
    def invoke(self, script, **extra_env):
        result = subprocess.run(['pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
                                env={**os.environ, 'CHECKER_PATH': str(CHECKER), 'LAB_ROOT': str(ROOT), **extra_env},
                                capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        return result.stdout

    def test_actual_tracked_rules_scope_successfully_and_bad_declarations_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            self.invoke(r'''
                $ErrorActionPreference = 'Stop'
                $tokens=$null; $errors=$null
                $ast=[System.Management.Automation.Language.Parser]::ParseFile($env:CHECKER_PATH,[ref]$tokens,[ref]$errors)
                if ($errors.Count) { throw 'Checker did not parse' }
                $definition=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-ScopedRuleQuery'},$true)
                Invoke-Expression $definition.Extent.Text
                $LookbackHours=2
                $scope="AppId == '33333333-3333-4333-8333-333333333333'"
                foreach($name in @('01-device-code-50199-to-success.kql','02-unapproved-device-code-client.kql')) {
                    $query=Get-ScopedRuleQuery -Path (Join-Path $env:LAB_ROOT "kql/sentinel/$name") -ScopePredicate $scope
                    if ([regex]::Matches($query,'(?m)^let Lookback = 2h;\r?$').Count -ne 1) { throw "Bad replacement: $name" }
                    if (-not $query.StartsWith('let ScopedSigninLogs = SigninLogs')) { throw "Missing scoped source: $name" }
                    if (-not $query.Contains("| where $scope;")) { throw "Missing immutable scope: $name" }
                    if (-not $query.Contains('ScopedSigninLogs')) { throw "Unscoped rule: $name" }
                }
                foreach($source in @('SigninLogs', 'let Lookback = 0m;', 'let Lookback = -1h;', 'let Lookback = 1d;', "let Lookback = 30m;`nlet Lookback = 1h;")) {
                    $path=Join-Path $env:QUERY_TEST_DIR 'invalid.kql'
                    [IO.File]::WriteAllText($path,$source)
                    $failure=''
                    try { Get-ScopedRuleQuery -Path $path -ScopePredicate $scope | Out-Null } catch { $failure=$_.Exception.Message }
                    if ($failure -notmatch 'Expected exactly one supported Lookback') { throw 'Invalid declaration was not rejected' }
                }
                'OK'
            ''', QUERY_TEST_DIR=directory)

    def test_checker_reaches_both_previews_and_incident_lookup_without_cloud_calls(self):
        output = self.invoke(r'''
            $ErrorActionPreference='Stop'
            $global:queries=@(); $global:incidentReads=0
            function global:az {
                $global:LASTEXITCODE=0
                $request=$args -join ' '
                if ($request -match '^monitor log-analytics query') {
                    $index=[array]::IndexOf($args,'--analytics-query')
                    $global:queries += [string]$args[$index+1]
                    return 'No rows'
                }
                if ($request -match '^account show') { return '{"id":"66666666-6666-4666-8666-666666666666"}' }
                if ($request -match '^rest --method GET' -and $request -match '/incidents\?') {
                    $global:incidentReads++
                    return '{"value":[]}'
                }
                throw 'Unexpected mock command; no real Azure call allowed'
            }
            & $env:CHECKER_PATH -WorkspaceId '11111111-1111-4111-8111-111111111111' -ClientId '33333333-3333-4333-8333-333333333333' -UserPrincipalName 'lab@example.com' -ResourceGroup 'lab-rg' -WorkspaceName 'lab-law'
            if ($global:queries.Count -ne 3 -or $global:incidentReads -ne 1) { throw 'Checker did not complete all read phases' }
            foreach($query in $global:queries) {
                if (-not $query.Contains('33333333-3333-4333-8333-333333333333') -or -not $query.Contains('lab@example.com')) { throw 'Missing lab identity scope' }
            }
            'OK'
        ''')
        self.assertIn('Exact Rule 1 logic', output)
        self.assertIn('Exact Rule 2 logic', output)
        self.assertIn('Incidents linked to the exact deterministic rule IDs', output)


if __name__ == '__main__':
    unittest.main()
