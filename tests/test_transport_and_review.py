import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('pwsh'), 'PowerShell 7 required')
class ReviewRuntimeTests(unittest.TestCase):
    def invoke(self, source, **environment):
        result = subprocess.run(['pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', source],
                                capture_output=True, text=True, timeout=30,
                                env={**os.environ, 'LAB_ROOT': str(ROOT), 'TEST_PYTHON': sys.executable, **environment})
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        return result.stdout

    def test_native_arguments_keep_multiline_scope_quotes_and_continuation_query(self):
        output = self.invoke(r'''
          $ErrorActionPreference='Stop'
          . (Join-Path $env:LAB_ROOT 'scripts/AzureCli.ps1')
          function Get-Command { param($Name) [pscustomobject]@{CommandType='Application';Source=$env:TEST_PYTHON} }
          $payload = "SigninLogs`r`n| where AppId == `'test`' and UserPrincipalName == `"o'brien@example.com`""
          $url = 'https://management.azure.com/path?api-version=1&$skipToken=a%20b'
          $response = Invoke-AzCliJson -Arguments @('-c','import json,sys;print(json.dumps(sys.argv[1:]));print("provider warning",file=sys.stderr)',$payload,$url,'%PATH%','(a|b)>c')
          if ($response.Count -ne 4 -or $response[0] -cne $payload -or $response[1] -cne $url -or $response[2] -cne '%PATH%' -or $response[3] -cne '(a|b)>c') { throw 'Argument boundary changed' }
          'OK'
        ''')
        self.assertIn('OK', output)

    def test_structured_absence_never_swallows_denial_or_arbitrary_404(self):
        self.invoke(r'''
          $ErrorActionPreference='Stop'
          . (Join-Path $env:LAB_ROOT 'scripts/AzureCli.ps1')
          function global:az { $global:LASTEXITCODE=1; return $global:reply }
          foreach($message in @('ERROR: Forbidden({"error":{"code":"Authorization_RequestDenied","message":"404"}})', '404', 'ERROR: Not Found({"error":{"code":"Unknown"}})')) {
            $global:reply=$message; $failed=$false
            try { Invoke-AzCliJson -Arguments @('rest') -NotFoundIsNull | Out-Null } catch { $failed=$true }
            if (-not $failed) { throw 'Non-absence error was swallowed' }
          }
          $global:reply='ERROR: Not Found({"error":{"code":"Request_ResourceNotFound"}})'
          if ($null -ne (Invoke-AzCliJson -Arguments @('rest') -NotFoundIsNull)) { throw 'Definitive absence not returned' }
        ''')

    @unittest.skipUnless(os.name == 'nt', 'Windows MSI-style wrapper regression')
    def test_windows_batch_resolution_bypasses_cmd_with_exact_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # A self-contained MSI-style fixture: ._pth deliberately limits
            # imports to the real standard library and this fake Azure module.
            base = Path(sys.base_prefix)
            shutil.copy2(base / 'python.exe', root / 'python.exe')
            for dll in list(base.glob('python*.dll')) + list(base.glob('vcruntime*.dll')):
                shutil.copy2(dll, root / dll.name)
            (root / f'python{sys.version_info.major}{sys.version_info.minor}._pth').write_text(
                str(base / 'Lib') + '\n' + str(base / 'DLLs') + '\nLib/site-packages\n')
            (root / 'wbin').mkdir()
            wrapper = root / 'wbin/az.cmd'
            wrapper.write_text('@echo Wrapper must never execute\nexit /b 98\n')
            module = root / 'Lib/site-packages/azure/cli'
            module.mkdir(parents=True)
            (module / '__main__.py').write_text('import json,sys\nprint(json.dumps(sys.argv[1:]))\nprint("benign warning",file=sys.stderr)\n')
            self.invoke(r'''
              $ErrorActionPreference='Stop'
              . (Join-Path $env:LAB_ROOT 'scripts/AzureCli.ps1')
              function Get-Command { param($Name) [pscustomobject]@{CommandType='Application';Source=$env:MOCK_WRAPPER} }
              $query="SigninLogs`n| where UserPrincipalName == `"o'brien@example.com`""
              $url='https://management.azure.com/exact?api-version=1&$skipToken=x%20y'
              $result=Invoke-AzCliJson -Arguments @($query,$url,'%PATH%','x(y)')
              if ($result.Count -ne 4 -or $result[0] -cne $query -or $result[1] -cne $url -or $result[2] -cne '%PATH%' -or $result[3] -cne 'x(y)') { throw 'Windows wrapper corrupted argv' }
            ''', MOCK_WRAPPER=str(wrapper))

    def test_utc_dates_remain_correct_under_french_culture_and_offsets(self):
        self.invoke(r'''
          $ErrorActionPreference='Stop'
          . (Join-Path $env:LAB_ROOT 'scripts/AzureCli.ps1')
          [cultureinfo]::CurrentCulture=[cultureinfo]::GetCultureInfo('fr-FR')
          $expected=[datetime]::new(2026,9,25,12,30,0,[DateTimeKind]::Utc)
          foreach($input in @('2026-09-25T07:30:00-05:00', [datetimeoffset]::Parse('2026-09-25T14:30:00+02:00'), $expected, [datetime]::new(2026,9,25,12,30,0))) {
            $actual=ConvertTo-UtcIncidentTime $input
            if ($actual -ne $expected -or $actual.Kind -ne [DateTimeKind]::Utc) { throw 'Timestamp shifted' }
          }
          $failed=$false; try { ConvertTo-UtcIncidentTime 'not a date' | Out-Null } catch { $failed=$true }
          if (-not $failed) { throw 'Invalid time accepted' }
        ''')

    def test_paging_rejects_cycles_cross_collection_and_incomplete_shapes(self):
        self.invoke(r'''
          $ErrorActionPreference='Stop'
          . (Join-Path $env:LAB_ROOT 'scripts/AzureCli.ps1')
          $initial='https://management.azure.com/exact/collection?api-version=1'
          function Invoke-AzCliJson { param($Arguments) return $global:page }
          foreach($next in @($initial,'https://management.azure.com/other?skip=1','https://management.azure.com:8443/exact/collection?skip=1','https://evil.example/exact/collection')) {
            $global:page=[pscustomobject]@{value=@();nextLink=$next};$failed=$false
            try { Get-VerifiedPagedValues -InitialUrl $initial | Out-Null } catch { $failed=$true }
            if (-not $failed) { throw 'Bad continuation accepted' }
          }
          $global:page=[pscustomobject]@{value=[pscustomobject]@{id='not array'}};$failed=$false
          try { Get-VerifiedPagedValues -InitialUrl $initial | Out-Null } catch { $failed=$true }
          if (-not $failed) { throw 'Malformed collection accepted' }
        ''')

    def test_group_scoped_role_and_unreadable_assignment_preflight_fail_closed(self):
        self.invoke(r'''
          $ErrorActionPreference='Stop'
          . (Join-Path $env:LAB_ROOT 'scripts/AzureCli.ps1')
          $tokens=$null;$errors=$null
          $ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $env:LAB_ROOT 'scripts/run-device-code-telemetry-test.ps1'),[ref]$tokens,[ref]$errors)
          foreach($name in @('Assert-GuidValue','Assert-NotPrivilegedAccount')) {
            $definition=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
            Invoke-Expression $definition.Extent.Text
          }
          function Invoke-AzCliJson {
            param($Arguments)
            $url=$Arguments[[array]::IndexOf($Arguments,'--url')+1]
            if ($url -match 'transitiveMemberOf') { return [pscustomobject]@{value=@([pscustomobject]@{id='11111111-1111-4111-8111-111111111111';'@odata.type'='#microsoft.graph.group'})} }
            if ($global:mode -eq 'denied') { throw '403 denied' }
            if ($url -match '11111111-' -and $global:mode -eq 'assigned') { return [pscustomobject]@{value=@([pscustomobject]@{id='role';directoryScopeId='/administrativeUnits/fixture'})} }
            return [pscustomobject]@{value=@()}
          }
          foreach($mode in @('assigned','denied','clear')) {
            $global:mode=$mode;$failed=$false
            try { Assert-NotPrivilegedAccount -UserId '22222222-2222-4222-8222-222222222222' } catch { $failed=$true }
            if ($failed -ne ($mode -ne 'clear')) { throw "Incorrect role decision: $mode" }
          }
        ''')

    def test_checker_literal_is_verbatim_and_complete_marker_has_time_bound(self):
        self.invoke(r'''
          $ErrorActionPreference='Stop';$global:queries=@()
          function global:az {
            $global:LASTEXITCODE=0
            if ($args[0] -ne 'monitor') { throw 'No cloud operation permitted' }
            $global:queries += $args[[array]::IndexOf($args,'--analytics-query')+1]
            if ($args[[array]::IndexOf($args,'--timespan')+1] -ne 'PT2H') { throw 'Missing bounded query timespan' }
            'No rows'
          }
          & (Join-Path $env:LAB_ROOT 'scripts/check-device-code-telemetry.ps1') -WorkspaceId '11111111-1111-4111-8111-111111111111' -ClientId '22222222-2222-4222-8222-222222222222' -UserPrincipalName "o'brien\lab@example.com" -RunId 'a'
          foreach($query in $global:queries) {
            if (-not $query.Contains("@'o''brien\lab@example.com'") -or -not $query.Contains("@'NineLivesLab/1.0 (run:a)'")) { throw 'Literal or full marker boundary lost' }
          }
        ''')


class DetectionTimingTests(unittest.TestCase):
    def test_direct_and_correlated_success_merge_freshness_and_conservative_risk(self):
        fixtures = [
            ([{'event': 'same-success', 'ingested': 10, 'clear': True},
              {'event': 'same-success', 'ingested': 20, 'clear': True}], 1, 20, True),
            ([{'event': 'same-success', 'ingested': 10, 'clear': True},
              {'event': 'same-success', 'ingested': 20, 'clear': False}], 1, 20, False),
        ]
        for observations, expected_count, expected_freshest, expected_clear in fixtures:
            merged = {}
            for item in observations:
                state = merged.setdefault(item['event'], {'ingested': item['ingested'], 'clear': True})
                state['ingested'] = max(state['ingested'], item['ingested'])
                state['clear'] = state['clear'] and item['clear']
            self.assertEqual(len(merged), expected_count)
            self.assertEqual(merged['same-success'], {'ingested': expected_freshest, 'clear': expected_clear})
        source = (ROOT/'kql/sentinel/02-unapproved-device-code-client.kql').read_text()
        self.assertIn('EventIngested=max(EventIngested), RiskClearFlag=min(toint(coalesce(RiskContextClear, false)))', source)
        self.assertNotIn('| distinct TimeGenerated, EventIngested', source)

    def test_fresh_pair_accepts_late_interrupt_without_global_pause(self):
        # Minutes before the evaluation: an old event can arrive recently.
        cases = [(29, 28, 2, 28, True), (10, 8, 10, 8, True),
                 (29, 28, 29, 28, False), (31, 29, 2, 2, False),
                 (20, 10, 2, 2, False)]
        for interrupt, success, interrupt_ingested, success_ingested, expected in cases:
            result = (interrupt < 30 and success < 30 and 0 <= interrupt-success <= 5
                      and min(interrupt_ingested, success_ingested) < 15)
            self.assertEqual(result, expected)
        bicep = (ROOT/'infra/sentinel-rules.bicep').read_text()
        self.assertEqual(bicep.count('suppressionEnabled: false'), 2)
        self.assertEqual(bicep.count("queryFrequency: 'PT15M'"), 2)
        self.assertEqual(bicep.count("aggregationKind: 'AlertPerResult'"), 2)


if __name__ == '__main__':
    unittest.main()
