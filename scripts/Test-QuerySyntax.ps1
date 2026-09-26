[CmdletBinding()]
param([Parameter(Mandatory)][string]$KustoAssembly)
$ErrorActionPreference = 'Stop'
Add-Type -Path $KustoAssembly
$schema = '(TimeGenerated:datetime,UserPrincipalName:string,UserId:string,IPAddress:string,AppDisplayName:string,AppId:string,UserAgent:string,CorrelationId:string,SessionId:string,ResultType:string,ResultDescription:string,AuthenticationProtocol:string,RiskLevelDuringSignIn:string,RiskLevelAggregated:string,RiskState:string)'
$table = [Kusto.Language.Symbols.TableSymbol]::new('SigninLogs', $schema, 'Synthetic documented SigninLogs schema')
$signins = [Kusto.Language.Symbols.TableSymbol]::new('EntraIdSignInEvents', '(Timestamp:datetime,ErrorCode:long,AccountObjectId:string,AccountUpn:string,SessionId:string,IPAddress:string,Application:string,ApplicationId:string)', 'Documented XDR sign-in columns')
$events = [Kusto.Language.Symbols.TableSymbol]::new('CloudAppEvents', '(Timestamp:datetime,AccountDisplayName:string,ActionType:string,RawEventData:dynamic,IPAddress:string,ObjectName:string,ObjectId:string)', 'Documented XDR cloud-event columns')
$database = [Kusto.Language.Symbols.DatabaseSymbol]::new('OfflineValidation', [Kusto.Language.Symbols.Symbol[]]@($table, $signins, $events))
$state = [Kusto.Language.GlobalState]::Default.WithDatabase($database)
foreach ($name in @('01-device-code-50199-to-success.kql', '02-unapproved-device-code-client.kql')) {
  $file = Get-Item (Join-Path $PSScriptRoot "../kql/sentinel/$name")
  $query = Get-Content -LiteralPath $file.FullName -Raw
  $code = [Kusto.Language.KustoCode]::ParseAndAnalyze($query, $state, [Kusto.Language.Utils.CancellationToken]::new())
  $diagnostics = @($code.GetDiagnostics())
  if ($diagnostics.Count) {
    $diagnostics | Select-Object Code, Severity, Message | Format-Table
    throw "Deployed query $($file.Name) failed offline semantic analysis."
  }
  foreach ($column in @('AppDisplayName', 'AccountName', 'AccountUPNSuffix')) {
    if ($column -notin $code.ResultType.Columns.Name) { throw "Entity mapping column $column is missing in $($file.Name)." }
  }
}
# Validate the checker's verbatim-literal boundary independently of SQL syntax.
$literal = [Kusto.Language.KustoCode]::ParseAndAnalyze("print upn = @'o''brien\demo@example.com'", $state, [Kusto.Language.Utils.CancellationToken]::new())
if (@($literal.GetDiagnostics()).Count) { throw 'Checker literal failed semantic analysis.' }
$hunt = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../kql/defender-xdr/03-device-registration-after-device-code.kql') -Raw
$huntCode = [Kusto.Language.KustoCode]::ParseAndAnalyze($hunt, $state, [Kusto.Language.Utils.CancellationToken]::new())
if (@($huntCode.GetDiagnostics()).Count) {
  $huntCode.GetDiagnostics() | Select-Object Code, Severity, Message | Format-Table
  throw 'The device-registration hunt failed offline semantic analysis.'
}
if ('UserAccountObjectId' -notin $huntCode.ResultType.Columns.Name) { throw 'The hunt omitted its immutable user identity.' }
Write-Host 'PASS: two deployed queries, device-registration hunt and checker literal parse/bind offline; no tenant query was run.'
