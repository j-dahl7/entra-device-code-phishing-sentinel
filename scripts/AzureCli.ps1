# Shared transport: never route query text, JSON, or continuation URLs through cmd.exe.
function Invoke-AzCli {
  param([Parameter(Mandatory)][string[]]$Arguments, [switch]$NotFoundIsNull)
  $command = Get-Command az -ErrorAction Stop
  if ($command.CommandType -in @('Function', 'Filter')) {
    $errors = [System.Collections.Generic.List[string]]::new()
    $output = @(& az @Arguments 2>&1 | ForEach-Object {
      if ($_ -is [System.Management.Automation.ErrorRecord]) { $errors.Add([string]$_) }
      else { $_ }
    })
    $exitCode = $LASTEXITCODE
    $stderr = $errors -join "`n"
    $text = ($output | Out-String).Trim()
  } else {
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $command.Source
    if ([IO.Path]::GetExtension($start.FileName) -in @('.cmd', '.bat')) {
      $python = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $command.Source) '../python.exe'))
      if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        throw 'Azure CLI batch wrapper has no adjacent bundled python.exe. Use a supported native Azure CLI installation.'
      }
      $start.FileName = $python
      foreach ($argument in @('-IBm', 'azure.cli')) { $start.ArgumentList.Add($argument) }
    }
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
      if (-not $process.Start()) { throw 'Could not start Azure CLI.' }
      $stdoutTask = $process.StandardOutput.ReadToEndAsync()
      $stderrTask = $process.StandardError.ReadToEndAsync()
      $process.WaitForExit()
      $text = $stdoutTask.GetAwaiter().GetResult().Trim()
      $stderr = $stderrTask.GetAwaiter().GetResult().Trim()
      $exitCode = $process.ExitCode
    } finally { $process.Dispose() }
  }
  if ($exitCode -ne 0) {
    $errorText = "$stderr`n$text".Trim()
    # az rest wraps Graph errors with the HTTP reason. Require BOTH definitive
    # absence and a structured Graph absence code; never search for "404" text.
    if ($NotFoundIsNull -and $errorText -match '^(?s)(?:ERROR:\s*)?Not Found\((?<body>\{.*\})\)$') {
      try {
        $code = [string](($Matches.body | ConvertFrom-Json -ErrorAction Stop).error.code)
        if ($code -in @('Request_ResourceNotFound', 'ResourceNotFound')) { return $null }
      } catch { }
    }
    throw "Azure CLI command failed with exit code $exitCode. No response body or query arguments were printed."
  }
  return $text
}

function Invoke-AzCliJson {
  param([Parameter(Mandatory)][string[]]$Arguments, [switch]$NotFoundIsNull)
  $text = Invoke-AzCli -Arguments $Arguments -NotFoundIsNull:$NotFoundIsNull
  if ($null -eq $text -and $NotFoundIsNull) { return $null }
  if ([string]::IsNullOrWhiteSpace($text)) { throw 'Azure CLI returned an empty JSON response.' }
  try { return $text | ConvertFrom-Json -ErrorAction Stop }
  catch { throw 'Azure CLI returned invalid JSON.' }
}

function Get-VerifiedPagedValues {
  param([Parameter(Mandatory)][string]$InitialUrl, [string]$NextLinkProperty = 'nextLink', [string[]]$Headers = @())
  $initial = [uri]$InitialUrl
  if ($initial.Scheme -cne 'https' -or $initial.Host -notin @('management.azure.com', 'graph.microsoft.com') -or
      $initial.Port -ne 443 -or $initial.UserInfo -or $initial.Fragment) { throw 'Invalid initial inventory URL.' }
  $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $values = [System.Collections.Generic.List[object]]::new()
  $nextUrl = $InitialUrl
  while ($nextUrl) {
    $uri = [uri]$nextUrl
    if ($uri.Scheme -cne 'https' -or $uri.Host -cne $initial.Host -or $uri.Port -ne 443 -or
        $uri.UserInfo -or $uri.Fragment -or $uri.AbsolutePath -cne $initial.AbsolutePath) { throw 'Inventory continuation changed its trusted origin or exact collection path.' }
    if (-not $seen.Add($nextUrl) -or $seen.Count -gt 100) { throw 'Inventory pagination repeated or exceeded 100 pages; results are incomplete.' }
    $arguments = @('rest', '--method', 'GET', '--url', $nextUrl, '--only-show-errors', '-o', 'json')
    if ($Headers.Count) { $arguments += @('--headers') + $Headers }
    $page = Invoke-AzCliJson -Arguments $arguments
    if ($page.value -isnot [array]) { throw 'Inventory response did not contain a value array.' }
    foreach ($value in $page.value) {
      if ($null -eq $value) { throw 'Inventory contained a null record.' }
      $values.Add($value)
      if ($values.Count -gt 10000) { throw 'Inventory exceeded 10000 records; results are incomplete.' }
    }
    $nextUrl = [string]$page.$NextLinkProperty
  }
  return $values.ToArray()
}

function ConvertTo-UtcIncidentTime {
  param([Parameter(Mandatory)][object]$Value)
  if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
  if ($Value -is [datetime]) {
    if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
    return $Value.ToUniversalTime()
  }
  $parsed = [datetimeoffset]::MinValue
  if (-not [datetimeoffset]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture,
      [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) { throw 'Invalid Sentinel createdTimeUtc; refusing incomplete incident filtering.' }
  return $parsed.UtcDateTime
}
