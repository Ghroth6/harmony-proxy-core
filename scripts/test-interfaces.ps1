[CmdletBinding()]
param([string]$ModuleCache)

$ErrorActionPreference = 'Stop'
$core = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$go = (Get-Command go -CommandType Application).Source
$version = & $go version
if ($LASTEXITCODE -ne 0 -or $version -notmatch '^go version go1\.24\.5 windows/amd64$') {
  throw "Use the documented host Go 1.24.5 windows/amd64; found $version"
}
$head = git -C $core rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify core revision' }
$dirty = @(git -C $core status --porcelain=v1 --untracked-files=all --ignore-submodules=none)
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect core working tree' }
if ($dirty.Count -ne 0) { throw 'Commit changes first: interface validation requires a clean core working tree' }

$packages = @(
  'common/event', 'adapter', 'tunnel/statistic', 'adapter/outbound', 'adapter/outboundgroup',
  'hub/executor', 'component/platformnetwork', 'component/iface',
  'component/dialer', 'dns', 'component/forwarding', 'component/http',
  'tunnel', 'listener/inner', 'hub/route', 'listener/sing_tun',
  'listener/sing_hysteria2', 'transport/anytls/session', 'transport/tuic',
  'transport/shadowquic', 'transport/kcptun'
)
$imports = @($packages | ForEach-Object { 'github.com/metacubex/mihomo/' + $_ })
$listenerPackages = @('listener', 'listener/inbound', 'listener/http', 'listener/tproxy')
$listenerImports = @($listenerPackages | ForEach-Object { 'github.com/metacubex/mihomo/' + $_ })
$stage = Join-Path $core ('local/runs/interface-tests-' + (Get-Date -AsUTC -Format 'yyyyMMddTHHmmssfffffffZ'))
if (Test-Path -LiteralPath $stage) { throw 'Existing test evidence; choose a new batch' }
New-Item -ItemType Directory -Path $stage | Out-Null
# The standalone driver selects the documented host toolchain without changing
# the upstream manifests. Copied checksums also verify cached dependency bytes.
@'
module interface-tests

go 1.24

require github.com/metacubex/mihomo v1.0.0
replace github.com/metacubex/mihomo => ../../..
'@ | Set-Content -LiteralPath (Join-Path $stage 'go.mod') -Encoding utf8NoBOM
Copy-Item -LiteralPath (Join-Path $core 'go.sum') -Destination (Join-Path $stage 'go.sum')

# Include all tracked core Go sources, covering the selected packages and their
# internal dependencies, notably constant.Connection and outbound constructors.
$files = @(git -C $core -c core.quotePath=false ls-files -- '*.go' 'go.mod' 'go.sum' 'README.md' 'scripts/test-interfaces.ps1')
if ($LASTEXITCODE -ne 0 -or $files.Count -eq 0) { throw 'Cannot enumerate tracked source inputs' }
$hashes = [ordered]@{}
foreach ($name in $files) {
  $hashes[$name] = (Get-FileHash -LiteralPath (Join-Path $core $name) -Algorithm SHA256).Hash
}
if (!$ModuleCache) { $ModuleCache = Join-Path $core 'local/cache/go-mod-cache' }
$env:GOENV = 'off'
$env:GOTOOLCHAIN = 'local'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
$env:GOPATH = Join-Path $core 'local/cache/go-host'
$env:GOMODCACHE = [IO.Path]::GetFullPath($ModuleCache)
$env:GOCACHE = Join-Path $core 'local/cache/go-host-cache'
# Tests use local/synthetic resources. Missing cached dependencies fail instead
# of fetching modules or contacting a checksum service during validation.
$env:GOPROXY = 'off'
$env:GOSUMDB = 'off'
$hostArguments = @('test', '-mod=mod', '-count=1', '-timeout=90s', '-json') + $imports
$listenerArguments = @('test', '-mod=mod', '-count=1', '-timeout=90s', '-json', '-run', '^TestListenerLifecycle') + $listenerImports
$ohosArguments = @(
  'test', '-mod=mod', '-count=1', '-timeout=90s', '-json', '-tags', 'ohos',
  '-run', '^TestOHOSBeforeFirstSnapshot$', 'github.com/metacubex/mihomo/dns'
)
[ordered]@{
  core=$head; go=$version; packages=$packages; source_sha256=$hashes
  module_cache=$env:GOMODCACHE; host_arguments=$hostArguments; ohos_tag_arguments=$ohosArguments
  listener_packages=$listenerPackages; listener_arguments=$listenerArguments
  scope='Windows CGO=0; cached dependencies only; no race detector, OHOS binary, or device validation'
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $stage 'inputs.json') -Encoding utf8NoBOM

& $go -C $stage @hostArguments *> (Join-Path $stage 'host-test.jsonl')
$hostExit = $LASTEXITCODE
& $go -C $stage @listenerArguments *> (Join-Path $stage 'listener-test.jsonl')
$listenerExit = $LASTEXITCODE
# A fresh test process is required: preceding tests must not have published a
# network snapshot before the initial OHOS defaults are observed.
& $go -C $stage @ohosArguments *> (Join-Path $stage 'ohos-tag-test.jsonl')
$ohosExit = $LASTEXITCODE

function Read-TestSummary([string]$Path) {
  $passed = @()
  $failed = @()
  $passedPackages = @()
  foreach ($line in Get-Content -LiteralPath $Path) {
    try { $item = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
    if ($item.Test -and $item.Test -notmatch '/') {
      if ($item.Action -eq 'pass') { $passed += ($item.Package + '/' + $item.Test) }
      if ($item.Action -eq 'fail') { $failed += ($item.Package + '/' + $item.Test) }
    } elseif (!$item.Test -and $item.Action -eq 'pass') {
      $passedPackages += $item.Package
    }
  }
  return [ordered]@{top_level_passed=$passed.Count; top_level_failed=$failed; passed_packages=$passedPackages}
}
$hostSummary = Read-TestSummary (Join-Path $stage 'host-test.jsonl')
$listenerSummary = Read-TestSummary (Join-Path $stage 'listener-test.jsonl')
$ohosSummary = Read-TestSummary (Join-Path $stage 'ohos-tag-test.jsonl')
$afterHead = git -C $core rev-parse HEAD
if ($LASTEXITCODE -ne 0) { $afterHead = '<unavailable>' }
$afterDirty = @(git -C $core status --porcelain=v1 --untracked-files=all --ignore-submodules=none)
if ($LASTEXITCODE -ne 0) { $afterDirty = @('<status unavailable>') }
$changed = @()
foreach ($name in $files) {
  $path = Join-Path $core $name
  if (!(Test-Path -LiteralPath $path) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $hashes[$name]) {
    $changed += $name
  }
}
$validInputs = $afterHead -ceq $head -and $afterDirty.Count -eq 0 -and $changed.Count -eq 0
$success = $hostExit -eq 0 -and $listenerExit -eq 0 -and $ohosExit -eq 0 -and $validInputs -and
  $hostSummary.passed_packages.Count -eq $packages.Count -and $ohosSummary.top_level_passed -eq 1 -and
  $listenerSummary.passed_packages.Count -eq $listenerPackages.Count -and $listenerSummary.top_level_passed -gt 0
$exitCode = if ($success) { 0 } else { 1 }
[ordered]@{
  exit_code=$exitCode; host_exit_code=$hostExit; ohos_tag_exit_code=$ohosExit
  listener_exit_code=$listenerExit; listener=$listenerSummary
  host=$hostSummary; ohos_tag=$ohosSummary; inputs_unchanged=$validInputs
  core_after=$afterHead; working_tree_after=$afterDirty; changed_source_hashes=$changed
  host_log='host-test.jsonl'; listener_log='listener-test.jsonl'; ohos_tag_log='ohos-tag-test.jsonl'
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $stage 'result.json') -Encoding utf8NoBOM
Write-Output "Host: $($hostSummary.top_level_passed) passed, $($hostSummary.top_level_failed.Count) failed; OHOS tag: $($ohosSummary.top_level_passed) passed; inputs unchanged: $validInputs"
Write-Output "Listener lifecycle: $($listenerSummary.top_level_passed) passed, $($listenerSummary.top_level_failed.Count) failed"
Write-Output "Evidence: $stage"
exit $exitCode
