param([string]$ModuleCache)

$ErrorActionPreference = 'Stop'
$core = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$go = (Get-Command go -CommandType Application).Source
$version = & $go version
if ($LASTEXITCODE -ne 0 -or $version -notmatch 'go1\.24\.5 windows/amd64') {
  throw "Use the documented host Go 1.24.5 windows/amd64; found $version"
}
$head = git -C $core rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify core revision' }
$stage = Join-Path $core ('local/statistic-tests-' + (Get-Date -AsUTC -Format 'yyyyMMddTHHmmssfffffffZ'))
if (Test-Path -LiteralPath $stage) { throw 'Existing test evidence' }
New-Item -ItemType Directory -Path $stage | Out-Null
# Keep the upstream module files unchanged while selecting the documented host
# toolchain. Dependencies continue to come from this core's module graph.
@'
module statistic-tests

go 1.24

require github.com/metacubex/mihomo v1.0.0
replace github.com/metacubex/mihomo => ../..
'@ | Set-Content -LiteralPath (Join-Path $stage 'go.mod') -Encoding utf8NoBOM
$hashes = [ordered]@{}
$files = @(Get-ChildItem -LiteralPath (Join-Path $core 'tunnel/statistic') -File -Filter '*.go')
$files += Get-Item -LiteralPath (Join-Path $core 'go.mod'), (Join-Path $core 'go.sum'), $PSCommandPath
foreach ($file in $files) {
  $relative = [IO.Path]::GetRelativePath($core, $file.FullName).Replace('\', '/')
  $hashes[$relative] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
}
if (!$ModuleCache) { $ModuleCache = Join-Path $core 'local/go-mod-cache' }
$env:GOENV = 'off'
$env:GOTOOLCHAIN = 'local'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
$env:GOPATH = Join-Path $core 'local/go-host'
$env:GOMODCACHE = [IO.Path]::GetFullPath($ModuleCache)
$env:GOCACHE = Join-Path $core 'local/go-host-cache'
[ordered]@{
  core=$head; go=$version; source_sha256=$hashes; module_cache=$env:GOMODCACHE
  scope='Host statistic package tests; not OHOS or device validation; race detector not enabled'
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stage 'inputs.json') -Encoding utf8NoBOM
& $go -C $stage test -mod=mod -count=1 -timeout=90s -v github.com/metacubex/mihomo/tunnel/statistic 2>&1 |
  Tee-Object -FilePath (Join-Path $stage 'test.log')
$result = $LASTEXITCODE
[ordered]@{exit_code=$result; scope='Host statistic package'; log='test.log'} |
  ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stage 'result.json') -Encoding utf8NoBOM
Write-Output "Evidence: $stage"
exit $result
