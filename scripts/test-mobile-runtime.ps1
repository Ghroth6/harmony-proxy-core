[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ModuleCache,
  [string]$HostSupplementCache
)
$ErrorActionPreference = 'Stop'
$core = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$revision = git -C $core rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify core source' }
if (@(git -C $core status --porcelain=v1 --untracked-files=all).Count) { throw 'Commit core source before testing' }
$go = (Get-Command go -CommandType Application).Source
$version = & $go version
if ($version -notmatch '^go version go1\.24\.5 windows/amd64$') { throw "Use the documented Windows host Go 1.24.5; found $version" }
$stage = Join-Path $core ('local/runs/mobile-runtime-tests-' + (Get-Date -AsUTC -Format 'yyyyMMddTHHmmssfffffffZ'))
New-Item -ItemType Directory -Path $stage | Out-Null
$protobuf = @(Get-Content -LiteralPath (Join-Path $core 'go.mod') | Where-Object { $_ -match '^replace google\.golang\.org/protobuf =>' })
if ($protobuf.Count -ne 1) { throw 'Review root protobuf replacement before testing' }
@"
module mobile-runtime-tests

go 1.24

require github.com/metacubex/mihomo v1.0.0
replace github.com/metacubex/mihomo => ../../..
$($protobuf[0])
"@ | Set-Content -LiteralPath (Join-Path $stage 'go.mod') -Encoding utf8NoBOM
# This entry reads existing caches. It never downloads or alters dependencies.
if ($HostSupplementCache) {
  $supplement = (Resolve-Path -LiteralPath $HostSupplementCache).Path
  foreach ($module in @('github.com/tailscale/certstore', 'github.com/tailscale/go-winio')) {
    $line = @(Get-Content -LiteralPath (Join-Path $core 'go.mod') | Where-Object { $_ -match ('^\s+' + [regex]::Escape($module) + '\s+') })
    if ($line.Count -ne 1) { throw "Cannot identify the pinned Windows dependency $module" }
    $parts = $line[0].Trim() -split '\s+'
    $directory = (Resolve-Path -LiteralPath (Join-Path $supplement ($module + '@' + $parts[1]))).Path.Replace('\', '/')
    ('replace ' + $module + ' => "' + $directory + '"') | Add-Content -LiteralPath (Join-Path $stage 'go.mod') -Encoding utf8NoBOM
  }
}
Copy-Item -LiteralPath (Join-Path $core 'go.sum') -Destination (Join-Path $stage 'go.sum')
$files = @(git -C $core -c core.quotePath=false ls-files -- '*.go' '*.h' 'go.mod' 'go.sum' 'mobile/README.md' 'scripts/test-mobile-runtime.ps1')
$hashes = [ordered]@{}
foreach ($file in $files) { $hashes[$file] = (Get-FileHash -LiteralPath (Join-Path $core $file) -Algorithm SHA256).Hash }
$env:GOENV='off'; $env:GOTOOLCHAIN='local'; $env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
$env:GOMODCACHE=(Resolve-Path -LiteralPath $ModuleCache).Path
$env:GOPATH=Join-Path $core 'local/cache/go-host'; $env:GOCACHE=Join-Path $core 'local/cache/go-host-cache'
$env:GOPROXY='off'; $env:GOSUMDB='off'
$packages = @('mobile/runtime', 'mobile/validation', 'mobile/protection', 'component/dialer', 'component/forwarding', 'tunnel', 'config', 'hub/executor', 'tunnel/statistic', 'log')
$arguments = @('test', '-mod=mod', '-count=1', '-timeout=90s', '-tags', 'with_gvisor', '-json') + @($packages | ForEach-Object { 'github.com/metacubex/mihomo/' + $_ })
[ordered]@{sourceRevision=$revision; goVersion=$version; moduleCache=$env:GOMODCACHE; hostSupplementCache=$HostSupplementCache; arguments=$arguments; sourceSha256=$hashes; scope='Windows CGO=0, real gVisor and engine with injected descriptor syscall boundary; no race detector or target TUN execution'} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $stage 'inputs.json') -Encoding utf8NoBOM
& $go -C $stage @arguments *> (Join-Path $stage 'tests.jsonl')
$testExit = $LASTEXITCODE
$events = @(Get-Content -LiteralPath (Join-Path $stage 'tests.jsonl') | ForEach-Object { try { $_ | ConvertFrom-Json -ErrorAction Stop } catch {} })
$passedPackages = @($events | Where-Object { $_.Action -eq 'pass' -and !$_.Test })
$failed = @($events | Where-Object { $_.Action -eq 'fail' })
$passedTests = @($events | Where-Object { $_.Action -eq 'pass' -and $_.Test -and $_.Test -notmatch '/' })
$changed = @($files | Where-Object { (Get-FileHash -LiteralPath (Join-Path $core $_) -Algorithm SHA256).Hash -ne $hashes[$_] })
$dirtyAfter = @(git -C $core status --porcelain=v1 --untracked-files=all)
$valid = $testExit -eq 0 -and $passedPackages.Count -eq $packages.Count -and $failed.Count -eq 0 -and $changed.Count -eq 0 -and $dirtyAfter.Count -eq 0 -and (git -C $core rev-parse HEAD) -ceq $revision
[ordered]@{success=$valid; testExit=$testExit; passedPackages=$passedPackages.Count; passedTopLevelTests=$passedTests.Count; failed=$failed; changedSources=$changed; workingTreeAfter=$dirtyAfter} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $stage 'result.json') -Encoding utf8NoBOM
Write-Output $stage
if (!$valid) { throw "Mobile runtime host checks failed; inspect $stage" }
