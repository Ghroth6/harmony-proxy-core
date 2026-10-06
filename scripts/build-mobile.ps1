[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$OHOSGo,
  [Parameter(Mandatory)][string]$NativeSdk,
  [Parameter(Mandatory)][string]$ModuleCache
)
$ErrorActionPreference = 'Stop'
$core = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$revision = git -C $core rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify core source' }
if (@(git -C $core status --porcelain=v1 --untracked-files=all).Count) { throw 'Commit core source before building' }
$go = (Resolve-Path -LiteralPath $OHOSGo).Path
$sdk = (Resolve-Path -LiteralPath $NativeSdk).Path
$cache = (Resolve-Path -LiteralPath $ModuleCache).Path
$stage = Join-Path $core ('local/runs/mobile-' + (Get-Date -AsUTC -Format 'yyyyMMddTHHmmssfffffffZ'))
New-Item -ItemType Directory -Path $stage,(Join-Path $stage 'tmp') | Out-Null
# The driver requests Go 1.24 without rewriting upstream go.mod. Replacements
# in a replaced dependency are not inherited; preserve this authoritative root
# replacement explicitly, rather than importing any old wrapper module graph.
$protobuf = @(Get-Content -LiteralPath (Join-Path $core 'go.mod') | Where-Object { $_ -match '^replace google\.golang\.org/protobuf =>' })
if ($protobuf.Count -ne 1) { throw 'Review core module replacements before using this driver' }
@"
module mobile-build

go 1.24

require github.com/metacubex/mihomo v1.0.0
replace github.com/metacubex/mihomo => ../../..
$($protobuf[0])
"@ | Set-Content -LiteralPath (Join-Path $stage 'go.mod') -Encoding utf8NoBOM
Copy-Item -LiteralPath (Join-Path $core 'go.sum') -Destination (Join-Path $stage 'go.sum')
$env:GOENV='off'; $env:GOTOOLCHAIN='local'; $env:GOOS='linux'; $env:GOARCH='arm64'; $env:CGO_ENABLED='1'
$env:GOMODCACHE=$cache; $env:GOCACHE=Join-Path $core 'local/cache/go-native'
$env:GOPROXY='off'; $env:GOSUMDB='off'; $env:GOTMPDIR=Join-Path $stage 'tmp'
$env:TMP=$env:GOTMPDIR; $env:TEMP=$env:GOTMPDIR
$env:CC=Join-Path $sdk 'llvm/bin/clang.exe'; $env:CXX=Join-Path $sdk 'llvm/bin/clang++.exe'
$sysroot=(Join-Path $sdk 'sysroot').Replace('\','/')
$env:CGO_CFLAGS="--target=aarch64-linux-ohos --sysroot=`"$sysroot`" -D__MUSL__ -fPIC"
$env:CGO_LDFLAGS="--target=aarch64-linux-ohos --sysroot=`"$sysroot`""
$arguments=@('build','-buildvcs=false','-mod=mod','-tlsmodegd','-buildmode','c-shared','-tags','ohos with_gvisor',
  '-ldflags',('-X github.com/metacubex/mihomo/mobile/validation.SourceRevision='+$revision),
  '-o','libcb_validation.so','github.com/metacubex/mihomo/cmd/mobile')
$goVersion = & $go version
& $go -C $stage @arguments *> (Join-Path $stage 'build.log')
if ($LASTEXITCODE -ne 0) { throw "Mobile core build failed; inspect $stage/build.log" }
$library=Join-Path $stage 'libcb_validation.so'
[ordered]@{
  sourceRevision=$revision; abiVersion=1; library=$library
  librarySha256=(Get-FileHash -LiteralPath $library -Algorithm SHA256).Hash.ToLowerInvariant()
  goVersion=$goVersion; goSha256=(Get-FileHash -LiteralPath $go -Algorithm SHA256).Hash
  clangSha256=(Get-FileHash -LiteralPath $env:CC -Algorithm SHA256).Hash
  sdk=(Get-Content -LiteralPath (Join-Path $sdk 'oh-uni-package.json') -Raw | ConvertFrom-Json)
  arguments=$arguments; cflags=$env:CGO_CFLAGS; ldflags=$env:CGO_LDFLAGS
  moduleSha256=(Get-FileHash -LiteralPath (Join-Path $stage 'go.mod') -Algorithm SHA256).Hash
  sumSha256=(Get-FileHash -LiteralPath (Join-Path $stage 'go.sum') -Algorithm SHA256).Hash
  scope='ARM64 compile only; runtime loading, phone behavior and side effects unverified'
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $stage 'build-inputs.json') -Encoding utf8NoBOM
Write-Output $library
