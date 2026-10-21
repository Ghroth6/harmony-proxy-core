[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$OHOSGo,
  [Parameter(Mandatory)][string]$NativeSdk,
  [Parameter(Mandatory)][string]$ModuleCache,
  [ValidateSet('arm64-v8a','x86_64')][string]$Architecture='arm64-v8a',
  [string]$BuildCache
)
$ErrorActionPreference = 'Stop'
$Architecture=$Architecture.ToLowerInvariant()
$core = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$revision = git -C $core rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify core source' }
if (@(git -C $core status --porcelain=v1 --untracked-files=all).Count) { throw 'Commit core source before building' }
$go = (Resolve-Path -LiteralPath $OHOSGo).Path
$sdk = (Resolve-Path -LiteralPath $NativeSdk).Path
$cache = (Resolve-Path -LiteralPath $ModuleCache).Path
$goArch=if ($Architecture -eq 'x86_64') { 'amd64' } else { 'arm64' }
$compilerTarget=if ($Architecture -eq 'x86_64') { 'x86_64-linux-ohos' } else { 'aarch64-linux-ohos' }
$elfMachine=if ($Architecture -eq 'x86_64') { 62 } else { 183 }
if (!$BuildCache) { $BuildCache=Join-Path $core ('local/cache/go-native/'+$Architecture) }
$buildCachePath=[IO.Path]::GetFullPath($BuildCache)
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
$env:GOENV='off'; $env:GOTOOLCHAIN='local'; $env:GOOS='linux'; $env:GOARCH=$goArch; $env:CGO_ENABLED='1'
$env:GOAMD64='v1'
$env:GOMODCACHE=$cache; $env:GOCACHE=$buildCachePath
$env:GOPROXY='off'; $env:GOSUMDB='off'; $env:GOTMPDIR=Join-Path $stage 'tmp'
$env:TMP=$env:GOTMPDIR; $env:TEMP=$env:GOTMPDIR
$env:CC=Join-Path $sdk 'llvm/bin/clang.exe'; $env:CXX=Join-Path $sdk 'llvm/bin/clang++.exe'
$sysroot=(Join-Path $sdk 'sysroot').Replace([IO.Path]::DirectorySeparatorChar, '/')
if ($sysroot -match '\s') { throw 'Use the existing repo-local sdk-native junction; cgo SDK path must not contain spaces' }
$env:CGO_CFLAGS="--target=$compilerTarget --sysroot=$sysroot -D__MUSL__ -fPIC"
$env:CGO_LDFLAGS="--target=$compilerTarget --sysroot=$sysroot"
# The fork's general-dynamic TLS mode is the established ARM64 path. AMD64
# uses the Go toolchain's ordinary c-shared TLS path; target loading is separate.
$tlsArguments=if ($Architecture -eq 'arm64-v8a') { @('-tlsmodegd') } else { @() }
$arguments=@('build','-buildvcs=false','-mod=mod')+$tlsArguments+@('-buildmode','c-shared','-tags','ohos with_gvisor',
  '-ldflags',('-X github.com/metacubex/mihomo/mobile/validation.SourceRevision='+$revision),
  '-o','libcb_validation.so','github.com/metacubex/mihomo/cmd/mobile')
$goVersion = & $go version
[ordered]@{ sourceRevision=$revision; architecture=$Architecture; goOs='linux'; goArch=$goArch; compilerTarget=$compilerTarget;
  arguments=$arguments; cflags=$env:CGO_CFLAGS; ldflags=$env:CGO_LDFLAGS; goVersion=$goVersion; buildCache=$buildCachePath;
  scope='Requested real OHOS core compilation; no successful artifact established yet' } |
  ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stage 'inputs.json') -Encoding utf8NoBOM
& $go -C $stage @arguments *> (Join-Path $stage 'build.log')
if ($LASTEXITCODE -ne 0) { throw "Mobile core build failed; inspect $stage/build.log" }
$library=Join-Path $stage 'libcb_validation.so'
$bytes=[IO.File]::ReadAllBytes($library)
if ($bytes.Length -lt 64 -or [Convert]::ToHexString($bytes[0..5]) -cne '7F454C460201' -or
    [BitConverter]::ToUInt16($bytes,16) -ne 3 -or [BitConverter]::ToUInt16($bytes,18) -ne $elfMachine) {
  throw 'Core build is not the requested ELF64 little-endian shared object'
}
$readelf=Join-Path $sdk 'llvm/bin/llvm-readelf.exe'
$elf=& $readelf -h -d -r $library
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect core ELF identity and relocations' }
$elf | Set-Content -LiteralPath (Join-Path $stage 'libcb_validation.so.elf.txt') -Encoding utf8NoBOM
[ordered]@{
  sourceRevision=$revision; abiVersion=1; library=$library
  architecture=$Architecture; goOs='linux'; goArch=$goArch; compilerTarget=$compilerTarget; elfMachine=$elfMachine; goAmd64=$env:GOAMD64
  librarySha256=(Get-FileHash -LiteralPath $library -Algorithm SHA256).Hash.ToLowerInvariant()
  goVersion=$goVersion; goSha256=(Get-FileHash -LiteralPath $go -Algorithm SHA256).Hash
  clangSha256=(Get-FileHash -LiteralPath $env:CC -Algorithm SHA256).Hash
  readelfSha256=(Get-FileHash -LiteralPath $readelf -Algorithm SHA256).Hash
  buildCache=$buildCachePath; goFlags=$env:GOFLAGS; goMaxProcs=$env:GOMAXPROCS
  sdk=(Get-Content -LiteralPath (Join-Path $sdk 'oh-uni-package.json') -Raw | ConvertFrom-Json)
  arguments=$arguments; cflags=$env:CGO_CFLAGS; ldflags=$env:CGO_LDFLAGS
  moduleSha256=(Get-FileHash -LiteralPath (Join-Path $stage 'go.mod') -Algorithm SHA256).Hash
  sumSha256=(Get-FileHash -LiteralPath (Join-Path $stage 'go.sum') -Algorithm SHA256).Hash
  scope=($Architecture+' OHOS compile only; runtime loading, target behavior and side effects unverified')
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $stage 'build-inputs.json') -Encoding utf8NoBOM
Write-Output $library
