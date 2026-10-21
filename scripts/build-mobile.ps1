[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$OHOSGo,
  [Parameter(Mandatory)][string]$NativeSdk,
  [Parameter(Mandatory)][string]$ModuleCache,
  [ValidateSet('arm64-v8a','x86_64')][string]$Architecture='arm64-v8a',
  [string]$BuildCache,
  [string]$ToolchainBuildReceipt
)
$ErrorActionPreference = 'Stop'
$Architecture=$Architecture.ToLowerInvariant()
$core = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$revision = git -C $core rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify core source' }
if (@(git -C $core status --porcelain=v1 --untracked-files=all).Count) { throw 'Commit core source before building' }
$go = (Resolve-Path -LiteralPath $OHOSGo).Path
$env:GOENV='off'; $env:GOTOOLCHAIN='local'
$goVersion=& $go version
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify OHOS Go version' }
$goRoot=& $go env GOROOT
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify OHOS Go root' }
$goToolDir=& $go env GOTOOLDIR
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify OHOS Go tools' }
$goSourceTreeRevision=git -C $goRoot rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify OHOS Go source tree' }
if (@(git -C $goRoot status --porcelain=v1 --untracked-files=all).Count) { throw 'Commit OHOS Go source tree before core compilation' }
$goHash=(Get-FileHash -LiteralPath $go -Algorithm SHA256).Hash.ToLowerInvariant()
$goTools=[ordered]@{}
foreach ($tool in Get-ChildItem -LiteralPath $goToolDir -Filter '*.exe' -File | Sort-Object Name) {
  $goTools[$tool.Name]=(Get-FileHash -LiteralPath $tool.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
foreach ($name in @('compile.exe','asm.exe','link.exe','cgo.exe')) {
  if (!$goTools.Contains($name)) { throw ('OHOS Go tool is missing: '+$name) }
}
$toolchainReceiptPath=$null; $toolchainReceiptHash=$null; $toolchainBuildRevision=$null
if ($ToolchainBuildReceipt) {
  $toolchainReceiptPath=(Resolve-Path -LiteralPath $ToolchainBuildReceipt).Path
  $toolchainIdentity=Get-Content -LiteralPath $toolchainReceiptPath -Raw | ConvertFrom-Json
  if (!$toolchainIdentity.sourceRevision -or $toolchainIdentity.goSha256 -ine $goHash) { throw 'OHOS Go does not match its toolchain build receipt' }
  foreach ($name in $goTools.Keys) {
    if ($toolchainIdentity.toolSha256.$name -ine $goTools[$name]) { throw ('OHOS Go tool does not match its build receipt: '+$name) }
  }
  $toolchainBuildRevision=$toolchainIdentity.sourceRevision
  $toolchainReceiptHash=(Get-FileHash -LiteralPath $toolchainReceiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
} elseif ($Architecture -eq 'x86_64') { throw 'x86_64 core compilation requires the OHOS Go toolchain build receipt' }
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
# Both OHOS architectures require the fork's dynamic TLS mode. The actual ELF
# gate below rejects a compiler that accepts this flag but still emits IE TLS.
$tlsArguments=@('-tlsmodegd')
$arguments=@('build','-buildvcs=false','-mod=mod')+$tlsArguments+@('-buildmode','c-shared','-tags','ohos with_gvisor',
  '-ldflags',('-X github.com/metacubex/mihomo/mobile/validation.SourceRevision='+$revision),
  '-o','libcb_validation.so','github.com/metacubex/mihomo/cmd/mobile')
[ordered]@{ sourceRevision=$revision; architecture=$Architecture; goOs='linux'; goArch=$goArch; compilerTarget=$compilerTarget;
  arguments=$arguments; cflags=$env:CGO_CFLAGS; ldflags=$env:CGO_LDFLAGS; goVersion=$goVersion; buildCache=$buildCachePath;
  sourceTreeRevisionAtCoreBuild=$goSourceTreeRevision; toolchainBuildRevision=$toolchainBuildRevision;
  toolchainBuildReceipt=$toolchainReceiptPath; toolchainBuildReceiptSha256=$toolchainReceiptHash; goSha256=$goHash; goToolSha256=$goTools;
  scope='Requested real OHOS core compilation; no successful artifact established yet' } |
  ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stage 'inputs.json') -Encoding utf8NoBOM
& $go -C $stage @arguments *> (Join-Path $stage 'build.log')
if ($LASTEXITCODE -ne 0) { throw "Mobile core build failed; inspect $stage/build.log" }
if ((Get-FileHash -LiteralPath $go -Algorithm SHA256).Hash -ine $goHash) { throw 'OHOS Go changed during core compilation' }
foreach ($name in $goTools.Keys) {
  if ((Get-FileHash -LiteralPath (Join-Path $goToolDir $name) -Algorithm SHA256).Hash -ine $goTools[$name]) { throw ('OHOS Go tool changed during core compilation: '+$name) }
}
$library=Join-Path $stage 'libcb_validation.so'
$elfIdentity=& (Join-Path $PSScriptRoot 'check-mobile-elf.ps1') -Library $library -NativeSdk $sdk -Architecture $Architecture -ElfOutput (Join-Path $stage 'libcb_validation.so.elf.txt')
[ordered]@{
  sourceRevision=$revision; abiVersion=1; library=$library
  architecture=$Architecture; goOs='linux'; goArch=$goArch; compilerTarget=$compilerTarget; elfMachine=$elfMachine; goAmd64=$env:GOAMD64
  librarySha256=(Get-FileHash -LiteralPath $library -Algorithm SHA256).Hash.ToLowerInvariant()
  goVersion=$goVersion; goSha256=$goHash; goToolSha256=$goTools; goRoot=$goRoot; goToolDir=$goToolDir
  sourceTreeRevisionAtCoreBuild=$goSourceTreeRevision; toolchainBuildRevision=$toolchainBuildRevision;
  toolchainBuildReceipt=$toolchainReceiptPath; toolchainBuildReceiptSha256=$toolchainReceiptHash; tls=$elfIdentity.tls
  clangSha256=(Get-FileHash -LiteralPath $env:CC -Algorithm SHA256).Hash
  readelfSha256=$elfIdentity.readelfSha256
  buildCache=$buildCachePath; goFlags=$env:GOFLAGS; goMaxProcs=$env:GOMAXPROCS
  sdk=(Get-Content -LiteralPath (Join-Path $sdk 'oh-uni-package.json') -Raw | ConvertFrom-Json)
  arguments=$arguments; cflags=$env:CGO_CFLAGS; ldflags=$env:CGO_LDFLAGS
  moduleSha256=(Get-FileHash -LiteralPath (Join-Path $stage 'go.mod') -Algorithm SHA256).Hash
  sumSha256=(Get-FileHash -LiteralPath (Join-Path $stage 'go.sum') -Algorithm SHA256).Hash
  scope=($Architecture+' OHOS compile only; runtime loading, target behavior and side effects unverified')
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $stage 'build-inputs.json') -Encoding utf8NoBOM
Write-Output $library
