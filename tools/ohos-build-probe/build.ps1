[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$OHOSGo,
  [Parameter(Mandatory)][string]$ToolchainReceipt,
  [Parameter(Mandatory)][string]$NativeSdk,
  [Parameter(Mandatory)][string]$RunRoot,
  [string]$CacheSeedRoot,
  [string]$CacheRoot
)
$ErrorActionPreference='Stop'
$core=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$revision=git -C $core rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or @(git -C $core status --porcelain=v1 --untracked-files=all).Count) { throw 'Commit isolated probe before building' }
$fixed='3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8'
git -C $core merge-base --is-ancestor $fixed HEAD
if ($LASTEXITCODE -ne 0) { throw 'Probe must descend from the fixed core' }
$upstreamChanges=@(git -C $core diff --name-only $fixed HEAD -- . ':!tools/ohos-build-probe')
if ($upstreamChanges.Count) { throw 'Upstream source must remain unchanged' }
$run=[IO.Path]::GetFullPath($RunRoot)
if (Test-Path -LiteralPath $run) { throw 'Use a new run directory to preserve original evidence' }
New-Item -ItemType Directory -Path $run,(Join-Path $run 'tmp'),(Join-Path $run 'modcache'),(Join-Path $run 'buildcache') | Out-Null
if ($CacheSeedRoot) {
  foreach ($name in @('modcache','buildcache')) {
    Get-ChildItem -LiteralPath (Join-Path $CacheSeedRoot $name) -Force | Copy-Item -Destination (Join-Path $run $name) -Recurse -Force
  }
}
$go=(Resolve-Path -LiteralPath $OHOSGo).Path
$sdk=(Resolve-Path -LiteralPath $NativeSdk).Path
$env:GOENV='off'; $env:GOTOOLCHAIN='local'; $env:GOFLAGS=''; $env:GOEXPERIMENT=''; $env:GOWORK='off'
$goRoot=& $go env GOROOT
$toolDir=& $go env GOTOOLDIR
$receipt=Get-Content -Raw -LiteralPath $ToolchainReceipt | ConvertFrom-Json
$goHash=(Get-FileHash -LiteralPath $go).Hash.ToLowerInvariant()
if ($receipt.goSha256 -cne $goHash) { throw 'Go binary differs from receipt' }
$toolHashes=[ordered]@{}
foreach ($entry in $receipt.toolSha256.PSObject.Properties) {
  $hash=(Get-FileHash -LiteralPath (Join-Path $toolDir $entry.Name)).Hash.ToLowerInvariant()
  if ($hash -cne $entry.Value) { throw ('Tool differs from receipt: '+$entry.Name) }
  $toolHashes[$entry.Name]=$hash
}
if (@(git -C $goRoot status --porcelain=v1 --untracked-files=all).Count) { throw 'Go source must be clean' }
Copy-Item -LiteralPath $ToolchainReceipt -Destination (Join-Path $run 'toolchain-receipt.json')
$env:GOOS='linux'; $env:GOARCH='arm64'; $env:CGO_ENABLED='1'; $env:GOMAXPROCS='4'
$env:GOMODCACHE=Join-Path $run 'modcache'; $env:GOCACHE=Join-Path $run 'buildcache'
if ($CacheRoot) {
  $env:GOMODCACHE=(Resolve-Path -LiteralPath (Join-Path $CacheRoot 'modcache')).Path
  $env:GOCACHE=(Resolve-Path -LiteralPath (Join-Path $CacheRoot 'buildcache')).Path
}
$env:GOTMPDIR=Join-Path $run 'tmp'; $env:TMP=$env:GOTMPDIR; $env:TEMP=$env:GOTMPDIR
$env:GOPROXY='https://proxy.golang.org'; $env:GOSUMDB='sum.golang.org'
$env:CC=Join-Path $sdk 'llvm/bin/clang.exe'; $env:CXX=Join-Path $sdk 'llvm/bin/clang++.exe'
$sysroot=(Join-Path $sdk 'sysroot').Replace('\','/')
if ($sysroot -match '\s') { throw 'Use existing SDK junction without spaces' }
$env:CGO_CFLAGS="--target=aarch64-linux-ohos --sysroot=$sysroot -D__MUSL__ -fPIC"
$env:CGO_LDFLAGS="--target=aarch64-linux-ohos --sysroot=$sysroot"
$protobuf=@(Get-Content -LiteralPath (Join-Path $core 'go.mod') | Where-Object { $_ -match '^replace ' })
if ($protobuf.Count -ne 1 -or $protobuf[0] -notmatch '^replace google\.golang\.org/protobuf =>') { throw 'Review upstream replacements' }
@"
module fixed-core-build-probe

go 1.24

require github.com/metacubex/mihomo v1.0.0
replace github.com/metacubex/mihomo => "$($core.Replace('\','/'))"
$($protobuf[0])
"@ | Set-Content -LiteralPath (Join-Path $run 'go.mod') -Encoding utf8NoBOM
Copy-Item -LiteralPath (Join-Path $core 'go.sum') -Destination (Join-Path $run 'go.sum')
$tags='ohos foss with_gvisor cmfa'
$arguments=@('build','-p=4','-buildvcs=false','-mod=mod','-tlsmodegd','-buildmode=c-shared','-tags',$tags,'-o','libfixed_core_probe.so','github.com/metacubex/mihomo/tools/ohos-build-probe')
$inputs=[ordered]@{
  issue='https://github.com/Ghroth6/clashbox-meta/issues/86'; fixedCore=$fixed; probeRevision=$revision; cacheSeedRoot=$CacheSeedRoot
  sourceRoot=$core; upstreamChanges=$upstreamChanges; goRoot=$goRoot; goVersion=(& $go version)
  goSourceRevision=(git -C $goRoot rev-parse HEAD); goHash=$goHash; toolHashes=$toolHashes
  toolchainReceiptHash=(Get-FileHash -LiteralPath $ToolchainReceipt).Hash; sdk=(Get-Content -Raw (Join-Path $sdk 'oh-uni-package.json') | ConvertFrom-Json)
  sdkPath=$sdk; clangHash=(Get-FileHash -LiteralPath $env:CC).Hash; clangVersion=(& $env:CC --version)
  upstreamModuleHash=(Get-FileHash -LiteralPath (Join-Path $core 'go.mod')).Hash
  upstreamSumHash=(Get-FileHash -LiteralPath (Join-Path $core 'go.sum')).Hash
  arguments=$arguments; tags=$tags; goos=$env:GOOS; goarch=$env:GOARCH; cgoEnabled=$env:CGO_ENABLED
  cflags=$env:CGO_CFLAGS; ldflags=$env:CGO_LDFLAGS; goToolchain=$env:GOTOOLCHAIN; goProxy=$env:GOPROXY; goSumDB=$env:GOSUMDB
  moduleCache=$env:GOMODCACHE; buildCache=$env:GOCACHE; tmp=$env:GOTMPDIR
  startedUtc=(Get-Date).ToUniversalTime().ToString('o'); scope='Host compile only. No runtime invocation, product bridge, protocol exclusions or upstream patches.'
}
$inputs | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $run 'inputs.json') -Encoding utf8NoBOM
& $go -C $run @arguments *> (Join-Path $run 'build.log')
$buildExit=$LASTEXITCODE
& $go -C $run list -mod=mod -tags $tags -e -deps -json github.com/metacubex/mihomo/tools/ohos-build-probe > (Join-Path $run 'packages.json') 2> (Join-Path $run 'packages.stderr.log')
$listExit=$LASTEXITCODE
& $go -C $run list -mod=mod -m -json all > (Join-Path $run 'modules.json') 2> (Join-Path $run 'modules.stderr.log')
$modulesExit=$LASTEXITCODE
$library=Join-Path $run 'libfixed_core_probe.so'
$elfExit=$null
if ($buildExit -eq 0) {
  & (Join-Path $sdk 'llvm/bin/llvm-readelf.exe') --file-header --dynamic --relocations --symbols $library > (Join-Path $run 'elf.txt') 2>&1
  $elfExit=$LASTEXITCODE
}
[ordered]@{ buildExit=$buildExit; packageListExit=$listExit; moduleListExit=$modulesExit; elfExit=$elfExit; libraryExists=(Test-Path -LiteralPath $library); endedUtc=(Get-Date).ToUniversalTime().ToString('o'); sourceStatus=@(git -C $core status --porcelain=v1 --untracked-files=all); goSourceStatus=@(git -C $goRoot status --porcelain=v1 --untracked-files=all) } |
  ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $run 'result.json') -Encoding utf8NoBOM
Write-Output $run
Get-Content -LiteralPath (Join-Path $run 'result.json')

