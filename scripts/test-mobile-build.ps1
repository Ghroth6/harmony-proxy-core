[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$OHOSGo,
  [Parameter(Mandatory)][string]$NativeSdk,
  [Parameter(Mandatory)][string]$ModuleCache,
  [ValidateSet('arm64-v8a','x86_64')][string]$Architecture='arm64-v8a',
  [string]$BuildCache,
  [string]$ApplicationBridge,
  [string]$ToolchainBuildReceipt
)
$ErrorActionPreference='Stop'
# Exercise the production build entry with real tools. This is a compile contract,
# not target loading or VPN acceptance. Numeric ELF values come from the ELF ABI.
$parameters=@{ OHOSGo=$OHOSGo; NativeSdk=$NativeSdk; ModuleCache=$ModuleCache }
if ($PSBoundParameters.ContainsKey('Architecture')) { $parameters.Architecture=$Architecture }
if ($BuildCache) { $parameters.BuildCache=$BuildCache }
if ($ApplicationBridge) { $parameters.ApplicationBridge=$ApplicationBridge }
if ($ToolchainBuildReceipt) {
  $parameters.ToolchainBuildReceipt=$ToolchainBuildReceipt
  # An actual compiler tool must match the immutable make receipt, independent
  # of the go.exe launcher. Corrupt only a copy of that real receipt.
  $fixture=Join-Path (Split-Path $PSScriptRoot) ('local/runs/toolchain-receipt-rejection-'+(Get-Date -AsUTC -Format 'yyyyMMddTHHmmssfffffffZ'))
  New-Item -ItemType Directory -Path $fixture | Out-Null
  $invalidReceipt=Join-Path $fixture 'invalid-build-receipt.json'
  $invalidIdentity=Get-Content -LiteralPath $ToolchainBuildReceipt -Raw | ConvertFrom-Json
  $invalidIdentity.toolSha256.'compile.exe'='0'*64
  $invalidIdentity | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $invalidReceipt -Encoding utf8NoBOM
  $negativeParameters=$parameters.Clone(); $negativeParameters.ToolchainBuildReceipt=$invalidReceipt
  $rejected=$false
  try { & (Join-Path $PSScriptRoot 'build-mobile.ps1') @negativeParameters | Out-Null }
  catch {
    if ($_.Exception.Message -notmatch '^OHOS Go tool does not match its build receipt: compile\.exe') { throw }
    $rejected=$true
  }
  if (!$rejected) { throw 'Mismatched compile.exe build receipt was accepted' }
}
$library=& (Join-Path $PSScriptRoot 'build-mobile.ps1') @parameters
if (@($library).Count -ne 1 -or !(Test-Path -LiteralPath $library)) { throw 'Expected one completed core library' }
$receipt=Get-Content -LiteralPath (Join-Path (Split-Path $library) 'build-inputs.json') -Raw | ConvertFrom-Json
$bytes=[IO.File]::ReadAllBytes($library)
$machine=if ($Architecture -eq 'x86_64') { 62 } else { 183 }
if ($bytes.Length -lt 64 -or [Convert]::ToHexString($bytes[0..5]) -cne '7F454C460201' -or
    [BitConverter]::ToUInt16($bytes,16) -ne 3 -or [BitConverter]::ToUInt16($bytes,18) -ne $machine) {
  throw 'Core is not the requested ELF64 little-endian shared object'
}
if ($receipt.architecture -cne $Architecture -or $receipt.librarySha256 -cne
    (Get-FileHash -LiteralPath $library -Algorithm SHA256).Hash.ToLowerInvariant()) { throw 'Core receipt does not identify the actual target and bytes' }
$dynamicRelocation=if ($Architecture -eq 'x86_64') { 'R_X86_64_TLSDESC' } else { 'R_AARCH64_TLSDESC' }
if ($receipt.tls.staticTls -ne $false -or $receipt.tls.initialExecRelocationCount -ne 0 -or
    $receipt.tls.dynamicRelocation -cne $dynamicRelocation -or $receipt.tls.dynamicRelocationCount -lt 1) { throw 'Core receipt lacks the real dynamic TLS observation' }
if ($ToolchainBuildReceipt) {
  $buildIdentity=Get-Content -LiteralPath $ToolchainBuildReceipt -Raw | ConvertFrom-Json
  if ($receipt.toolchainBuildRevision -cne $buildIdentity.sourceRevision -or
      $receipt.toolchainBuildReceiptSha256 -cne (Get-FileHash -LiteralPath $ToolchainBuildReceipt -Algorithm SHA256).Hash.ToLowerInvariant()) {
    throw 'Core receipt does not preserve the actual compiler build identity'
  }
}
[ordered]@{ success=$true; architecture=$Architecture; elfMachine=$machine; library=$library; sourceRevision=$receipt.sourceRevision;
  scope='Real OHOS toolchain compile and ELF identity; target loading and execution unverified' } |
  ConvertTo-Json | Set-Content -LiteralPath (Join-Path (Split-Path $library) 'build-contract-test.json') -Encoding utf8NoBOM
Write-Output $library
