[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$OHOSGo,
  [Parameter(Mandatory)][string]$NativeSdk,
  [Parameter(Mandatory)][string]$ModuleCache,
  [ValidateSet('arm64-v8a','x86_64')][string]$Architecture='x86_64',
  [string]$BuildCache
)
$ErrorActionPreference='Stop'
# Exercise the production build entry with real tools. This is a compile contract,
# not target loading or VPN acceptance. Numeric ELF values come from the ELF ABI.
$parameters=@{ OHOSGo=$OHOSGo; NativeSdk=$NativeSdk; ModuleCache=$ModuleCache; Architecture=$Architecture }
if ($BuildCache) { $parameters.BuildCache=$BuildCache }
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
[ordered]@{ success=$true; architecture=$Architecture; elfMachine=$machine; library=$library; sourceRevision=$receipt.sourceRevision;
  scope='Real OHOS toolchain compile and ELF identity; target loading and execution unverified' } |
  ConvertTo-Json | Set-Content -LiteralPath (Join-Path (Split-Path $library) 'build-contract-test.json') -Encoding utf8NoBOM
Write-Output $library
