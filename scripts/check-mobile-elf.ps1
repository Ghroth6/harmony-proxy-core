[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Library,
  [Parameter(Mandatory)][string]$NativeSdk,
  [ValidateSet('arm64-v8a','x86_64')][string]$Architecture='arm64-v8a',
  [Parameter(Mandatory)][string]$ElfOutput
)
$ErrorActionPreference='Stop'
$Architecture=$Architecture.ToLowerInvariant()
$libraryPath=(Resolve-Path -LiteralPath $Library).Path
$readelf=Join-Path (Resolve-Path -LiteralPath $NativeSdk).Path 'llvm/bin/llvm-readelf.exe'
$machine=if ($Architecture -eq 'x86_64') { 62 } else { 183 }
$bytes=[IO.File]::ReadAllBytes($libraryPath)
if ($bytes.Length -lt 64 -or [Convert]::ToHexString($bytes[0..5]) -cne '7F454C460201' -or
    [BitConverter]::ToUInt16($bytes,16) -ne 3 -or [BitConverter]::ToUInt16($bytes,18) -ne $machine) {
  throw 'Core build is not the requested ELF64 little-endian shared object'
}
$elf=@(& $readelf --wide -h -d -r $libraryPath)
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect core ELF identity and relocations' }
$elf | Set-Content -LiteralPath $ElfOutput -Encoding utf8NoBOM
$dynamicRelocation=if ($Architecture -eq 'x86_64') { 'R_X86_64_TLSDESC' } else { 'R_AARCH64_TLSDESC' }
$initialExecPattern=if ($Architecture -eq 'x86_64') { 'R_X86_64_(?:TPOFF32|TPOFF64|GOTTPOFF)' } else { 'R_AARCH64_(?:TLS_TPREL64|TLS_TPREL|TLSIE_[A-Z0-9_]+)' }
$staticTls=[bool]($elf -match '\(FLAGS(?:_1)?\).*\bSTATIC_TLS\b')
$initialExec=@($elf -match ('^\s*[0-9a-f]+\s+[0-9a-f]+\s+'+$initialExecPattern+'\b'))
$dynamicCount=@($elf -match ('^\s*[0-9a-f]+\s+[0-9a-f]+\s+'+$dynamicRelocation+'\b')).Count
if ($staticTls -or $initialExec.Count -or $dynamicCount -lt 1) {
  throw ('Mobile core TLS model must use '+$dynamicRelocation+' without STATIC_TLS or initial-exec relocations')
}
[pscustomobject][ordered]@{
  architecture=$Architecture; elfMachine=$machine; readelfSha256=(Get-FileHash -LiteralPath $readelf -Algorithm SHA256).Hash.ToLowerInvariant()
  tls=[ordered]@{ model='general-dynamic-tlsdesc'; staticTls=$staticTls; initialExecRelocationCount=$initialExec.Count;
    dynamicRelocation=$dynamicRelocation; dynamicRelocationCount=$dynamicCount }
}
