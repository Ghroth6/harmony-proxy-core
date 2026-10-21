[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$LegacyAmd64Library,
  [Parameter(Mandatory)][string]$Arm64Library,
  [Parameter(Mandatory)][string]$NativeSdk
)
$ErrorActionPreference='Stop'
$core=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$stage=Join-Path $core ('local/runs/mobile-elf-tests-'+(Get-Date -AsUTC -Format 'yyyyMMddTHHmmssfffffffZ'))
New-Item -ItemType Directory -Path $stage | Out-Null
$checker=Join-Path $PSScriptRoot 'check-mobile-elf.ps1'
$rejected=$false
try {
  & $checker -Library $LegacyAmd64Library -NativeSdk $NativeSdk -Architecture x86_64 -ElfOutput (Join-Path $stage 'legacy-amd64.elf.txt') | Out-Null
} catch {
  if ($_.Exception.Message -notmatch '^Mobile core TLS model') { throw }
  $rejected=$true
}
if (!$rejected) { throw 'Legacy initial-exec AMD64 core was accepted despite the target loader failure' }
$arm=& $checker -Library $Arm64Library -NativeSdk $NativeSdk -ElfOutput (Join-Path $stage 'arm64.elf.txt')
if ($arm.tls.staticTls -ne $false -or $arm.tls.dynamicRelocation -cne 'R_AARCH64_TLSDESC' -or $arm.tls.dynamicRelocationCount -lt 1) {
  throw 'Existing ARM64 dynamic TLS model was not preserved'
}
[ordered]@{ success=$true; legacyAmd64Rejected=$rejected; legacyAmd64Library=$LegacyAmd64Library;
  legacyAmd64Sha256=(Get-FileHash -LiteralPath $LegacyAmd64Library -Algorithm SHA256).Hash.ToLowerInvariant(); arm64=$arm;
  scope='Real saved core ELF inspection; no new compilation or target execution' } |
  ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stage 'result.json') -Encoding utf8NoBOM
Write-Output $stage
