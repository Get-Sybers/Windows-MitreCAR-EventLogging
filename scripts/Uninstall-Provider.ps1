#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Unregisters the Get-Sybers-MitreCAR provider and channel and removes the installed files.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'Get-Sybers\MitreCAR')
)
$man = Join-Path $InstallDir 'GetSybersMitreCar.man'
if (Test-Path $man) {
    & wevtutil.exe um $man
    if ($LASTEXITCODE) { Write-Warning "wevtutil um returned $LASTEXITCODE" }
}
if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
Write-Host 'unregistered Get-Sybers-MitreCAR'
