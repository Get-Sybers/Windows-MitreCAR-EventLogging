#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Registers the Get-Sybers-MitreCAR provider and its Get-Sybers-MitreCAR/Operational channel.

.DESCRIPTION
Copies the resource DLL and the manifest to the install directory and runs `wevtutil im`, pointing the
resource and message file paths at the installed DLL. Afterwards the channel appears in Event Viewer
under Applications and Services Logs > Get-Sybers-MitreCAR > Operational. Re-running is safe: an
existing registration is removed first.
#>
[CmdletBinding()]
param(
    [string]$Dll        = (Join-Path $PSScriptRoot '..\dist\GetSybersMitreCar.dll'),
    [string]$Manifest   = (Join-Path $PSScriptRoot '..\manifest\GetSybersMitreCar.man'),
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'Get-Sybers\MitreCAR')
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Dll)) { $Dll = Join-Path $PSScriptRoot '..\build\GetSybersMitreCar.dll' }
$Dll = (Resolve-Path $Dll).Path
$Manifest = (Resolve-Path $Manifest).Path
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force -Path $Dll, $Manifest -Destination $InstallDir
$man = Join-Path $InstallDir (Split-Path $Manifest -Leaf)
$res = Join-Path $InstallDir (Split-Path $Dll -Leaf)

& wevtutil.exe um $man 2>$null | Out-Null       # idempotent: drop a previous registration
& wevtutil.exe im $man "/rf:$res" "/mf:$res"
if ($LASTEXITCODE) { throw "wevtutil im failed ($LASTEXITCODE)" }

Write-Host "registered provider Get-Sybers-MitreCAR from $man"
& wevtutil.exe gl 'Get-Sybers-MitreCAR/Operational'
if ($LASTEXITCODE) { throw "channel Get-Sybers-MitreCAR/Operational is not registered ($LASTEXITCODE)" }
