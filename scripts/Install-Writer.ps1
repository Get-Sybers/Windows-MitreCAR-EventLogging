#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Installs the sensor as the GetSybersMitreCar Windows service (LocalSystem, automatic start) and starts it.
The provider must be registered first (Install-Provider.ps1).
#>
[CmdletBinding()]
param(
    [string]$SourceDir  = (Join-Path $PSScriptRoot '..\src\GetSybersMitreCar.Writer\bin\Release\net48'),
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'Get-Sybers\MitreCAR')
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force -Recurse -Path (Join-Path $SourceDir '*') -Destination $InstallDir
$exe = Join-Path $InstallDir 'GetSybersMitreCar.Writer.exe'
if (-not (Test-Path $exe)) { throw "$exe not found - build the writer first (dotnet build src/GetSybersMitreCar.Writer -c Release)" }
& sc.exe stop GetSybersMitreCar 2>$null | Out-Null
& sc.exe delete GetSybersMitreCar 2>$null | Out-Null
& sc.exe create GetSybersMitreCar binPath= "`"$exe`"" start= auto obj= LocalSystem DisplayName= "Get-Sybers MITRE CAR Sensor"
if ($LASTEXITCODE) { throw "sc create failed ($LASTEXITCODE)" }
& sc.exe description GetSybersMitreCar "Observes live kernel and channel telemetry and writes MITRE CAR events to Get-Sybers-MitreCAR/Operational." | Out-Null
& sc.exe start GetSybersMitreCar
if ($LASTEXITCODE) { throw "sc start failed ($LASTEXITCODE)" }
Write-Host "installed and started GetSybersMitreCar from $exe"
