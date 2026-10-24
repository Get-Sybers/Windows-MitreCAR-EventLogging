#Requires -Version 5.1
<#
.SYNOPSIS
Builds everything, on Windows: the resource DLL from the manifest and the sensor from the C# source,
and stages an installable set under dist\.

.DESCRIPTION
  1. scripts\Build-Manifest.ps1   mc.exe -> rc.exe -> link.exe /noentry  => build\GetSybersMitreCar.dll (+ .h)
  2. dotnet build src\GetSybersMitreCar.Writer -c Release                 => the sensor
  3. stage dist\: GetSybersMitreCar.dll, GetSybersMitreCar.h, GetSybersMitreCar.man, writer\*, SHA256SUMS

Needs: Windows 10/11 SDK (mc.exe, rc.exe), MSVC (link.exe), .NET SDK 6+ with the .NET Framework 4.8
targeting pack (Visual Studio or Build Tools install both). Nothing is downloaded by this script
except the writer's NuGet packages during restore.
#>
[CmdletBinding()]
param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [switch]$SkipManifest,
    [switch]$SkipWriter
)
$ErrorActionPreference = 'Stop'
Set-Location $Root
$dist = Join-Path $Root 'dist'

if (-not $SkipManifest) {
    & "$PSScriptRoot\Build-Manifest.ps1" -OutDir (Join-Path $Root 'build')
}
if (-not $SkipWriter) {
    & dotnet build (Join-Path $Root 'src\GetSybersMitreCar.Writer') -c Release -nologo
    if ($LASTEXITCODE) { throw "dotnet build failed ($LASTEXITCODE)" }
}

New-Item -ItemType Directory -Force -Path $dist, (Join-Path $dist 'writer') | Out-Null
Copy-Item -Force (Join-Path $Root 'manifest\GetSybersMitreCar.man') $dist
foreach ($f in 'GetSybersMitreCar.dll', 'GetSybersMitreCar.h') {
    $p = Join-Path $Root "build\$f"
    if (Test-Path $p) { Copy-Item -Force $p $dist }
}
$writerOut = Join-Path $Root 'src\GetSybersMitreCar.Writer\bin\Release\net48'
if (Test-Path $writerOut) {
    Copy-Item -Force -Recurse (Join-Path $writerOut '*') (Join-Path $dist 'writer')
    Get-ChildItem (Join-Path $dist 'writer') -Filter '*.pdb' -Recurse | Remove-Item -Force
}
Get-ChildItem $dist -File -Recurse | Where-Object { $_.Name -ne 'SHA256SUMS' } |
    ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.FullName.Substring($dist.Length + 1).Replace('\', '/') } |
    Set-Content -Encoding ascii (Join-Path $dist 'SHA256SUMS')
Write-Host "staged $dist :"
Get-Content (Join-Path $dist 'SHA256SUMS') | ForEach-Object { Write-Host "  $_" }
