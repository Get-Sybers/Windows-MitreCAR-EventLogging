#Requires -Version 5.1
<#
.SYNOPSIS
Compiles manifest/GetSybersMitreCar.man into GetSybersMitreCar.dll, a resource-only DLL (no source code).

.DESCRIPTION
The Event Log service needs a manifest-based provider's metadata (WEVT_TEMPLATE) and message table as
Win32 resources in a DLL. Nothing in that DLL is code:

    mc.exe  -um  GetSybersMitreCar.man   -> GetSybersMitreCar.h (event descriptors), .rc, *TEMP.bin, MSG00001.bin
    rc.exe       GetSybersMitreCar.rc    -> GetSybersMitreCar.res
    link.exe /dll /noentry .res          -> GetSybersMitreCar.dll

Needs the Windows 10/11 SDK (mc.exe, rc.exe) and the MSVC linker (link.exe). Both are preinstalled on
GitHub's windows-latest runners, which is where CI builds and publishes the DLL; a deployment only
needs the DLL, the manifest and Install-Provider.ps1.
#>
[CmdletBinding()]
param(
    [string]$Manifest = (Join-Path $PSScriptRoot '..\manifest\GetSybersMitreCar.man'),
    [string]$OutDir   = (Join-Path $PSScriptRoot '..\build'),
    [ValidateSet('x64', 'arm64')][string]$Machine = 'x64'
)
$ErrorActionPreference = 'Stop'
$Manifest = (Resolve-Path $Manifest).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

function Find-KitsTool([string]$Name) {
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $hit = Get-ChildItem -Path $kits -Directory -Filter '10.*' -ErrorAction SilentlyContinue |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName "x64\$Name" } |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $hit) { throw "$Name not found under $kits - install the Windows SDK" }
    $hit
}

function Find-Link {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { throw 'vswhere.exe not found - install Visual Studio Build Tools (MSVC)' }
    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw 'no Visual Studio instance with the MSVC toolset' }
    $hit = Get-ChildItem -Path (Join-Path $vs 'VC\Tools\MSVC') -Directory |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName 'bin\Hostx64\x64\link.exe' } |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $hit) { throw "link.exe not found under $vs" }
    $hit
}

$mc = Find-KitsTool 'mc.exe'
$rc = Find-KitsTool 'rc.exe'
$link = Find-Link
Write-Host "mc.exe   $mc"
Write-Host "rc.exe   $rc"
Write-Host "link.exe $link"

Push-Location $OutDir
try {
    & $mc -um -z GetSybersMitreCar -r $OutDir -h $OutDir $Manifest
    if ($LASTEXITCODE) { throw "mc.exe failed ($LASTEXITCODE)" }
    & $rc /nologo /fo "$OutDir\GetSybersMitreCar.res" "$OutDir\GetSybersMitreCar.rc"
    if ($LASTEXITCODE) { throw "rc.exe failed ($LASTEXITCODE)" }
    & $link /nologo /dll /noentry "/machine:$Machine" "/out:$OutDir\GetSybersMitreCar.dll" "$OutDir\GetSybersMitreCar.res"
    if ($LASTEXITCODE) { throw "link.exe failed ($LASTEXITCODE)" }
}
finally { Pop-Location }

$descriptors = @(Select-String -Path "$OutDir\GetSybersMitreCar.h" -Pattern 'EVENT_DESCRIPTOR\s+\w+\s*=').Count
$dll = Get-Item "$OutDir\GetSybersMitreCar.dll"
Write-Host ("built {0} ({1:N0} bytes, resources only); {2} event descriptors in GetSybersMitreCar.h" -f $dll.FullName, $dll.Length, $descriptors)
