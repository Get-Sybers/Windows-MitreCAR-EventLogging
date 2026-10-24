#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Stops and removes the GetSybersMitreCar service. Installed files are left for Uninstall-Provider.ps1 to remove.
#>
& sc.exe stop GetSybersMitreCar 2>$null | Out-Null
Start-Sleep -Seconds 2
& sc.exe delete GetSybersMitreCar
Write-Host 'removed service GetSybersMitreCar'
