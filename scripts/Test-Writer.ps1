#Requires -Version 5.1
<#
.SYNOPSIS
Runs the sensor in the foreground, starts a real process while it watches, and checks that
process/create (1002) and process/terminate (1003) for that process landed in the channel with the
properties the kernel event and the live lookups supply.

.DESCRIPTION
Needs the provider registered (Install-Provider.ps1) and an elevated prompt (the kernel ETW session).
#>
[CmdletBinding()]
param(
    [string]$Exe = (Join-Path $PSScriptRoot '..\src\GetSybersMitreCar.Writer\bin\Release\net48\GetSybersMitreCar.Writer.exe'),
    [int]$Duration = 25,
    [switch]$SkipClear
)
$ErrorActionPreference = 'Stop'
$log = 'Get-Sybers-MitreCAR/Operational'
$Exe = (Resolve-Path $Exe).Path
$work = Join-Path ([IO.Path]::GetTempPath()) 'gscar-writer-test'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$out = Join-Path $work 'writer.out.log'
$err = Join-Path $work 'writer.err.log'

if (-not $SkipClear) {
    & wevtutil.exe cl $log
    if ($LASTEXITCODE) { throw "wevtutil cl $log failed ($LASTEXITCODE) - run elevated" }
}

$writer = Start-Process -FilePath $Exe -ArgumentList @('--duration', "$Duration") -PassThru -NoNewWindow `
    -RedirectStandardOutput $out -RedirectStandardError $err
Write-Host "writer started (pid $($writer.Id)) for $Duration s"
Start-Sleep -Seconds 6                       # let the kernel session come up

$marker = 'gscar-marker-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$child = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList @('/c', "ping -n 4 127.0.0.1 >nul & echo $marker") -PassThru -NoNewWindow
Write-Host "started cmd.exe (pid $($child.Id)) with marker $marker; parent is this PowerShell (pid $PID)"
$child.WaitForExit()
Write-Host "cmd.exe exited ($($child.ExitCode))"

$writer.WaitForExit()
Write-Host '--- writer output ---'
if (Test-Path $out) { Get-Content $out | ForEach-Object { Write-Host "  $_" } }
if (Test-Path $err) { Get-Content $err | ForEach-Object { Write-Host "  stderr: $_" } }
if ($writer.ExitCode -ne 0) { throw "writer exited with $($writer.ExitCode)" }

function ConvertTo-Props($ev) {
    $xml = [xml]$ev.ToXml()
    $nsm = New-Object System.Xml.XmlNamespaceManager $xml.NameTable
    $nsm.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
    $props = [ordered]@{}
    foreach ($d in $xml.SelectNodes('/e:Event/e:EventData/e:Data', $nsm)) { $props[$d.GetAttribute('Name')] = $d.InnerText }
    $props
}

$events = @(Get-WinEvent -LogName $log -Oldest -ErrorAction SilentlyContinue)
Write-Host ("channel now holds {0} events" -f $events.Count)
$create = $null; $terminate = $null
foreach ($ev in $events) {
    $p = ConvertTo-Props $ev
    if ($p['pid'] -eq "$($child.Id)") {
        if ($ev.Id -eq 1002 -and -not $create) { $create = @{ Event = $ev; Props = $p } }
        if ($ev.Id -eq 1003 -and -not $terminate) { $terminate = @{ Event = $ev; Props = $p } }
    }
}

$failures = @()
function Expect([bool]$ok, [string]$what) { if ($ok) { Write-Host "  ok    $what" } else { Write-Host "  FAIL  $what"; $script:failures += $what } }

Write-Host "--- process/create (1002) for pid $($child.Id) ---"
Expect ($null -ne $create) 'event present'
if ($create) {
    $p = $create.Props
    foreach ($k in $p.Keys) { if ($p[$k]) { Write-Host ("        {0,-26} {1}" -f $k, $p[$k]) } }
    Expect ($create.Event.TaskDisplayName -eq 'process' -and $create.Event.OpcodeDisplayName -eq 'create') 'Task=process Opcode=create'
    Expect ($p['exe'] -eq 'cmd.exe') 'exe = cmd.exe (kernel event)'
    Expect ($p['command_line'] -like "*$marker*") 'command_line carries the marker (kernel event)'
    Expect ($p['ppid'] -eq "$PID") "ppid = $PID (kernel event)"
    Expect ($p['hostname'] -eq $env:COMPUTERNAME) 'hostname = this machine'
    Expect ($p['image_path'] -like '*\cmd.exe') 'image_path resolved from the live process'
    Expect ($p['sha256_hash'] -match '^[0-9a-f]{64}$') 'sha256_hash of the image file'
    Expect ($p['md5_hash'] -match '^[0-9a-f]{32}$') 'md5_hash of the image file'
    Expect ($p['sid'] -like 'S-1-*') 'sid from the live token'
    Expect ($p['user'] -ne '') 'user from the live token'
    Expect (@('low', 'medium', 'high', 'system') -contains $p['integrity_level']) 'integrity_level from the live token'
    Expect ($p['parent_image_path'] -like '*\powershell.exe' -or $p['parent_image_path'] -like '*\pwsh.exe') 'parent_image_path resolved from the live parent'
    foreach ($empty in @('guid', 'parent_guid', 'access_level', 'call_trace', 'target_pid')) { Expect ($p[$empty] -eq '') "$empty empty (not observed)" }
}

Write-Host "--- process/terminate (1003) for pid $($child.Id) ---"
Expect ($null -ne $terminate) 'event present'
if ($terminate) {
    $p = $terminate.Props
    foreach ($k in $p.Keys) { if ($p[$k]) { Write-Host ("        {0,-26} {1}" -f $k, $p[$k]) } }
    Expect ($terminate.Event.TaskDisplayName -eq 'process' -and $terminate.Event.OpcodeDisplayName -eq 'terminate') 'Task=process Opcode=terminate'
    Expect ($p['exe'] -eq 'cmd.exe') 'exe = cmd.exe'
    Expect ($p['image_path'] -like '*\cmd.exe') 'image_path carried from the observed start'
}

$all1002 = @($events | Where-Object { $_.Id -eq 1002 }).Count
$all1003 = @($events | Where-Object { $_.Id -eq 1003 }).Count
Write-Host ("the sensor also saw {0} other process starts and {1} stops while it ran" -f ($all1002 - [int][bool]$create), ($all1003 - [int][bool]$terminate))

if ($failures.Count) { throw "$($failures.Count) check(s) failed: $($failures -join '; ')" }
Write-Host 'ok: the sensor observed a live process start and stop and wrote process/create and process/terminate as the model defines them'
