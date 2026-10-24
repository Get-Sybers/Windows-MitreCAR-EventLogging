#Requires -Version 5.1
<#
.SYNOPSIS
Runs the sensor against real activity for every phase-1 object and checks that the CAR events for that
activity landed in the channel: process, file, registry, flow, module and thread.

.DESCRIPTION
Elevated; provider registered (Install-Provider.ps1); writer built (build.ps1). The script itself performs
the activity (its own pid is the actor for file, registry and network; a child cmd.exe is the actor for
process, module and thread), then reads the channel back and asserts one event per (object, action) it
exercised, with the properties the kernel event and the live lookups supply.
Not exercised here: driver load/unload (no test driver), thread remote_create and suspend, file
acl_modify, registry key_edit - see docs/Decisions.md.
#>
[CmdletBinding()]
param(
    [string]$Exe = (Join-Path $PSScriptRoot '..\dist\writer\GetSybersMitreCar.Writer.exe'),
    [int]$Duration = 45,
    [switch]$SkipClear
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Exe)) { $Exe = Join-Path $PSScriptRoot '..\src\GetSybersMitreCar.Writer\bin\Release\net48\GetSybersMitreCar.Writer.exe' }
$Exe = (Resolve-Path $Exe).Path
$log = 'Get-Sybers-MitreCAR/Operational'
$work = Join-Path ([IO.Path]::GetTempPath()) ('gscar-sensor-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $work | Out-Null
$out = Join-Path $work 'writer.out.log'; $err = Join-Path $work 'writer.err.log'

if (-not $SkipClear) {
    & wevtutil.exe cl $log
    if ($LASTEXITCODE) { throw "wevtutil cl $log failed ($LASTEXITCODE) - run elevated" }
}

$writer = Start-Process -FilePath $Exe -ArgumentList @('--duration', "$Duration", '--threads', '--file-reads') -PassThru -NoNewWindow `
    -RedirectStandardOutput $out -RedirectStandardError $err
Write-Host "writer started (pid $($writer.Id)) for $Duration s"
Start-Sleep -Seconds 8                       # kernel session + rundown settle

# ---- activity ---------------------------------------------------------------------------------
$marker = 'gscar-' + [guid]::NewGuid().ToString('N').Substring(0, 8)

# process (+ module, thread): a child cmd.exe that lives a few seconds
$child = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList @('/c', "ping -n 4 127.0.0.1 >nul & echo $marker") -PassThru -NoNewWindow
Write-Host "process: cmd.exe pid $($child.Id) (parent $PID)"

# file: create, write, read, timestomp, rename (modify), delete - all by this process
$file = Join-Path $work "$marker.txt"
[IO.File]::WriteAllText($file, "hello $marker")                     # create + write
$null = [IO.File]::ReadAllText($file)                               # read
[IO.File]::SetLastWriteTimeUtc($file, [datetime]'2001-01-01T00:00:00Z')   # timestomp (FileBasicInformation)
$renamed = Join-Path $work "$marker.renamed.txt"
[IO.File]::Move($file, $renamed)                                    # rename -> modify
[IO.File]::Delete($renamed)                                         # delete
Write-Host "file: $file"

# registry: key add, value set, value delete, key delete - all by this process
$key = "HKCU:\Software\GSCAR-Test-$marker"
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name 'Marker' -Value $marker
Remove-ItemProperty -Path $key -Name 'Marker'
Remove-Item -Path $key -Force
Write-Host "registry: $key"

# flow: TCP connect/accept/disconnect over loopback, both ends in this process
$listener = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$client = New-Object System.Net.Sockets.TcpClient
$client.Connect([System.Net.IPAddress]::Loopback, $port)
$server = $listener.AcceptTcpClient()
$client.GetStream().Write([byte[]](1..64), 0, 64)
Start-Sleep -Milliseconds 300
$client.Close(); $server.Close(); $listener.Stop()
Write-Host "flow: tcp 127.0.0.1:$port"

$child.WaitForExit()
Write-Host "cmd.exe exited ($($child.ExitCode)); waiting for the writer to finish"
$writer.WaitForExit()
Write-Host '--- writer output ---'
if (Test-Path $out) { Get-Content $out | ForEach-Object { Write-Host "  $_" } }
if (Test-Path $err) { Get-Content $err | ForEach-Object { Write-Host "  stderr: $_" } }
if ($writer.ExitCode -ne 0) { throw "writer exited with $($writer.ExitCode)" }

# ---- read back ------------------------------------------------------------------------------------
function ConvertTo-Props($ev) {
    $xml = [xml]$ev.ToXml()
    $nsm = New-Object System.Xml.XmlNamespaceManager $xml.NameTable
    $nsm.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
    $props = [ordered]@{}
    foreach ($d in $xml.SelectNodes('/e:Event/e:EventData/e:Data', $nsm)) { $props[$d.GetAttribute('Name')] = $d.InnerText }
    $props
}
$events = @(Get-WinEvent -LogName $log -Oldest -ErrorAction SilentlyContinue)
Write-Host ("channel holds {0} events; by EventID: {1}" -f $events.Count, (($events | Group-Object Id | Sort-Object { [int]$_.Name } | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' '))
$rows = @($events | ForEach-Object { [pscustomobject]@{ Ev = $_; P = (ConvertTo-Props $_) } })

$failures = @()
function Expect([bool]$ok, [string]$what) { if ($ok) { Write-Host "  ok    $what" } else { Write-Host "  FAIL  $what"; $script:failures += $what } }
function Show($row) { foreach ($k in $row.P.Keys) { if ($row.P[$k]) { Write-Host ("        {0,-26} {1}" -f $k, $row.P[$k]) } } }
function First([int]$id, [scriptblock]$where) { $rows | Where-Object { $_.Ev.Id -eq $id -and (& $where $_.P) } | Select-Object -First 1 }

Write-Host "--- process 1002/1003 (pid $($child.Id)) ---"
$r = First 1002 { param($p) $p['pid'] -eq "$($child.Id)" }
Expect ($null -ne $r) 'process/create present'
if ($r) { Show $r
    Expect ($r.P['exe'] -eq 'cmd.exe') 'exe = cmd.exe'
    Expect ($r.P['command_line'] -like "*$marker*") 'command_line carries the marker'
    Expect ($r.P['ppid'] -eq "$PID") 'ppid = this PowerShell'
    Expect ($r.P['image_path'] -like '*\cmd.exe') 'image_path from the kernel event'
    Expect ($r.P['sha256_hash'] -match '^[0-9a-f]{64}$') 'sha256_hash of the image'
    Expect ($r.P['sid'] -like 'S-1-*') 'sid from the live token'
    Expect (@('low','medium','high','system') -contains $r.P['integrity_level']) 'integrity_level from the live token'
    Expect ($r.P['current_working_directory'] -match '^[A-Za-z]:\\') 'current_working_directory from the PEB'
    Expect ($r.P['env_vars'] -match 'PATH=') 'env_vars from the PEB'
    Expect ($r.P['parent_command_line'] -like '*powershell*' -or $r.P['parent_command_line'] -like '*pwsh*') 'parent_command_line (this PowerShell)' }
$r = First 1003 { param($p) $p['pid'] -eq "$($child.Id)" }
Expect ($null -ne $r) 'process/terminate present'
if ($r) {
    Expect ($r.P['sha256_hash'] -match '^[0-9a-f]{64}$') 'process/terminate carries the image hash observed at start'
    Expect ($r.P['env_vars'] -match 'PATH=') 'process/terminate carries the environment observed at start' }

Write-Host "--- file 1102 create / 1107 write / 1105 read / 1106 timestomp / 1104 modify (rename) / 1103 delete ($marker) ---"
foreach ($pair in @(@(1102,'create',$file), @(1107,'write',$file), @(1105,'read',$file), @(1106,'timestomp',$file), @(1104,'modify',$file), @(1103,'delete',$renamed))) {
    $id, $action, $path = $pair
    $r = First $id { param($p) $p['pid'] -eq "$PID" -and $p['file_path'] -like "*$marker*" }
    Expect ($null -ne $r) "file/$action present for this pid and $marker"
    if ($r -and $action -in 'create','delete') { Show $r
        Expect ($r.P['file_name'] -like "$marker*") 'file_name'
        Expect ($r.P['extension'] -eq '.txt') 'extension'
        Expect ($r.P['image_path'] -like '*powershell.exe' -or $r.P['image_path'] -like '*pwsh.exe') 'image_path = this PowerShell'
        Expect ($r.P['company'] -like '*Microsoft*') 'company from the acting image version resource'
        Expect ($r.P['sha256_hash'] -match '^[0-9a-f]{64}$') 'sha256_hash of the acting image' }
    if ($r -and $action -eq 'create') {
        Expect ($r.P['owner_uid'] -like 'S-1-*') 'owner_uid of the created file'
        Expect ($r.P['mode'] -match '(^|;)D:') 'mode: the file DACL in SDDL form'
        Expect ([bool]$r.P['creation_time']) 'creation_time of the created file' }
}

Write-Host "--- registry 1301 add / 1304 value_edit / 1303 remove (GSCAR-Test-$marker) ---"
$r = First 1301 { param($p) $p['pid'] -eq "$PID" -and $p['key'] -like "*GSCAR-Test-$marker*" }
Expect ($null -ne $r) 'registry/add present (key created)'
if ($r) { Show $r; Expect ($r.P['hive'] -eq 'HKEY_USERS' -or $r.P['hive'] -eq 'HKEY_CURRENT_USER') 'hive'; Expect ($r.P['key'] -like 'HK*') 'key in HK* form' }
$r = First 1304 { param($p) $p['pid'] -eq "$PID" -and $p['key'] -like "*GSCAR-Test-$marker*" -and $p['value'] -eq 'Marker' }
Expect ($null -ne $r) 'registry/value_edit present'
if ($r) { Show $r; Expect ($r.P['data'] -eq $marker) 'data read live from the value'; Expect ($r.P['type'] -eq 'REG_SZ') 'type' }
$r = First 1303 { param($p) $p['pid'] -eq "$PID" -and $p['key'] -like "*GSCAR-Test-$marker*" }
Expect ($null -ne $r) 'registry/remove present'

Write-Host "--- flow 1203 start / 1201 end (127.0.0.1:$port) ---"
$r = First 1203 { param($p) $p['pid'] -eq "$PID" -and $p['dest_port'] -eq "$port" }
Expect ($null -ne $r) 'flow/start present (outbound connect)'
if ($r) { Show $r
    Expect ($r.P['transport_protocol'] -eq 'tcp') 'transport_protocol'
    Expect ($r.P['network_direction'] -eq 'outbound') 'network_direction'
    Expect ($r.P['dest_ip'] -eq '127.0.0.1') 'dest_ip'
    Expect ($r.P['start_time'] -match '^\d{4}-\d{2}-\d{2}T') 'start_time ISO 8601'
    Expect ($r.P['dest_hostname'] -eq $env:COMPUTERNAME) 'dest_hostname = this host (loopback is local, no DNS)' }
$r = First 1203 { param($p) $p['pid'] -eq "$PID" -and $p['src_port'] -eq "$port" -and $p['network_direction'] -eq 'inbound' }
Expect ($null -ne $r) 'flow/start present (inbound accept)'
$r = First 1201 { param($p) $p['pid'] -eq "$PID" -and ($p['dest_port'] -eq "$port" -or $p['src_port'] -eq "$port") }
Expect ($null -ne $r) 'flow/end present'
if ($r) { Show $r
    Expect ($r.P['end_time'] -match '^\d{4}-\d{2}-\d{2}T') 'end_time ISO 8601'
    Expect (($r.P['in_bytes'] -match '^\d+$') -or ($r.P['out_bytes'] -match '^\d+$')) 'byte counts tallied on the flow' }

Write-Host "--- module 1401 (loads into cmd.exe pid $($child.Id)) ---"
$r = First 1401 { param($p) $p['pid'] -eq "$($child.Id)" -and $p['module_name'] -eq 'kernel32.dll' }
Expect ($null -ne $r) 'module/load kernel32.dll in the child'
if ($r) { Show $r; Expect ($r.P['base_address'] -like '0x*') 'base_address'; Expect ($r.P['module_path'] -like '*\kernel32.dll') 'module_path'; Expect ($r.P['sha256_hash'] -match '^[0-9a-f]{64}$') 'sha256_hash' }

Write-Host "--- thread 1501 create / 1504 terminate (in cmd.exe pid $($child.Id)) ---"
$r = First 1501 { param($p) $p['tgt_pid'] -eq "$($child.Id)" }
Expect ($null -ne $r) 'thread/create in the child'
if ($r) { Show $r; Expect ($r.P['start_address'] -like '0x*') 'start_address'; Expect ($r.P['tgt_tid'] -match '^\d+$') 'tgt_tid'
    Expect ($r.P['start_module_name'] -match '\.(dll|exe)$') 'start_module_name resolved from the module map' }
$r = First 1504 { param($p) $p['tgt_pid'] -eq "$($child.Id)" }
Expect ($null -ne $r) 'thread/terminate in the child'

Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
if ($failures.Count) { throw "$($failures.Count) check(s) failed: $($failures -join '; ')" }
Write-Host 'ok: process, file, registry, flow, module and thread events observed live and written as the model defines them'
