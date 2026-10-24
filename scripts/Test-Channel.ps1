#Requires -Version 5.1
<#
.SYNOPSIS
Proves the registered channel end to end: the sensor's own emitter writes two events per EventID (every
property populated, then every property empty), and each is read back and checked for object (Task),
action (Opcode), keyword, property names and values, and a rendered message.

.DESCRIPTION
Needs the provider registered (Install-Provider.ps1) and the writer built (build.ps1). Runs elevated:
clearing the channel and the sensor's EventRegister need it. When the mc.exe header is present, every
event descriptor in it is also compared with the values the model (and the writer) compute.
#>
[CmdletBinding()]
param(
    [string]$Exe    = (Join-Path $PSScriptRoot '..\dist\writer\GetSybersMitreCar.Writer.exe'),
    [string]$Header = (Join-Path $PSScriptRoot '..\dist\GetSybersMitreCar.h'),
    [string]$Model  = (Join-Path $PSScriptRoot '..\model\generated\car-eventlog-model.json'),
    [int[]]$EventId,
    [switch]$SkipClear,
    [int]$TimeoutSeconds = 60
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Exe)) { $Exe = Join-Path $PSScriptRoot '..\src\GetSybersMitreCar.Writer\bin\Release\net48\GetSybersMitreCar.Writer.exe' }
$Exe = (Resolve-Path $Exe).Path

# NB: $Model is the [string] path parameter; PowerShell variables are case-insensitive, so the parsed
# model lives in $spec.
$spec = Get-Content -Raw -Encoding UTF8 $Model | ConvertFrom-Json
if (-not $spec -or -not $spec.events) { throw "could not read the model from $Model" }
$log = $spec.provider.channel.name

# --- optional: the descriptors mc.exe generated must equal what the model (and the writer) compute ---
if (Test-Path $Header) {
    $descriptors = @{}
    foreach ($m in (Select-String -Path $Header -Pattern 'EVENT_DESCRIPTOR\s+(\w+)\s*=\s*\{([^}]*)\}')) {
        $g = $m.Matches[0].Groups
        $p = @($g[2].Value -split ',' | ForEach-Object { $_.Trim() -replace '^0[xX]', '' })
        $descriptors[$g[1].Value] = [pscustomobject]@{
            Id = [Convert]::ToInt32($p[0], 16); Version = [Convert]::ToInt32($p[1], 16); Channel = [Convert]::ToInt32($p[2], 16)
            Level = [Convert]::ToInt32($p[3], 16); Opcode = [Convert]::ToInt32($p[4], 16); Task = [Convert]::ToInt32($p[5], 16)
            Keywords = [Convert]::ToUInt64($p[6], 16)
        }
    }
    $channelKeyword = [Convert]::ToUInt64($spec.channel_keyword.Substring(2), 16)
    $mismatches = @()
    foreach ($e in $spec.events) {
        $d = $descriptors[$e.symbol]
        if (-not $d) { $mismatches += "$($e.symbol): missing from the header"; continue }
        $wantKeywords = [Convert]::ToUInt64($e.keyword.Substring(2), 16) -bor $channelKeyword
        $want = "id=$($e.id) version=0 channel=$($spec.provider.channel.value) level=4 opcode=$($e.opcode) task=$($e.task) keywords=0x$($wantKeywords.ToString('x16'))"
        $have = "id=$($d.Id) version=$($d.Version) channel=$($d.Channel) level=$($d.Level) opcode=$($d.Opcode) task=$($d.Task) keywords=0x$($d.Keywords.ToString('x16'))"
        if ($want -ne $have) { $mismatches += "$($e.symbol): header $have != model $want" }
    }
    if ($mismatches) { throw "descriptor mismatch between mc.exe's header and the model:`n  " + ($mismatches -join "`n  ") }
    Write-Host ("descriptors: all {0} in the header equal the model's (channel keyword 0x{1})" -f @($spec.events).Count, $channelKeyword.ToString('x16'))
}

$fieldsOf = @{}
foreach ($o in $spec.objects) { $fieldsOf[$o.key] = @($o.fields) }
$all = @($spec.events)
$events = if ($PSBoundParameters.ContainsKey('EventId')) { @($all | Where-Object { $EventId -contains [int]$_.id }) } else { $all }
if ($events.Count -eq 0) { throw "no events selected (EventId filter: $($EventId -join ','))" }
Write-Host ("model: {0} objects, {1} events; testing {2}" -f @($spec.objects).Count, $all.Count, $events.Count)

if (-not $SkipClear) {
    & wevtutil.exe cl $log
    if ($LASTEXITCODE) { throw "wevtutil cl $log failed ($LASTEXITCODE) - run elevated or pass -SkipClear" }
}

# --- write: the sensor's self-test mode writes, per EventID, one event with every property set to its own
#     name and one with every property empty, through the same EventWrite path the live sensor uses ---------
$args = @('--selftest') + @($events | ForEach-Object { "$($_.id)" })
& $Exe @args
if ($LASTEXITCODE) { throw "writer --selftest exited with $LASTEXITCODE" }
$expected = New-Object System.Collections.Generic.List[object]
foreach ($e in $events) {
    $fields = $fieldsOf[$e.object]
    $expected.Add([pscustomobject]@{ Event = $e; Payload = @($fields | ForEach-Object { $_.name }) })
    $expected.Add([pscustomobject]@{ Event = $e; Payload = @($fields | ForEach-Object { '' }) })
}

# --- read back ---------------------------------------------------------------------------------
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
do {
    Start-Sleep -Seconds 1
    $logged = @(Get-WinEvent -LogName $log -Oldest -ErrorAction SilentlyContinue)
} while ($logged.Count -lt $expected.Count -and (Get-Date) -lt $deadline)
if ($logged.Count -lt $expected.Count) { throw "expected $($expected.Count) events in $log, found $($logged.Count)" }
$logged = @($logged | Select-Object -Last $expected.Count)

$ns = 'http://schemas.microsoft.com/win/2004/08/events/event'
$sep = [string][char]1
$failures = 0
for ($i = 0; $i -lt $expected.Count; $i++) {
    $x = $expected[$i]; $e = $x.Event; $ev = $logged[$i]
    $xml = [xml]$ev.ToXml()
    $nsm = New-Object System.Xml.XmlNamespaceManager $xml.NameTable
    $nsm.AddNamespace('e', $ns)
    $data = @($xml.SelectNodes('/e:Event/e:EventData/e:Data', $nsm))
    $names = @($data | ForEach-Object { $_.GetAttribute('Name') })
    $values = @($data | ForEach-Object { $_.InnerText })
    $wantNames = @($fieldsOf[$e.object] | ForEach-Object { $_.name })
    $problems = @()
    if ($ev.Id -ne $e.id)                              { $problems += "Id $($ev.Id) != $($e.id)" }
    if ($ev.Task -ne $e.task)                          { $problems += "Task $($ev.Task) != $($e.task)" }
    if ($ev.TaskDisplayName -ne $e.object)             { $problems += "Task name '$($ev.TaskDisplayName)' != '$($e.object)'" }
    if ($ev.Opcode -ne $e.opcode)                      { $problems += "Opcode $($ev.Opcode) != $($e.opcode)" }
    if ($ev.OpcodeDisplayName -ne $e.action)           { $problems += "Opcode name '$($ev.OpcodeDisplayName)' != '$($e.action)'" }
    if (-not (@($ev.KeywordsDisplayNames) -contains $e.object)) { $problems += "keyword '$($e.object)' missing ($($ev.KeywordsDisplayNames -join ','))" }
    if (($names -join ',') -ne ($wantNames -join ','))  { $problems += "property names differ: $($names -join ',')" }
    if (($values -join $sep) -ne ($x.Payload -join $sep)) { $problems += 'property values differ' }
    if ([string]::IsNullOrWhiteSpace($ev.Message))     { $problems += 'no rendered message (resource DLL not resolved)' }
    if ($problems) {
        $failures++
        Write-Host ("FAIL {0} {1}/{2}: {3}" -f $e.id, $e.object, $e.action, ($problems -join '; '))
    }
}

$sample = $logged | Where-Object { $_.Id -eq 1002 } | Select-Object -First 1
if ($sample) {
    Write-Host '--- sample: EventID 1002 (process/create) as rendered ---'
    Write-Host (($sample.Message -split "`r?`n" | Select-Object -First 8) -join "`n")
    Write-Host ("Task={0} ({1})  Opcode={2} ({3})  Keywords={4}  Properties={5}" -f $sample.Task, $sample.TaskDisplayName,
        $sample.Opcode, $sample.OpcodeDisplayName, ($sample.KeywordsDisplayNames -join ','), $sample.Properties.Count)
}
if ($failures) { throw "$failures of $($expected.Count) events did not read back as written" }
Write-Host ("ok: {0} events verified - object (Task), action (Opcode), keyword, property names and values, rendered message" -f $expected.Count)
