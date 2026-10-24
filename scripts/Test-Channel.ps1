#Requires -Version 5.1
<#
.SYNOPSIS
Writes CAR events to the Get-Sybers-MitreCAR/Operational channel and reads them back, checking object,
action and properties for every EventID.

.DESCRIPTION
For each EventID in the model (or those given with -EventId) two events are written: one with every
property set to the CAR example value, one with every property empty (empty = not observed). Events are
written with the in-box New-WinEvent cmdlet, which marshals the payload from the registered template - no
compiled code. The event descriptors mc.exe generated into the header when the DLL was built are checked
against the values the model (and the C# writer) compute: same id, channel, level, opcode, task and keywords.

Each event read back must have: the EventID; Task = the object (number and display name); Opcode = the
action (number and display name); the object's keyword; EventData property names in the model's order
with the written values; and a rendered message (which proves the resource DLL is found).

Runs under Windows PowerShell 5.1 or PowerShell 7 on Windows (New-WinEvent is in Microsoft.PowerShell.Diagnostics).
#>
[CmdletBinding()]
param(
    [string]$Header = (Join-Path $PSScriptRoot '..\build\GetSybersMitreCar.h'),
    [string]$Model  = (Join-Path $PSScriptRoot '..\model\generated\car-eventlog-model.json'),
    [int[]]$EventId,
    [switch]$SkipClear,
    [int]$TimeoutSeconds = 60
)
$ErrorActionPreference = 'Stop'
# NB: $Model is the [string] path parameter; PowerShell variables are case-insensitive, so the parsed
# model must live in a differently named variable or it is coerced back to a string.
$spec = Get-Content -Raw -Encoding UTF8 $Model | ConvertFrom-Json
if (-not $spec -or -not $spec.events) { throw "could not read the model from $Model" }
$log = $spec.provider.channel.name

# --- event descriptors from the mc.exe header -----------------------------------------------
# EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR GSCAR_PROCESS_CREATE = {0x3ea, 0x0, 0x10, 0x4, 0x10, 0x1, 0x8000000000000001};
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
if ($descriptors.Count -eq 0) { throw "no EVENT_DESCRIPTOR found in $Header" }

# --- the descriptors mc.exe generated must equal what the model (and the C# writer) compute --------
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
Write-Host ("descriptors: all {0} in the header equal the model's (channel keyword 0x{1})" -f $spec.events.Count, $channelKeyword.ToString('x16'))

$fieldsOf = @{}
foreach ($o in $spec.objects) { $fieldsOf[$o.key] = @($o.fields) }

$all = @($spec.events)
if ($PSBoundParameters.ContainsKey('EventId')) {
    $events = @($all | Where-Object { $EventId -contains [int]$_.id })
} else {
    $events = $all
}
Write-Host ("model: {0} objects, {1} events; selected {2}" -f @($spec.objects).Count, $all.Count, $events.Count)
if ($events.Count -eq 0) { throw "no events selected (EventId filter: $($EventId -join ','))" }

if (-not $SkipClear) {
    & wevtutil.exe cl $log
    if ($LASTEXITCODE) { throw "wevtutil cl $log failed ($LASTEXITCODE) - run elevated or pass -SkipClear" }
}

# --- write (New-WinEvent marshals the payload from the registered template; no 8-string cap) ------
$expected = New-Object System.Collections.Generic.List[object]
foreach ($e in $events) {
    $fields = $fieldsOf[$e.object]
    $full  = [object[]]@($fields | ForEach-Object { if ($null -ne $_.example) { [string]$_.example } else { '' } })
    $empty = [object[]]@($fields | ForEach-Object { '' })
    foreach ($payload in @($full, $empty)) {
        New-WinEvent -ProviderName $spec.provider.name -Id $e.id -Version 0 -Payload $payload
        $expected.Add([pscustomobject]@{ Event = $e; Payload = $payload })
    }
}
Write-Host ("wrote {0} events ({1} EventIDs x 2) to {2}" -f $expected.Count, $events.Count, $log)

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
