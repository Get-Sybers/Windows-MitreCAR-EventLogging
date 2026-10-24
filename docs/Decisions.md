# Decisions

Decisions taken on 2026-10-24 and what each changed. The step-1 gate of the brief is passed; the
build continues with the manifest and the channel (step 2), then the writer (step 3).

| # | Decision | Applied as |
|---|---|---|
| d1 | **Define all 73 (object, action) pairs.** | The manifest defines 73 events over 13 templates. Every pair is its own event; nothing is suppressed. The 23 overlay actions are shown in the table with the ATT&CK data component they derive from (e.g. registry `create` ← *windows registry key creation: "A registry key was created"*, beside CAR `add`: *"adding a registry key, hive, type, or value"*). Which live observation maps to which pair is decided per source in the writer's provider→CAR map (deliverable 5), not in the schema. |
| d2 | **Do you need to compile code? Would WMI subscribers do?** | Answered below. One thing must be built once with the SDK tools, and it contains no code. |
| d3 | **Three-phase coverage.** | Phase 1 process, file, flow, registry, module, thread · phase 2 driver, service, user_session, authentication · phase 3 socket, http · email: schema only (Windows has no in-box mail-server eventing). |
| d4 | **An event is only the CAR object + action + the object's properties.** | The sensor envelope is gone. A template is exactly the object's CAR property set, in the model's order. Observed time and host are the event's own `TimeCreated` and `Computer`, plus the CAR `fqdn`/`hostname` properties where the model has them. Every property is `win:UnicodeString` with a declared value format, because the brief requires *empty = not observed* and only a string can be empty (the model itself uses the empty state: `file.signature_valid` is "empty if file is not signed"). |
| d5 | **Names.** | Provider `Get-Sybers-MitreCAR`, channel `Get-Sybers-MitreCAR/Operational`, GUID `5bc454ac-3ed9-4b89-b9f4-af8202af0ed8`, resource DLL `GetSybersMitreCar.dll`, symbol prefix `GSCAR_`. |
| d6 | **The numbering "doesn't make sense".** | Re-derived so that every number follows a pinned source's own order and none follows judgement or the brief's illustrative examples (rule in the header of `model/eventids.yaml`): objects in the brief's §5.1 order then alphabetical; **Task = the object's ordinal (1–13)**; within an object, actions in `car-vocab` order (alphabetical), pinned-CAR actions at offsets 1–49 and overlay actions at 50–99; one global Opcode per action name, alphabetical. Hence `process/create` = 1002, `thread/create` = 1501, `user_session/login` = 1702. |
| d7 | **Read Microsoft's docs from the MicrosoftDocs repositories.** | Done; limits corrected and cited in the table (§8): custom opcodes 10–239 (not 238), tasks 1–239, keyword bits 0–47, 100 insertion strings, 128 data items per `EventWrite`, 64 KB per event. The unverifiable "8 channels per provider" claim was dropped. |

## d2 — what has to be compiled, and what does not

**The channel.** An event log channel whose events have named properties, Task/Opcode/Keyword names and
rendered messages exists in Windows only as a *manifest-based provider*. The Event Log service reads the
provider's metadata and message table from Win32 resources in a DLL, so the manifest has to be compiled
into one: `mc.exe` → `rc.exe` → `link.exe /dll /noentry`. That DLL holds **no code** — it is resources
only — and it is built **once**, by CI on a `windows-latest` runner (the Windows SDK and MSVC are
preinstalled there) and published as an artefact. A deployment needs the DLL, the manifest and
`Install-Provider.ps1`, which runs `wevtutil im`. No compiler is involved at install time.

**Writing events.** No compiled code is needed. Windows PowerShell writes fully typed events to the
channel through .NET's `System.Diagnostics.Eventing.EventProvider`; `scripts/Test-Channel.ps1` does
exactly that for all 73 EventIDs and reads them back. `New-WinEvent` is the cmdlet form of the same call.

**WMI subscribers.** WMI can be a *source* for part of the telemetry: `Win32_ProcessStartTrace` /
`Win32_ProcessStopTrace`, `Win32_ThreadStartTrace` / `Win32_ThreadStopTrace` and
`Win32_ModuleLoadTrace` deliver process, thread and module events (with a handful of properties each —
no command line, hashes, user or integrity level). A WMI permanent subscription's
`NTEventLogEventConsumer` can also write events — but only *classic* events: unnamed insertion strings,
no Task/Opcode names, no manifest channel, so it cannot carry a CAR property set by name. And WMI has
no file, registry (with the acting process), network, logon or authentication telemetry at all. So WMI
subscribers alone cannot produce these events; they can feed a few of them.

**Where the properties actually come from.** The kernel ETW providers (process/thread/image, file,
registry, network) for phase 1, and the Security / System / TerminalServices channels for phase 2 —
the sources the brief names in §5.2, with Byakugan's reviewed bindings in the table's last column.

## Open — how the writer is implemented

The channel and the schema are settled and language-neutral. The writer is the remaining choice:

| Option | What it is | Fit |
|---|---|---|
| **A. Script-first reference writer** | Windows PowerShell service (or scheduled task): WMI trace classes + channel subscriptions (`Get-WinEvent`/`EventLogWatcher`) → `EventProvider`. No compiler anywhere. | Proves the model end-to-end on real activity for process/thread/module/user_session/authentication/service. Cannot keep up with the kernel file/registry/network providers (tens of thousands of events per second). |
| **B. Compiled consumer, C#/.NET** | Windows service: real-time ETW sessions (`Microsoft.Diagnostics.Tracing.TraceEvent`) + channel subscriptions → `EventProvider`/`EventWrite`. | Full fidelity for every phase-1 object with far less code than C++; the protected-provider (PPL) path is out of reach for managed code and degrades gracefully. |
| **C. Compiled consumer, C/C++** | The brief's original default: Win32 ETW consumer + `mc.exe`-generated `EventWrite` wrappers. | Most control; needed only if the PPL/ELAM path is pursued. |

Recommendation: **A first, then B** — A lands quickly and exercises every EventID against real activity;
B replaces it for the high-volume kernel sources. Say which, and step 3 starts there.
