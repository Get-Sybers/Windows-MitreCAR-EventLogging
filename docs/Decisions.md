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

**Writing events.** No compiled code is needed. The in-box `New-WinEvent` cmdlet writes an event of the
registered provider with a payload marshalled from the template; `scripts/Test-Channel.ps1` does exactly
that for all 73 EventIDs and reads them back. (The .NET `EventProvider.WriteEvent(params object[])`
convenience overload caps a payload at 8 strings and so cannot carry these templates; the writer calls the
native `EventRegister` / `EventWrite` API directly, which has no such cap.)

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

## d8 — the writer is C#/.NET (decided 2026-10-24)

`src/GetSybersMitreCar.Writer/` — a Windows service (console mode for tests) targeting .NET Framework
4.8, which is in-box on every supported Windows, so deployment is a copy plus `sc create`; CI builds it on
`windows-latest` and nothing is compiled at install time.

| Part | What it does |
|---|---|
| `KernelProcessSource` | Opens the real-time ETW session `GSCAR-Sensor` on the kernel's process provider (Microsoft's `TraceEvent` library). On every process start/stop it builds the CAR `process` property set: pid, ppid, exe and the full command line from the kernel event; image path, parent image path, user, SID and integrity level from a live lookup on the process at that instant; hashes, embedded-signature signer and signature validity from the image file. Writes `process/create` (1002) and `process/terminate` (1003). |
| `CarEventWriter` | `EventRegister` / `EventWrite` on the provider GUID; one descriptor per (object, action) computed from `CarModel.g.cs` exactly as `mc.exe` generated them (asserted in CI); every property a null-terminated UTF-16 string, empty when not observed. |
| `CarModel.g.cs` | Generated by `tools/carmodel.py` from the model: objects, ordered property sets, events, descriptor values. Drift-gated like the manifest. |
| `scripts/Test-Writer.ps1` | CI proof: starts the sensor, launches `cmd.exe`, and asserts the 1002/1003 events for that pid carry the expected properties. |
| `scripts/Install-Writer.ps1` | `sc create GetSybersMitreCar … start= auto obj= LocalSystem`. |

Known limits of this first slice, stated rather than hidden: the event's `TimeCreated` is the write time, a
few milliseconds after the action (user-mode ETW delivery); a process that exits before its start event is
delivered yields empty live-lookup properties (image path, user, …) while the kernel-supplied ones stay;
catalog-signed Windows binaries have no embedded signature, so `signer` / `signature_valid` are empty for
them until catalog lookup is added; `parent_command_line`, `current_working_directory` and `env_vars`
(PEB reads) are not yet observed. Next: the remaining phase-1 objects (file, flow, registry, module,
thread) on the same session, then the channel-subscription sources, the autologger, and the sensor
self-events.
