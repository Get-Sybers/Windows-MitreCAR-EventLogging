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

## d8 — the writer is C#/.NET; everything is built on Windows (decided 2026-10-24)

`src/GetSybersMitreCar.Writer/` — a Windows service (console mode for tests) targeting .NET Framework 4.8,
in-box on every supported Windows, so deployment is a copy plus `sc create`. `scripts/build.ps1` builds the
resource DLL (`mc.exe` → `rc.exe` → `link.exe`) and the sensor (`dotnet build`) on a Windows machine and
stages `dist\`. Nothing is compiled on GitHub Actions; CI only checks the model.

| Part | What it does |
|---|---|
| `KernelSource` | One real-time kernel ETW session (`GSCAR-Sensor`, Microsoft's `TraceEvent` library) with the process, thread, image, file, registry and TCP/IP keywords. Each kernel event maps to one CAR (object, action) — the map is `model/sources-map.yaml` — and the object's full property set is filled from the event, from a live lookup at that instant, and from the sensor's own tables (processes, modules, flows). Nothing is inferred and no name is resolved by DNS. Writes process 1002/1003, file 1102–1107, flow 1201–1203, registry 1301/1303/1304/1350, module 1401/1402, thread 1501/1502/1504, driver 1601/1602. |
| host-observability fills | The adversarial audit (2026-10-24): every property a host can show without inference or DNS is read. `ProcessInspector` reads the live token (SID, integrity) and the process **PEB** (`current_working_directory`, `command_line`, `env_vars`); the kernel Process payload's own `TOKEN_USER` SID is parsed as a fallback. `ProcessTable` carries a process's start-time facts (image hashes, signer, parent image and command line, cwd, environment) so `process/terminate` reports them for a process that has already exited. `FileInspector.Read` adds `owner`/`group` and their SIDs, the DACL as `mode` (SDDL), `link_target` (reparse point), and the registered `mime_type`; `company` comes from the acting image's version resource. `FileIO/OperationEnd` is matched to its create/set-information request so the kernel's own result (not the requested disposition) decides a real `create` or `timestomp`. `ModuleMap` + `PeExports` resolve a thread's `start_module` / `start_function` (exact export only). `FlowTable` counts a flow's bytes and packets for `flow/end`, and a flow endpoint that is one of this host's own addresses is named as this host. |
| `CarEventWriter` | `EventRegister` / `EventWrite` on the provider GUID; one descriptor per (object, action) computed from `CarModel.g.cs` exactly as `mc.exe` generated them (`Test-Channel.ps1` asserts this against the header); every property a null-terminated UTF-16 string, empty when not observed; property names are validated against the object's set. |
| `CarModel.g.cs` | Generated by `tools/carmodel.py`: objects, ordered property sets, events, descriptor values. Drift-gated. |
| `--selftest` | Writes, per EventID, one event with every property set to its own name and one with every property empty — the channel proof `Test-Channel.ps1` reads back. |
| `scripts/Test-Sensor.ps1` | Runs the sensor and performs real activity for every phase-1 object, then asserts the events for that activity and their properties. |

Volume controls: `--threads`, `--file-reads`, `--flow-messages`, `--registry-access` turn on the pairs that
fire thousands of times a second; everything else is always on. `EventsLost` from the session and handler
errors are logged at stop.

Known limits, stated rather than hidden: the event's `TimeCreated` is the write time, a few milliseconds
after the action (user-mode ETW delivery); a kernel registry create event carries no disposition, so an
`NtCreateKey` on an existing key also yields `registry/add`; kernel registry events carry no data, so
`value_edit` reads the value live after the set; catalog-signed Windows binaries have no embedded
signature, so `signer` / `signature_valid` are empty for them until catalog lookup is added; a PEB read
needs the process to be alive and openable, so `current_working_directory` / `env_vars` of a short-lived
or protected process (and of another user's process without `SeDebugPrivilege`) stay empty; `file/delete`
reads the file's on-disk state before the entry is gone, so its `owner` / `mode` / times may be empty if the
delete has already completed; `file` reads do an ACL and attribute read per event, a real cost paid only on
the opt-in `--file-reads` and on writes; what still needs a source other than the kernel session is not yet
observed — `env_vars` is off with `--no-env-vars`; `process` `guid` / `access_level` / `target_*` (Sysmon-style
process-access), `file` `content`, `flow` `content` / `proto_info` / `tcp_flags` / `application_protocol`, and
`registry/key_edit`, `file/acl_modify`, `thread/suspend`, `process/access` (other providers). Next: phase 2
(service, user_session, authentication from the Security / System / TerminalServices channels), phase 3
(socket, http), the autologger, and the sensor self-events.

### Adversarial host-observability audit (2026-10-24)

The brief requires each event to carry the object's complete property set, "only what is actually observed …
empty = not observed." After phase 1 first landed, every empty property of every implemented pair was
re-examined against one question: can the host the log is generated on show this value now, without inference
and without a DNS or reverse-DNS lookup? Everything that could be is now read. The per-pair populated-property
counts rose accordingly (`model/sources-map.yaml` is the authoritative per-property map):

| pair | before | after | what was added |
|---|---|---|---|
| process/create | 17 | 21 | PEB `current_working_directory`, `env_vars`, `parent_command_line`; `uid` |
| process/terminate | 8 | 21 | all start-time facts carried from the process table (hashes, signer, integrity, parents, cwd, env) |
| file/create | 12 | 24 | `ppid`, image hashes/`signer`/`signature_valid`/`company`, `group`/`gid`, `mode` (SDDL), `link_target`, `mime_type` |
| file/write, read, delete, modify | 9–10 | 23 | same on-disk and acting-image fills as create |
| file/timestomp | 10 | 25 | the create fills plus `previous_creation_time` |
| flow/start | 14 | 17 | `ppid`; `src_`/`dest_hostname`/`fqdn` when an endpoint is this host |
| flow/end | 13 | 23 | `ppid`, local host names, `in_bytes` / `out_bytes` / `packet_count` counted on the flow |
| registry/access | 8 | 10 | live value `data` / `type` on a QueryValue |
| module/unload, driver/unload | 8 / 6 | 13 / 11 | the file is still on disk, so hashes / `signer` / `signature_valid` like load |
| thread/create, remote_create | 12 | 15 | `start_module` / `start_module_name` / `start_function` from the module map and PE exports |
| thread/terminate | 8 | 13 | the same start-module resolution plus the owning process's `user` / `uid` |

Deliberately still empty (the host cannot show them here without inference, or they belong to another source):
reverse-DNS names for a remote flow endpoint; `flow` payload fields (`content`, `proto_info`, `tcp_flags`,
`application_protocol`); `file`/`flow` `content`; Sysmon-style `process` `guid` / `target_*` / `access_level`;
and the pairs still marked `planned` in the map.
