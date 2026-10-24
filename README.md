# Windows-MitreCAR-EventLogging

A native Windows event log for MITRE CAR. Every event is **one CAR object, one CAR action, and the
object's full property set**, exactly as the [CAR data model](https://car.mitre.org/data_model/)
defines them:

| CAR | Windows event | Example |
|---|---|---|
| object | **Task** (and one Keyword bit) | `process` |
| action | **Opcode** | `create` |
| properties | **EventData** — every property of the object, by name, in the model's order | `fqdn`, `hostname`, `command_line`, `exe`, `image_path`, `md5_hash`, … (29 for process) |
| (object, action) | **EventID** | `process/create` = **1002** |

Delivery is Sysmon-style: its own channel, **`Get-Sybers-MitreCAR/Operational`**, under
*Applications and Services Logs*, visible in Event Viewer and collectable with `wevtutil`, WEF/WEC and
any SIEM. A property that was not observed is written empty, never inferred.

## Status

| Step | State |
|---|---|
| 1. EventID table derived from the pinned model | done — [`docs/EventID-Table.md`](docs/EventID-Table.md) |
| 2. Manifest, build, register, prove the channel | manifest generated — [`manifest/GetSybersMitreCar.man`](manifest/GetSybersMitreCar.man); CI builds the DLL, registers the channel and writes/reads back every EventID (`scripts/`) |
| 3. Writer: live telemetry → events | C#/.NET service (`src/GetSybersMitreCar.Writer`): first slice observes process start/stop from the kernel ETW provider in real time and writes `process/create` / `process/terminate`; CI launches a process and reads the events back |

## The model

13 objects, 219 properties, 73 (object, action) events. 50 actions come from the pinned CAR data model,
23 are the ATT&CK data-component actions that `byakugan car-vocab` adds (shown with their ATT&CK
definition in the table). EventID = object base + offset, Task = the object's ordinal, one Opcode per
action name, one Keyword bit per object. The full table: [`docs/EventID-Table.md`](docs/EventID-Table.md).

| Task | Object | EventIDs | Task | Object | EventIDs |
|---:|---|---|---:|---|---|
| 1 | process | 1001–1003, 1050–1052 | 8 | user_session | 1701–1705, 1750–1752 |
| 2 | file | 1101–1107, 1150–1152 | 9 | service | 1801–1805, 1850–1853 |
| 3 | flow | 1201–1203, 1250–1252 | 10 | authentication | 1901–1903 |
| 4 | registry | 1301–1304, 1350–1353 | 11 | email | 2001–2005 |
| 5 | module | 1401–1402, 1450–1451 | 12 | http | 2101–2104 |
| 6 | thread | 1501–1504 | 13 | socket | 2201–2203 |
| 7 | driver | 1601–1602, 1650 | | | |

Ranges 2300/2400/2500 are reserved for the schema's promoted objects (group, scheduled_job,
user_account — no CAR field sets yet) and 9000–9099 for sensor self-events.

## Install and try it (Windows, elevated)

```powershell
# channel: from the CI artefact `GetSybersMitreCar`, or build locally (Windows SDK + MSVC link.exe; code-free resource DLL)
.\scripts\Build-Manifest.ps1            # manifest/GetSybersMitreCar.man -> build/GetSybersMitreCar.dll
.\scripts\Install-Provider.ps1          # wevtutil im -> the channel appears in Event Viewer
.\scripts\Test-Channel.ps1 -EventId 1002  # writes two process/create events (New-WinEvent) and reads them back

# sensor: build (dotnet build src/GetSybersMitreCar.Writer -c Release) or take it from the artefact, then
.\scripts\Test-Writer.ps1               # runs it in the foreground, starts cmd.exe, checks 1002/1003 for that pid
.\scripts\Install-Writer.ps1            # or install it as the GetSybersMitreCar service (LocalSystem, automatic)

.\scripts\Uninstall-Writer.ps1; .\scripts\Uninstall-Provider.ps1
```

## Authoritative sources (pinned)

| What | Where | Pin |
|---|---|---|
| MITRE CAR data model — objects, actions, property sets, sensor cards | `model/sources/car` (git submodule of `Get-Sybers/car`) | `1b922fe1527d956e222a99473472e594f10f610b` |
| Canonical action vocabulary (`byakugan car-vocab`), the `model/schema` vocabulary, the ATT&CK data components behind the overlay actions, reviewed Windows-event bindings | `model/sources/byakugan/` (vendored, byte-checked in CI) | Byakugan `8e151977a05d607b87ef852617058ee23967a6e0` |

Byakugan is a **schema source only**: nothing here integrates with its pipeline, stores, projection,
Elastic or STIX outputs.

## Layout

```
manifest/GetSybersMitreCar.man        the instrumentation manifest — GENERATED from the model
src/GetSybersMitreCar.Writer/         the sensor (C#, .NET Framework 4.8): ETW consumer → CAR events; CarModel.g.cs is GENERATED
scripts/                              Build-Manifest, Install/Uninstall-Provider, Test-Channel, Test-Writer, Install/Uninstall-Writer
model/
  sources/car/                        pinned MITRE CAR data model (submodule)
  sources/byakugan/                   PIN.yaml + the vendored vocabulary / schema / ATT&CK / bindings files
  eventids.yaml                       THE registry: objects → Task/base/Keyword, actions → Opcode, (object, action) → EventID
  templates.yaml                      the value format per CAR property (every property is win:UnicodeString)
  generated/car-eventlog-model.json   the derived model, machine-readable
docs/EventID-Table.md                 the numbered table — GENERATED
docs/Decisions.md                     decisions taken, including the writer's design
tools/carmodel.py                     generate | check | dump | matrix
tests/test_model.py                   unit tests (unittest / pytest)
.github/workflows/ci.yml              model drift gate (ubuntu) + build/register/write/read gate (windows)
```

```sh
git submodule update --init model/sources/car
python -m pip install pyyaml
python tools/carmodel.py check          # what CI runs
python tools/carmodel.py generate       # after editing eventids.yaml / templates.yaml
python -m unittest discover -s tests
```

A published EventID, Task, Opcode or Keyword never changes: retire by keeping the number, add by taking
the next free slot. A model refresh is a submodule-pin bump plus re-vendoring `model/sources/byakugan/`.

## Scope

**In:** the provider/channel manifest and resource DLL, the real-time writer (live telemetry → events),
the provider→CAR mapping as data, per-EventID tests, install/uninstall scripts.
**Out (brief §3):** Byakugan pipeline integration, dead-box or batch processing, enrichment,
relationship/timeline building, cross-event correlation. One observed action → one event.
