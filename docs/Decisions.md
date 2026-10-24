# Decisions — confirm before step 2

**Where we are.** Deliverable 1 of the mission brief is done: the numbered EventID table
([`EventID-Table.md`](EventID-Table.md)) is derived from the pinned model by
[`tools/carmodel.py`](../tools/carmodel.py), pinned in [`model/eventids.yaml`](../model/eventids.yaml),
typed in [`model/templates.yaml`](../model/templates.yaml), and gated by CI. Per brief §10 step 1 the
build pauses here for confirmation. Everything below is either a decision the brief said is required
before kickoff, or a choice made while deriving the table that should be ratified (or changed —
nothing is built on the numbers yet, so changing them now is free).

Recommendations are marked **→**. Items are ordered by how much they change what gets built.

---

## D0 — Which matrix is "the pinned model"? *(found during derivation)*

The brief names three authoritative sources. They agree on the 13 objects and on every field list,
but they are **nested, not identical**, on actions:

| Source | Objects | (object, action) pairs | Field sets |
|---|---:|---:|---|
| `model/sources/car` — the pinned MITRE CAR submodule (`1b922fe`) | 13 | **50** | yes |
| `byakugan car-vocab` — fields from the submodule, actions from the CAR + ATT&CK data-component superset | 13 | **73** | yes (same 219 fields) |
| `model/schema/vocab/car-actions.schema.json` — generated from `model/car/objects` plus the three *promoted* objects | 16 | 73 + 13 | **no** field sets for group / scheduled_job / user_account |

The 23 extra `car-vocab` pairs come from ATT&CK data components folded onto CAR objects
(`byakugan/build_data_model.py: _action_for`): file `access/content/metadata`, flow `content/create/flow`,
module `content/metadata`, process `execute/metadata/modify`, registry `access/create/delete/modify`,
service `access/enumerate/metadata/modify`, user_session `create/metadata/terminate`, driver `metadata`.
Several are **state descriptors, not observable actions** (`metadata`, `content`), and several are
**twins of a pinned CAR action** (registry `create`≈`add`, `delete`≈`remove`, `modify`≈`value_edit`/`key_edit`;
flow `create`≈`start`; user_session `create`≈`login`, `terminate`≈`logout`; file `access`≈`read`).

**→ Recommendation: option B.**

| | Option | Consequence |
|---|---|---|
| A | Pinned CAR only — 50 EventIDs | Smallest manifest; the CI gate can no longer be "against `car-vocab`" literally. |
| **B** | **`car-vocab` — all 73 EventIDs defined; writer emits only what it observes** | Manifest cost is nil (templates are per object). Pinned-CAR actions sit at offsets 1–49, superset at 50–99, so A can be adopted later without renumbering. The writer maps one observed event to **one** CAR event — the pinned-CAR action — so twins stay defined but unpopulated; superset events are emitted only where a *distinct* observation exists. |
| C | B plus the three promoted objects with hand-authored field sets | Rejected: the pinned model gives them actions only; authoring fields is exactly the invention the brief forbids. Their ranges (2300/2400/2500) are **reserved**, so adopting them after Byakugan's runtime promotion lands never renumbers. |

The table is built as B. Nothing changes if you choose A except that the 23 `superset` rows are dropped
from the manifest (one flag in the generator).

## D1 — Implementation language *(required before kickoff)*

**→ C/C++** (the brief's recommended default): instrumentation manifest → `mc.exe`/`rc.exe`/`link` →
message/resource DLL registered with `wevtutil im`; the writer is a Win32 service that consumes ETW in
real time (`OpenTrace`/`ProcessTrace` + TDH decoding) and the Security/System channels by push
subscription (`EvtSubscribe`), and calls the `mc.exe`-generated `EventWrite*` wrappers. Reasons:

- The Event Viewer channel is a hard requirement (§1), so the **manifest path is mandatory**; the
  manifest is the artefact the generator will emit from `car-eventlog-model.json`, language aside.
- Only the manifest + Win32 route gives exact control of EventID / Task / Opcode / Keyword values and the
  typed templates in §6 of the table. .NET `EventSource` can target a channel but generates its own
  manifest and constrains how tasks/opcodes/keywords and payload types are expressed; keeping its
  output byte-aligned with this registry would be a constant fight.
- Rust is viable (`windows` crate; `cargo check --target x86_64-pc-windows-gnu` type-checks on Linux,
  which is attractive for CI) but the ETW consumer/TDH surface is verbose in Rust and gains nothing
  over C here; it remains the fallback if a memory-safety mandate appears.

Toolchain facts from this environment: no `dotnet`, no MSVC; `mingw-w64` is installable (compile
checks only — it has no `mc.exe`); Rust 1.97 is present. **Manifest compilation and the end-to-end
tests therefore run on a `windows-latest` GitHub Actions runner** (Windows SDK + MSVC are preinstalled),
added as a second CI job in step 2.

## D2 — v1 coverage *(required before kickoff)*

**→ Phase 1: process, file, flow, registry, module, thread** — the objects whose live telemetry comes
from the in-box kernel ETW providers (process/thread/image, file I/O, registry, network); these are
also the objects the pinned Sysmon sensor cards and Byakugan's maps cover best, so field population
can be cross-checked against known-good Sysmon semantics.

**→ Phase 2: driver, service, user_session, authentication** — sourced from the kernel image-load
trace (drivers) and from real-time subscriptions to the Security and System channels plus the
TerminalServices/Winlogon operational channels (Byakugan's `evtx` bindings in the table list the
event ids per pair).

**→ Phase 3: socket, http** — Winsock/TCPIP provider events and the HTTP service / WinINet /
WinHTTP providers; lower certainty, verified on a live host first.

**email: schema only.** Windows has no in-box mail-server eventing (Byakugan's own warrant sweep
records "honest null — no OS mail eventing"). The five EventIDs exist so a future Exchange/MTA feed
has a home; the writer will not populate them.

## D3 — Keyword scheme *(required before kickoff)*

**→ One keyword bit per object** (bits 0–12), bits 13–15 reserved for the promoted objects, bit 47
for sensor self-events. Keywords are a *mask*, so this is the one filter that selects several objects
in a single WEF subscription or `wevtutil qe` query, which Task (a scalar) cannot.

For the eight `car+attack` objects the object bit **is** the ATT&CK data-source bit (the pinned
superset catalogue maps them 1:1: Process, File, Network Traffic, Windows Registry, Module, Driver,
Service, Logon Session), so a data-source keyword adds nothing. An ATT&CK **tactic** keyword cannot
be derived from the model — tactics attach to analytics and techniques, not to (object, action) — so
encoding one would be invention. **→ No tactic keywords in v1.**

## D4 — The sensor envelope

Every template opens with three non-CAR fields (table §5): `UtcTime` (the observed instant, brief §6),
`Host` (host identity on every event, brief §6), and `SourceProvider` (which live provider/event
supplied the record). The third is this project's addition: it lets a consumer judge *how* each
field was populated and is the honest counterpart of "no inferred fields". **→ Keep all three**; drop
`SourceProvider` if a strictly-CAR payload is preferred.

## D5 — Names *(required before kickoff)*

| Item | Proposed |
|---|---|
| Provider name | `Get-Sybers-MitreCAR` |
| Channel | `Get-Sybers-MitreCAR/Operational` (type Operational) |
| Provider GUID | `5bc454ac-3ed9-4b89-b9f4-af8202af0ed8` — freshly generated; replace if one is already allocated |
| Symbol prefix (manifest / generated header) | `GSCAR_` |
| Resource/message DLL | `GetSybersMitreCar.dll` |
| Writer service | `GetSybersMitreCar` ("Get-Sybers MITRE CAR Sensor") |
| Trace session / autologger | `GSCAR-Sensor` |

## D6 — Numbering choices to ratify

- **Task = EventID div 100.** The brief asked only that Task identify the object; making the hundreds
  digits *be* the Task keeps the ID self-describing (1xxx–2xxx CAR objects, 90xx sensor).
- **Within an object:** the brief's example IDs were honoured wherever the model has the action
  (1001/1002, 1101/1102/1103, 1201/1202, 1301, 1401, **1501 = remote_create**), then the remaining
  pinned-CAR actions follow in the order `data_model/<object>.yaml` lists them, then superset actions
  alphabetically from offset 50.
  - **registry:** the brief's `1302 edit` has no counterpart — CAR defines `value_edit` and `key_edit` —
    so: add 1301, remove 1302, value_edit 1303, key_edit 1304.
  - **thread:** honouring `1501 remote_create` puts the subset event before `create` (1502); CAR's own
    order would be create/suspend/terminate/remote_create. **Review item** — either is fine, decide now.
- **Opcodes:** one global value per action name, pinned-CAR names alphabetical from 10, the five
  superset-only names (`content, enumerate, execute, flow, metadata`) after them (51–55).
- **Stability rule:** a published number never changes; a retired action keeps its number as
  `retired`; new ones take the next free slot. Renumbering is a schema-version bump.

## D7 — Typing choices to ratify

CAR carries no types. `model/templates.yaml` adds one wire type per field via 14 rules; everything
not listed is `win:UnicodeString`. Cross-checked against the type decisions Byakugan's CAR→ECS
projection made for the same fields (date/long/ip/boolean; keyword otherwise) — used as a reference
only, no projection is integrated. Choices worth a look:

- IPs and hashes are strings (brief §6; ETW has no IP type worth the rendering trouble).
- `pid`/`ppid`/`*_pid` → `win:UInt32` (`win:PID`); `tid`/`*_tid` → `win:UInt32` (`win:TID`); ports → `win:UInt16`.
- Timestamps (`creation_time`, `previous_creation_time`, `start_time`, `end_time`, email `date`) → `win:FILETIME` UTC.
- Virtual addresses (`base_address`, `stack_*`, `start_address`, `user_stack_*`) → `win:UInt64` rendered `win:HexInt64`.
- `access_level` → `win:UInt32` rendered `win:HexInt32`; `login_id` (a LUID) → `win:UInt64` rendered `win:HexInt64`.
- `guid` / `parent_guid` / `target_guid` → `win:GUID`, **minted by the sensor Sysmon-style** when the
  source telemetry carries no process GUID (deterministic from boot id + pid + start time). This is an
  identifier the sensor assigns, not an inferred fact; flagging it here because it is the one place
  the writer will write something it did not read.
- `response_time` → milliseconds (`win:UInt32`, CAR example "12ms"); `attachment_size` → bytes
  (`win:UInt64`, CAR example "567 Kb" is loose text); `response_status_code` → `win:UInt16`.
- `integrity_level`, registry `type`, file `mode`, `network_direction`, `tcp_flags` stay strings as
  the model gives them (the writer normalises casing where CAR mandates values).

## D8 — Facts taken from memory (verify at first `mc.exe` run)

Microsoft Docs was not reachable from the build environment (DNS blocked). The generator enforces
these limits from memory; `mc.exe` is the authority and will reject anything wrong:
custom opcodes 10–238 · provider keyword bits 0–47 (top 16 bits reserved) · Task 1–65535 ·
`EventWrite` ≤ 128 data items · message inserts `%1`–`%99` · ≤ 8 channels per provider ·
channel name ≤ 255 characters. The largest template (process) is 32 data items.

---

## Once confirmed — brief §10 steps 2–5

1. **Manifest for one object end-to-end** (process create/terminate): emit `GetSybersMitreCar.man`
   from `car-eventlog-model.json`, build (`mc`/`rc`/`link`), register (`wevtutil im`), confirm it renders
   in Event Viewer; windows-latest CI job.
2. **Writer for that object** against the live process provider; prove 1001/1002 land fully populated.
3. **Fan out** per D2; the provider→CAR mapping table (deliverable 5) as data beside the registry,
   seeded from the table's *Byakugan evtx bindings* column and the pinned sensor cards.
4. Autologger install, privilege model for the PPL-gated provider, drop metrics, sensor self-events
   (range 9000), and the Windows build/test job joining the model drift gate already in CI.
