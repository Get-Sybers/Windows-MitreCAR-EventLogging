# Windows-MitreCAR-EventLogging

A real-time Windows Event Log provider that emits **MITRE CAR objects as structured events**: one
EventID per CAR **(object, action)**, each event carrying that object's **complete property set**,
populated from live telemetry at the instant the action happens. Delivery is Sysmon-style — a
dedicated channel under *Applications and Services Logs*, visible in Event Viewer and collectable by
`wevtutil`, WEF/WEC and any SIEM — but with the **MITRE CAR data model** as the event schema.

**Status: deliverable 1 complete — awaiting confirmation before the manifest/writer build.**
Read [`docs/EventID-Table.md`](docs/EventID-Table.md) (the numbered table) and
[`docs/Decisions.md`](docs/Decisions.md) (what to confirm).

## The model in one screen

| Task | Object | EventIDs | Events | Properties | Task | Object | EventIDs | Events | Properties |
|---:|---|---|---:|---:|---:|---|---|---:|---:|
| 10 | process | 1001–1003, 1050–1052 | 6 | 29 | 17 | service | 1701–1705, 1750–1753 | 9 | 10 |
| 11 | file | 1101–1107, 1150–1152 | 10 | 26 | 18 | user_session | 1801–1805, 1850–1852 | 8 | 10 |
| 12 | flow | 1201–1203, 1250–1252 | 6 | 27 | 19 | authentication | 1901–1903 | 3 | 19 |
| 13 | registry | 1301–1304, 1350–1353 | 8 | 11 | 20 | socket | 2001–2003 | 3 | 10 |
| 14 | module | 1401–1402, 1450–1451 | 4 | 13 | 21 | http | 2101–2104 | 4 | 17 |
| 15 | thread | 1501–1504 | 4 | 15 | 22 | email | 2201–2205 | 5 | 21 |
| 16 | driver | 1601–1602, 1650 | 3 | 11 | | | | | |

- **73 events** over **13 objects** and **219 properties**: 50 actions defined by the pinned CAR
  submodule (offsets 1–49) plus 23 added by `byakugan car-vocab` from the ATT&CK overlay (offsets 50–99).
- **EventID = object base + offset · Task = EventID div 100 · Opcode = the action (global) · Keyword = one bit per object.**
  Filter by object (Task, Keyword), by action (Opcode), or slice by ID range.
- **One typed template per object**, reused across its actions; a 3-field sensor envelope
  (`UtcTime`, `Host`, `SourceProvider`) then the object's full CAR property set. Unobserved fields
  are empty, never inferred.
- Ranges 2300/2400/2500 are reserved for the schema's promoted objects (group, scheduled_job,
  user_account — no CAR field set yet); 9000–9099 for sensor self-events.

## Authoritative sources (pinned)

| What | Where | Pin |
|---|---|---|
| MITRE CAR data model — objects, actions, property sets, sensor cards | `model/sources/car` (git submodule of `Get-Sybers/car`) | `1b922fe1527d956e222a99473472e594f10f610b` |
| Canonical action vocabulary (`byakugan car-vocab`), the `model/schema` vocabulary, reviewed Windows-event bindings | `model/sources/byakugan/` (vendored, byte-checked in CI) | Byakugan `8e151977a05d607b87ef852617058ee23967a6e0` |

Byakugan is a **schema source only**. Nothing here integrates with its pipeline, stores, CAR→ECS
projection, Elastic or STIX outputs (brief §3).

## Layout

```
model/
  sources/car/                 pinned MITRE CAR data model (submodule)
  sources/byakugan/            PIN.yaml + car-vocab.json + car-actions.schema.json + matched-evidences.yaml
  eventids.yaml                THE registry: objects → Task/base/Keyword, actions → Opcode, (object, action) → EventID
  templates.yaml               the sensor envelope + a wire type per CAR field
  generated/car-eventlog-model.json   the derived model, machine-readable (input to the manifest generator)
docs/
  EventID-Table.md             deliverable 1 — GENERATED, do not edit
  Decisions.md                 decisions to confirm before step 2
tools/carmodel.py              generate | check | dump | matrix
tests/test_model.py            unit tests (unittest / pytest)
.github/workflows/ci.yml       the drift gate: pins ⇄ vendored files ⇄ registry ⇄ generated outputs
```

## Working with the model

```sh
git submodule update --init model/sources/car     # once, after cloning
python -m pip install pyyaml                       # the only runtime dependency
python tools/carmodel.py check                     # validate + fail on drift (what CI runs)
python tools/carmodel.py generate                  # after editing eventids.yaml / templates.yaml
python tools/carmodel.py matrix                    # the object × action matrix at a glance
python -m unittest discover -s tests               # or: pytest -q tests
```

Change protocol: a published EventID, Task, Opcode or Keyword never changes. Retire by keeping the
number; add by taking the next free slot in the object's range. A model refresh is a submodule-pin
bump plus re-vendoring `model/sources/byakugan/` at a new Byakugan commit, then `generate`.

## Scope

**In:** the provider/channel manifest, the real-time writer service (ETW consumer + channel
subscriptions → `EventWrite`), the provider→CAR mapping as data, per-EventID tests, install/uninstall scripts.
**Out (brief §3):** Byakugan pipeline integration, dead-box or batch processing, enrichment,
relationship/timeline building, cross-event correlation. One observed action → one event.
