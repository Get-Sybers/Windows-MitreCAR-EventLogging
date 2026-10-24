# `model/` — the pinned model, the registries, the derived output

Nothing in this directory describes the CAR data model in its own words. The model is **read** from
the pinned sources, the registries **pin numbers and types onto it**, and the generator **validates**
one against the other before rendering anything.

| Path | Role | Edit? |
|---|---|---|
| `sources/car/` | git submodule — the MITRE CAR data model (`Get-Sybers/car` @ `1b922fe…`): `data_model/*.yaml` are the objects, actions and property sets; `sensors/*.yaml` the sensor cards | never — bump the pin |
| `sources/byakugan/PIN.yaml` | the Byakugan commit behind the vendored files, and what each file is | on a pin bump |
| `sources/byakugan/car-vocab.json` | `byakugan car-vocab` output at the pin — the canonical `{object: [actions]}` vocabulary | never — re-vendor |
| `sources/byakugan/car-actions.schema.json` | `model/schema/vocab/car-actions.schema.json` at the pin — the 13 objects + the 3 promoted objects | never — re-vendor |
| `sources/byakugan/matched-evidences.yaml` | `model/schema/matched-evidences.yaml` at the pin; only its `evtx:` section is read (Windows event → (object, action) bindings) | never — re-vendor |
| `eventids.yaml` | **the EventID registry** — objects → Task/base/Keyword, actions → Opcode, (object, action) → EventID, reserved ranges | yes, under the change protocol |
| `templates.yaml` | the sensor envelope and one wire type per CAR field (default `win:UnicodeString`) | yes |
| `generated/car-eventlog-model.json` | the derived model — every object with its typed fields and events — the input for the manifest generator | never — `generate` |

## Regenerate

```sh
python tools/carmodel.py check      # validates everything and fails on drift — what CI runs
python tools/carmodel.py generate   # rewrites generated/ and docs/EventID-Table.md
```

## Change protocol

- **Numbers are wire format.** Never renumber. A retired action keeps its EventID (mark it
  `retired`); a new action takes the next free offset in its object's range (1–49 if it is in the
  pinned CAR submodule, 50–99 if `car-vocab` adds it); a new object takes the next free hundred.
- **Pin bumps:** update the submodule to the new commit, re-copy the three Byakugan files at the new
  Byakugan commit, record both in `PIN.yaml`, run `generate`, review the diff of
  `docs/EventID-Table.md` — the generator refuses to proceed when the registry no longer covers the
  model exactly, so a new upstream action shows up as a validation error, not as a silent gap.
- **Types:** add a rule to `templates.yaml` rather than a one-off; every non-string field cites a rule.
