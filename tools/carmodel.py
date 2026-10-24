#!/usr/bin/env python3
"""tools/carmodel.py — derive the CAR event-log model from the pinned sources and gate drift.

The model has exactly three inputs, all pinned:

  model/sources/car/                       the MITRE CAR data model (git submodule): objects, actions,
                                           property sets, descriptions, examples, sensor cards
  model/sources/byakugan/car-vocab.json    the canonical car_action vocabulary (`byakugan car-vocab`)
  model/sources/byakugan/car-actions.schema.json
                                           the model/schema vocabulary (adds the promoted objects)

and two hand-pinned registries that are VALIDATED against them, never derived from them:

  model/eventids.yaml                      objects → Task/base/Keyword, actions → Opcode, (object, action) → EventID
  model/templates.yaml                     the envelope + a wire type per CAR field

Outputs (committed, regenerated, drift-gated):

  docs/EventID-Table.md                    deliverable 1 — the numbered EventID table
  model/generated/car-eventlog-model.json  the same model, machine-readable, for the manifest generator

Usage:
  python tools/carmodel.py generate        validate, then (re)write the outputs
  python tools/carmodel.py check           validate, regenerate in memory, fail if the committed outputs differ
  python tools/carmodel.py dump            validate, print the derived model as JSON
  python tools/carmodel.py matrix          validate, print the object × action matrix
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import OrderedDict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CAR_DIR = ROOT / "model" / "sources" / "car"
BYK_DIR = ROOT / "model" / "sources" / "byakugan"
REGISTRY = ROOT / "model" / "eventids.yaml"
TEMPLATES = ROOT / "model" / "templates.yaml"
OUT_JSON = ROOT / "model" / "generated" / "car-eventlog-model.json"
OUT_MD = ROOT / "docs" / "EventID-Table.md"

# Limits the ETW manifest toolchain imposes (verified again by mc.exe at build time).
OPCODE_RANGE = (10, 238)          # provider-defined opcode values; 0–9 reserved by ETW
KEYWORD_BITS = (0, 47)            # provider-defined keyword bits; the top 16 are reserved
TASK_RANGE = (1, 65535)
EVENTID_RANGE = (0, 65535)
MAX_MESSAGE_INSERTS = 99          # %1..%99 in an event message string
MAX_EVENT_DATA_DESCRIPTORS = 128  # EventWrite UserDataCount ceiling


class ModelError(Exception):
    """A validation failure; the message lists every problem found."""


# ----------------------------------------------------------------------------- loading


def _yaml(path: Path):
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _json(path: Path):
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def load_pinned_car() -> "OrderedDict[str, dict]":
    """The 13 CAR objects from the pinned submodule, keyed by the data_model file stem."""
    dm = CAR_DIR / "data_model"
    if not dm.is_dir():
        raise ModelError(f"pinned CAR data model missing at {dm} — "
                         "run `git submodule update --init model/sources/car`")
    objs: "OrderedDict[str, dict]" = OrderedDict()
    for p in sorted(dm.glob("*.yaml")):
        d = _yaml(p)
        objs[p.stem] = {
            "key": p.stem,
            "name": d["name"],
            "description": (d.get("description") or "").strip(),
            "actions": [a["name"] for a in d["actions"]],
            "action_descriptions": {a["name"]: (a.get("description") or "").strip() for a in d["actions"]},
            "fields": [
                {"name": f["name"],
                 "description": (f.get("description") or "").strip(),
                 "example": f.get("example")}
                for f in d["fields"]
            ],
            "coverage_map": d.get("coverage_map") or {},
            "source_file": f"model/sources/car/data_model/{p.name}",
        }
    return objs


def load_sensor_cards() -> dict:
    """{(object, action): [{"sensor", "event", "fields"}]} from model/sources/car/sensors/*.yaml."""
    out: dict = {}
    sdir = CAR_DIR / "sensors"
    for p in sorted(sdir.glob("*.yaml")) if sdir.is_dir() else []:
        d = _yaml(p)
        for m in d.get("mappings") or []:
            note = m.get("notes") or ""
            ev = re.search(r"Event\s+(\d+(?:/\d+)*)", note)
            out.setdefault((m["object"], m["action"]), []).append({
                "sensor": p.stem,
                "event": ev.group(1) if ev else None,
                "fields": list(m.get("fields") or []),
            })
    return out


def load_vocab() -> dict:
    return _json(BYK_DIR / "car-vocab.json")


def load_schema_vocab() -> tuple[list[str], dict]:
    s = _json(BYK_DIR / "car-actions.schema.json")
    defs = s["$defs"]
    objects = list(defs["object"]["enum"])
    actions = {o: list(defs[f"{o}-actions"]["enum"]) for o in objects}
    return objects, actions


def load_evtx_evidences() -> dict:
    """{(object, action): [row]} — only the `evtx:` section of Byakugan's matched-evidences overlay."""
    d = _yaml(BYK_DIR / "matched-evidences.yaml")
    out: dict = {}
    for r in d.get("evtx") or []:
        if isinstance(r, dict) and r.get("object") and r.get("action"):
            out.setdefault((r["object"], r["action"]), []).append(r)
    return out


def load_pin() -> dict:
    return _yaml(BYK_DIR / "PIN.yaml")


def load_registry() -> dict:
    return _yaml(REGISTRY)


def load_templates() -> dict:
    return _yaml(TEMPLATES)


# ----------------------------------------------------------------------------- validation


def _git(*args: str) -> str | None:
    try:
        return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True,
                              text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def check_pins(pin: dict, errors: list[str], warnings: list[str]) -> None:
    want = pin["car_submodule"]["commit"]
    idx = _git("ls-files", "-s", "model/sources/car")
    if idx:
        parts = idx.split()
        if len(parts) >= 2 and parts[0] == "160000" and parts[1] != want:
            errors.append(f"submodule pin drift: index records model/sources/car @ {parts[1]}, "
                          f"PIN.yaml says {want}")
    else:
        warnings.append("git index unavailable — submodule pin not cross-checked")
    head = _git("-C", "model/sources/car", "rev-parse", "HEAD")
    if head and head != want:
        errors.append(f"submodule checkout drift: model/sources/car is at {head}, PIN.yaml says {want}")


def validate(car, vocab, schema_objects, schema_actions, reg, tpl, pin) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    check_pins(pin, errors, warnings)

    # --- the object set: pinned CAR == car-vocab == registry ----------------------------------
    car_objs = list(car.keys())
    if sorted(car_objs) != sorted(vocab):
        errors.append(f"object set drift: pinned CAR {sorted(car_objs)} vs car-vocab {sorted(vocab)}")
    reg_objs = [o["name"] for o in reg["objects"]]
    if sorted(reg_objs) != sorted(car_objs):
        errors.append(f"registry objects {sorted(reg_objs)} != pinned CAR objects {sorted(car_objs)}")
    if len(set(reg_objs)) != len(reg_objs):
        errors.append("duplicate object in registry")

    # --- the action vocabulary: car-vocab ⊇ pinned CAR; schema == car-vocab for CAR objects --------
    for o in car_objs:
        pinned = set(car[o]["actions"])
        voc = set(vocab.get(o, []))
        if not pinned <= voc:
            errors.append(f"{o}: pinned CAR actions {sorted(pinned - voc)} missing from car-vocab")
        if o in schema_actions and sorted(schema_actions[o]) != sorted(voc):
            errors.append(f"{o}: car-actions.schema.json enum {sorted(schema_actions[o])} "
                          f"!= car-vocab {sorted(voc)}")
    promoted = {p["name"]: p for p in reg.get("promoted_objects") or []}
    if sorted(schema_objects) != sorted(set(car_objs) | set(promoted)):
        errors.append(f"car-actions.schema.json objects {sorted(schema_objects)} != CAR objects + "
                      f"registry promoted_objects {sorted(set(car_objs) | set(promoted))}")
    for name, p in promoted.items():
        if name in schema_actions and sorted(schema_actions[name]) != sorted(p["actions"]):
            errors.append(f"promoted {name}: registry actions {sorted(p['actions'])} != schema enum "
                          f"{sorted(schema_actions[name])}")

    # --- objects: task / base / keyword ------------------------------------------------------
    width = reg["id_scheme"]["object_range_width"]
    seen_task, seen_base, seen_kw, seen_sym = set(), set(), set(), set()
    all_ranged = list(reg["objects"]) + list(reg.get("promoted_objects") or []) + [
        {"name": f"reserved {r['range']}", "task": r["task"], "base": r["range"][0], "keyword": r["keyword"],
         "keyword_symbol": r["keyword_symbol"]} for r in reg.get("reserved_ranges") or []]
    for o in all_ranged:
        if not TASK_RANGE[0] <= o["task"] <= TASK_RANGE[1]:
            errors.append(f"{o['name']}: task {o['task']} out of range")
        if o["base"] % width or o["task"] != o["base"] // width:
            errors.append(f"{o['name']}: base {o['base']} must be a multiple of {width} with task == base div {width}")
        kw = int(o["keyword"])
        if kw == 0 or kw & (kw - 1):
            errors.append(f"{o['name']}: keyword {kw:#x} must be a single bit")
        elif not KEYWORD_BITS[0] <= kw.bit_length() - 1 <= KEYWORD_BITS[1]:
            errors.append(f"{o['name']}: keyword bit {kw.bit_length() - 1} outside provider-defined bits {KEYWORD_BITS}")
        for key, bag in (("task", seen_task), ("base", seen_base), ("keyword", seen_kw), ("keyword_symbol", seen_sym)):
            if o[key] in bag:
                errors.append(f"{o['name']}: duplicate {key} {o[key]}")
            bag.add(o[key])

    # --- actions: one opcode per action name in the union vocabulary ---------------------------
    union = sorted({a for o in vocab for a in vocab[o]})
    ops = {a["name"]: a for a in reg["actions"]}
    if sorted(ops) != union:
        errors.append(f"registry actions {sorted(set(ops) ^ set(union))} differ from the car-vocab union")
    vals = [a["opcode"] for a in reg["actions"]]
    if len(set(vals)) != len(vals):
        errors.append("duplicate opcode value")
    for a in reg["actions"]:
        if not OPCODE_RANGE[0] <= a["opcode"] <= OPCODE_RANGE[1]:
            errors.append(f"action {a['name']}: opcode {a['opcode']} outside {OPCODE_RANGE}")
    syms = [a["symbol"] for a in reg["actions"]]
    if len(set(syms)) != len(syms):
        errors.append("duplicate opcode symbol")

    # --- events: exactly the car-vocab matrix, numbered inside the object's range ---------------
    lo_car, hi_car = reg["id_scheme"]["offsets"]["car"]
    lo_sup, hi_sup = reg["id_scheme"]["offsets"]["superset"]
    by_obj = {o["name"]: o for o in reg["objects"]}
    ids = [e["id"] for e in reg["events"]]
    if len(set(ids)) != len(ids):
        errors.append(f"duplicate EventID(s): {sorted(i for i in set(ids) if ids.count(i) > 1)}")
    pairs = [(e["object"], e["action"]) for e in reg["events"]]
    if len(set(pairs)) != len(pairs):
        errors.append("duplicate (object, action) in events")
    want_pairs = {(o, a) for o in vocab for a in vocab[o]}
    if set(pairs) != want_pairs:
        errors.append(f"events differ from the car-vocab matrix: missing {sorted(want_pairs - set(pairs))}, "
                      f"extra {sorted(set(pairs) - want_pairs)}")
    for e in reg["events"]:
        o = by_obj.get(e["object"])
        if not o:
            continue
        off = e["id"] - o["base"]
        prov = "car" if e["action"] in car[e["object"]]["actions"] else "superset"
        if e.get("provenance") != prov:
            errors.append(f"event {e['id']} {e['object']}/{e['action']}: provenance says {e.get('provenance')}, "
                          f"the pinned model says {prov}")
        lo, hi = (lo_car, hi_car) if prov == "car" else (lo_sup, hi_sup)
        if not lo <= off <= hi:
            errors.append(f"event {e['id']} {e['object']}/{e['action']} ({prov}): offset {off} outside {lo}–{hi}")
        if e["id"] // width != o["task"]:
            errors.append(f"event {e['id']}: Task {e['id'] // width} != object task {o['task']}")

    # --- templates: types for exactly the pinned fields ---------------------------------------
    rules = tpl["rules"]
    for r, spec in rules.items():
        if not str(spec.get("in", "")).startswith("win:"):
            errors.append(f"rule {r}: `in` must be a win: input type")
    env_names = {f["name"].lower() for f in tpl["envelope"]}
    for f in tpl["envelope"]:
        if f["rule"] not in rules:
            errors.append(f"envelope {f['name']}: unknown rule {f['rule']}")
    if sorted(tpl["objects"]) != sorted(car_objs):
        errors.append(f"templates.yaml objects {sorted(tpl['objects'])} != pinned CAR objects")
    for o in car_objs:
        names = [f["name"] for f in car[o]["fields"]]
        if len(set(names)) != len(names):
            errors.append(f"{o}: duplicate field name in the pinned model")
        for fname, rule in (tpl["objects"].get(o) or {}).items():
            if fname not in names:
                errors.append(f"templates {o}.{fname}: not a field of the pinned model")
            if rule not in rules:
                errors.append(f"templates {o}.{fname}: unknown rule {rule}")
        clash = env_names & {n.lower() for n in names}
        if clash:
            errors.append(f"{o}: envelope/field name clash {sorted(clash)}")
        n = len(tpl["envelope"]) + len(names)
        if n > MAX_EVENT_DATA_DESCRIPTORS:
            errors.append(f"{o}: {n} template data items exceed EventWrite's {MAX_EVENT_DATA_DESCRIPTORS}")
        elif n > MAX_MESSAGE_INSERTS:
            warnings.append(f"{o}: {n} template data items exceed the %1..%{MAX_MESSAGE_INSERTS} message inserts")

    return errors, warnings


# ----------------------------------------------------------------------------- derivation


def derive(car, vocab, reg, tpl, pin, cards, evidences) -> dict:
    rules = tpl["rules"]
    ops = {a["name"]: a for a in reg["actions"]}
    env = []
    for i, f in enumerate(tpl["envelope"], start=1):
        r = rules[f["rule"]]
        env.append({"index": i, "name": f["name"], "rule": f["rule"], "in": r["in"],
                    "out": r.get("out"), "description": f["description"]})

    def card_text(o, a):
        return [f"{c['sensor']}" + (f" (Event {c['event']})" if c["event"] else "") for c in cards.get((o, a), [])]

    def evtx_text(o, a):
        out = []
        for r in evidences.get((o, a), []):
            out.append({"when": str(r.get("when")), "evidence": r.get("evidence"), "time": r.get("time")})
        return out

    objects = []
    events = []
    for ro in reg["objects"]:
        o = ro["name"]
        c = car[o]
        typed = tpl["objects"].get(o) or {}
        fields = []
        for j, f in enumerate(c["fields"], start=len(env) + 1):
            rule = typed.get(f["name"], "string")
            r = rules[rule]
            fields.append({"index": j, "name": f["name"], "rule": rule, "in": r["in"], "out": r.get("out"),
                           "description": f["description"],
                           "example": None if f["example"] is None else str(f["example"])})
        acts = []
        for e in sorted((e for e in reg["events"] if e["object"] == o), key=lambda e: e["id"]):
            a = e["action"]
            row = {"id": e["id"], "action": a, "opcode": ops[a]["opcode"], "opcode_symbol": ops[a]["symbol"],
                   "provenance": e["provenance"],
                   "description": c["action_descriptions"].get(a, "") if e["provenance"] == "car"
                   else "ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object",
                   "sensor_cards": card_text(o, a), "evtx_bindings": evtx_text(o, a)}
            acts.append(row)
            events.append({"id": e["id"], "object": o, "task": ro["task"], "action": a, "opcode": ops[a]["opcode"],
                           "provenance": e["provenance"], "keyword": f"{int(ro['keyword']):#018x}",
                           "symbol": f"{reg['provider']['symbol']}_{o.upper()}_{a.upper()}",
                           "sensor_cards": row["sensor_cards"], "evtx_bindings": row["evtx_bindings"]})
        objects.append({
            "key": o, "name": c["name"], "description": c["description"], "task": ro["task"], "base": ro["base"],
            "range": [ro["base"], ro["base"] + reg["id_scheme"]["object_range_width"] - 1],
            "keyword": f"{int(ro['keyword']):#018x}", "keyword_symbol": ro["keyword_symbol"],
            "template": f"{reg['provider']['symbol']}_T_{o.upper()}",
            "template_data_items": len(env) + len(fields),
            "events": acts, "fields": fields, "source_file": c["source_file"],
        })

    actions = []
    for a in sorted(reg["actions"], key=lambda a: a["opcode"]):
        users = [o["key"] for o in objects if any(e["action"] == a["name"] for e in o["events"])]
        prov = "car" if any(a["name"] in car[o]["actions"] for o in car) else "superset"
        actions.append({"name": a["name"], "opcode": a["opcode"], "symbol": a["symbol"], "provenance": prov,
                        "objects": users})

    return {
        "generated_by": "tools/carmodel.py generate — do not edit by hand",
        "schema_version": reg["schema_version"],
        "pins": {
            "car": {"url": pin["car_submodule"]["url"], "commit": pin["car_submodule"]["commit"],
                    "path": "model/sources/car"},
            "byakugan": {"url": pin["repository"], "commit": pin["commit"], "path": "model/sources/byakugan"},
        },
        "provider": reg["provider"],
        "id_scheme": reg["id_scheme"],
        "limits": {"opcode_range": list(OPCODE_RANGE), "keyword_bits": list(KEYWORD_BITS),
                   "max_message_inserts": MAX_MESSAGE_INSERTS,
                   "max_event_data_descriptors": MAX_EVENT_DATA_DESCRIPTORS},
        "counts": {"objects": len(objects), "fields": sum(len(o["fields"]) for o in objects),
                   "events": len(events), "events_car": sum(e["provenance"] == "car" for e in events),
                   "events_superset": sum(e["provenance"] == "superset" for e in events),
                   "opcodes": len(actions)},
        "envelope": env,
        "rules": rules,
        "actions": actions,
        "objects": objects,
        "events": events,
        "promoted_objects": reg.get("promoted_objects") or [],
        "reserved_ranges": reg.get("reserved_ranges") or [],
    }


# ----------------------------------------------------------------------------- rendering


def _cell(v) -> str:
    if v is None:
        return ""
    s = str(v).replace("\r", " ").replace("\n", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def _code(v) -> str:
    return f"`{v}`" if v not in (None, "") else ""


def _type(f) -> str:
    return _code(f["in"]) + (f" → {_code(f['out'])}" if f.get("out") else "")


def _bindings(e) -> str:
    parts = []
    for b in e["evtx_bindings"]:
        mark = "" if b["evidence"] == "definitive" else " ‡"
        parts.append(_cell(b["when"]) + mark)
    return "; ".join(parts)


def render_markdown(m: dict) -> str:
    L: list[str] = []
    w = L.append
    p = m["provider"]
    c = m["counts"]
    car_pin = m["pins"]["car"]
    byk_pin = m["pins"]["byakugan"]
    w("# CAR Event Log — the EventID table")
    w("")
    w("> **GENERATED** by `python tools/carmodel.py generate` from the pinned model — do not edit by hand; "
      "edit `model/eventids.yaml` / `model/templates.yaml` or bump a pin and regenerate. "
      "`python tools/carmodel.py check` (CI) fails on drift.")
    w(">")
    w(f"> Pins — MITRE CAR data model: [`{car_pin['commit'][:12]}`]({car_pin['url'].removesuffix('.git')}/tree/{car_pin['commit']}) "
      f"(`{car_pin['path']}`, git submodule); Byakugan (schema source): "
      f"[`{byk_pin['commit'][:12]}`]({byk_pin['url']}/tree/{byk_pin['commit']}) (`{byk_pin['path']}/PIN.yaml`).")
    w("")
    w("## 1. At a glance")
    w("")
    w(f"- **{c['objects']} CAR objects**, **{c['fields']} properties**, **{c['events']} (object, action) events**: "
      f"{c['events_car']} defined by the pinned CAR submodule (`car`), {c['events_superset']} added by "
      f"`byakugan car-vocab` from the ATT&CK data-component overlay (`superset`). The three *promoted* objects in "
      f"`car-actions.schema.json` (group, scheduled_job, user_account) have no CAR field set and are **reserved**, not defined — §7.")
    w(f"- **Provider** `{p['name']}` · **channel** `{p['channel']['name']}` (type {p['channel']['type']}) · "
      f"provider GUID `{p['guid']}` — proposed names, see `docs/Decisions.md` §D5.")
    w(f"- **EventID = object base + offset.** Offsets {m['id_scheme']['offsets']['car'][0]}–{m['id_scheme']['offsets']['car'][1]} "
      f"are pinned-CAR actions, {m['id_scheme']['offsets']['superset'][0]}–{m['id_scheme']['offsets']['superset'][1]} are "
      f"superset actions. **Task = EventID div 100** (the object). **Opcode = the action**, one value per action name across "
      f"all objects. **Keyword = one bit per object.** Filter by object (Task or Keyword), by action (Opcode), or slice by ID range.")
    w(f"- **One typed template per object**, reused by all of that object's actions; every template opens with the "
      f"{len(m['envelope'])}-field sensor envelope (§5) followed by the object's complete CAR property set (§6). "
      f"Unobserved fields are written empty — never inferred.")
    w("")
    w("## 2. Objects → Task, ID range, Keyword")
    w("")
    w("| Task | Object | EventIDs | Keyword | Properties | Events (car + superset) | Template | CAR description |")
    w("|---:|---|---|---|---:|---|---|---|")
    for o in m["objects"]:
        ncar = sum(e["provenance"] == "car" for e in o["events"])
        nsup = len(o["events"]) - ncar
        w(f"| {o['task']} | **{o['key']}** | {o['range'][0]}–{o['range'][1]} | `{o['keyword']}` | {len(o['fields'])} | "
          f"{len(o['events'])} ({ncar} + {nsup}) | `{o['template']}` | {_cell(o['description'])} |")
    w("")
    w("## 3. Actions → Opcode")
    w("")
    w("Custom opcodes occupy 10–238 (ETW reserves 0–9). Pinned-CAR action names were assigned alphabetically from 10; "
      "the five names only the superset adds follow.")
    w("")
    w("| Opcode | Action | Provenance | Objects |")
    w("|---:|---|---|---|")
    for a in m["actions"]:
        w(f"| {a['opcode']} | `{a['name']}` | {a['provenance']} | {', '.join(a['objects'])} |")
    w("")
    w("## 4. The EventID table")
    w("")
    w("Every (object, action) pair in the pinned model, numbered. *Sensor cards* = the pinned CAR `sensors/*.yaml` that "
      "claim the pair; *Byakugan evtx bindings* = Windows events Byakugan's reviewed overlay binds to the pair "
      "(‡ = heuristic). Both columns are **coverage evidence from the pinned sources**, not this project's writer map — "
      "that map is deliverable 5.")
    w("")
    w("| EventID | Object | Action | Task | Opcode | Prov. | Symbol | Sensor cards | Byakugan evtx bindings |")
    w("|---:|---|---|---:|---:|---|---|---|---|")
    for e in m["events"]:
        w(f"| **{e['id']}** | {e['object']} | `{e['action']}` | {e['task']} | {e['opcode']} | {e['provenance']} | "
          f"`{e['symbol']}` | {_cell('; '.join(e['sensor_cards']))} | {_bindings(e)} |")
    w("")
    w("## 5. Envelope — the first fields of every template")
    w("")
    w("Sensor-level fields, not CAR properties. Numbered as template data items (`%n` in message strings).")
    w("")
    w("| # | Field | ETW type | Description |")
    w("|---:|---|---|---|")
    for f in m["envelope"]:
        w(f"| {f['index']} | `{f['name']}` | {_type(f)} | {_cell(f['description'])} |")
    w("")
    w("## 6. Templates — one per object, the complete CAR property set")
    w("")
    w("Field names, descriptions and examples are verbatim from the pinned CAR data model. The ETW type is this "
      "project's decision (`model/templates.yaml`): `win:UnicodeString` unless the *Basis* column says otherwise.")
    w("")
    for o in m["objects"]:
        ids = ", ".join(str(e["id"]) for e in o["events"])
        w(f"### 6.{o['task'] - 9} `{o['key']}` — Task {o['task']}, EventIDs {ids}")
        w("")
        w(f"{_cell(o['description'])}")
        w("")
        w(f"Source: `{o['source_file']}` · template `{o['template']}` ({o['template_data_items']} data items incl. envelope) · "
          f"keyword `{o['keyword']}` (`{o['keyword_symbol']}`)")
        w("")
        w("| EventID | Action | Opcode | Prov. | CAR action description |")
        w("|---:|---|---:|---|---|")
        for e in o["events"]:
            w(f"| **{e['id']}** | `{e['action']}` | {e['opcode']} | {e['provenance']} | {_cell(e['description'])} |")
        w("")
        w("| # | Field | ETW type | Basis | CAR description | Example |")
        w("|---:|---|---|---|---|---|")
        for f in o["fields"]:
            basis = "" if f["rule"] == "string" else _cell(m["rules"][f["rule"]]["basis"])
            w(f"| {f['index']} | `{f['name']}` | {_type(f)} | {basis} | {_cell(f['description'])} | {_cell(f['example'])} |")
        w("")
    w("## 7. Reserved — defined by number only")
    w("")
    w("| Task | Range | Keyword | Name | Why reserved |")
    w("|---:|---|---|---|---|")
    for po in m["promoted_objects"]:
        w(f"| {po['task']} | {po['base']}–{po['base'] + 99} | `{int(po['keyword']):#018x}` | **{po['name']}** | "
          f"promoted object in `car-actions.schema.json` with actions {', '.join('`' + a + '`' for a in po['actions'])} "
          f"but **no CAR field set** in the pinned model — no template can be derived without inventing fields |")
    for r in m["reserved_ranges"]:
        w(f"| {r['task']} | {r['range'][0]}–{r['range'][1]} | `{int(r['keyword']):#018x}` | sensor | {_cell(r['purpose'])} |")
    w("")
    w("## 8. What the generator enforces")
    w("")
    w("- the object set is identical in the pinned CAR submodule, `car-vocab.json` and the registry;")
    w("- every (object, action) in `car-vocab` has exactly one EventID and no EventID is outside it; the recorded provenance "
      "matches the pinned submodule; `car` offsets stay in 1–49 and `superset` in 50–99; Task = EventID div 100;")
    w("- `car-actions.schema.json` agrees with `car-vocab` for the 13 CAR objects and adds exactly the registry's promoted objects;")
    w("- one Opcode per action name in 10–238, one single-bit Keyword per object in bits 0–47, all unique;")
    w("- every typed field exists in the pinned model, every rule exists, envelope names never collide with CAR fields, "
      f"and no template exceeds {m['limits']['max_message_inserts']} data items;")
    w("- the submodule checkout and index match `PIN.yaml`; the committed outputs match a fresh generation.")
    w("")
    return "\n".join(L)


def render_json(m: dict) -> str:
    return json.dumps(m, indent=2, ensure_ascii=False) + "\n"


# ----------------------------------------------------------------------------- commands


def build() -> tuple[dict, list[str]]:
    car = load_pinned_car()
    vocab = load_vocab()
    schema_objects, schema_actions = load_schema_vocab()
    reg = load_registry()
    tpl = load_templates()
    pin = load_pin()
    errors, warnings = validate(car, vocab, schema_objects, schema_actions, reg, tpl, pin)
    if errors:
        raise ModelError("model validation failed:\n  - " + "\n  - ".join(errors))
    model = derive(car, vocab, reg, tpl, pin, load_sensor_cards(), load_evtx_evidences())
    return model, warnings


def cmd_generate(_: argparse.Namespace) -> int:
    model, warnings = build()
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(render_json(model), encoding="utf-8")
    OUT_MD.write_text(render_markdown(model), encoding="utf-8")
    for wmsg in warnings:
        print(f"warning: {wmsg}", file=sys.stderr)
    c = model["counts"]
    print(f"generated {OUT_MD.relative_to(ROOT)} and {OUT_JSON.relative_to(ROOT)}: "
          f"{c['objects']} objects, {c['fields']} fields, {c['events']} events "
          f"({c['events_car']} car + {c['events_superset']} superset), {c['opcodes']} opcodes")
    return 0


def cmd_check(_: argparse.Namespace) -> int:
    model, warnings = build()
    for wmsg in warnings:
        print(f"warning: {wmsg}", file=sys.stderr)
    stale = []
    for path, text in ((OUT_JSON, render_json(model)), (OUT_MD, render_markdown(model))):
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            stale.append(str(path.relative_to(ROOT)))
    if stale:
        print("DRIFT: committed outputs differ from a fresh generation: " + ", ".join(stale)
              + "\n       run `python tools/carmodel.py generate` and commit the result", file=sys.stderr)
        return 1
    print("ok: model valid, pins consistent, generated outputs up to date")
    return 0


def cmd_dump(_: argparse.Namespace) -> int:
    model, _w = build()
    sys.stdout.write(render_json(model))
    return 0


def cmd_matrix(_: argparse.Namespace) -> int:
    model, _w = build()
    for o in model["objects"]:
        cells = [f"{e['action']}={e['id']}" + ("" if e["provenance"] == "car" else "*") for e in o["events"]]
        print(f"{o['key']:15s} T{o['task']:<3d} {', '.join(cells)}")
    print("(* = superset action)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate").set_defaults(fn=cmd_generate)
    sub.add_parser("check").set_defaults(fn=cmd_check)
    sub.add_parser("dump").set_defaults(fn=cmd_dump)
    sub.add_parser("matrix").set_defaults(fn=cmd_matrix)
    ns = ap.parse_args(argv)
    try:
        return ns.fn(ns)
    except ModelError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
