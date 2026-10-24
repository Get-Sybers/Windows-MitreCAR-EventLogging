#!/usr/bin/env python3
"""tools/carmodel.py — derive the CAR event-log model from the pinned sources and gate drift.

Inputs, all pinned:

  model/sources/car/                        the MITRE CAR data model (git submodule): objects, actions,
                                            property sets, descriptions, examples, sensor cards
  model/sources/byakugan/car-vocab.json     the canonical car_action vocabulary (`byakugan car-vocab`)
  model/sources/byakugan/car-actions.schema.json
                                            the model/schema vocabulary (adds the promoted objects)
  model/sources/byakugan/attack_data_sources_objects.yaml
                                            the ATT&CK data components the overlay actions derive from
  model/sources/byakugan/matched-evidences.yaml
                                            Byakugan's reviewed Windows-event → (object, action) bindings

Hand-pinned registries, VALIDATED against the inputs, never derived from them:

  model/eventids.yaml                       objects → Task/base/Keyword, actions → Opcode, (object, action) → EventID
  model/templates.yaml                      the value format per CAR field (every field is win:UnicodeString)

Outputs (committed, regenerated, drift-gated):

  docs/EventID-Table.md                     deliverable 1 — the numbered EventID table
  model/generated/car-eventlog-model.json   the same model, machine-readable
  manifest/GetSybersMitreCar.man            the instrumentation manifest (deliverable 2)
  src/GetSybersMitreCar.Writer/CarModel.g.cs the model as C# tables for the writer (deliverable 4)

Usage:
  python tools/carmodel.py generate         validate, then (re)write the outputs
  python tools/carmodel.py check            validate, regenerate in memory, fail if the committed outputs differ
  python tools/carmodel.py dump             validate, print the derived model as JSON
  python tools/carmodel.py matrix           validate, print the object × action matrix
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import OrderedDict
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

import yaml

ROOT = Path(__file__).resolve().parents[1]
CAR_DIR = ROOT / "model" / "sources" / "car"
BYK_DIR = ROOT / "model" / "sources" / "byakugan"
REGISTRY = ROOT / "model" / "eventids.yaml"
TEMPLATES = ROOT / "model" / "templates.yaml"
OUT_JSON = ROOT / "model" / "generated" / "car-eventlog-model.json"
OUT_MD = ROOT / "docs" / "EventID-Table.md"
OUT_MAN = ROOT / "manifest" / "GetSybersMitreCar.man"
OUT_CS = ROOT / "src" / "GetSybersMitreCar.Writer" / "CarModel.g.cs"

# mc.exe gives the first custom channel this keyword bit and ORs it into every event descriptor that
# targets the channel; the writer must set it too or the Event Log session filters the event out.
# Test-Channel.ps1 asserts this value against the header mc.exe generated.
CHANNEL_KEYWORD = 0x8000000000000000

# Limits of the manifest toolchain, read from the MicrosoftDocs repositories (mc.exe is the final
# authority at build time). Paths are relative to the repository named; commits are the `docs`
# branch heads the pages were read at (2026-10-24).
LIMITS = {
    "opcode_range": (10, 239),
    "task_range": (1, 239),
    "keyword_bits": (0, 47),
    "max_message_inserts": 100,
    "max_event_data_descriptors": 128,
    "max_event_bytes": 65536,
    "channel_name_max_chars": 255,
}
LIMIT_SOURCES = [
    {"fact": "custom opcode values 10–239", "repo": "MicrosoftDocs/win32", "commit": "ca8274decead49403d70ceeed4af8d4ca74eaf11",
     "path": "desktop-src/WES/eventmanifestschema-opcodetype-complextype.md"},
    {"fact": "task values 1–239", "repo": "MicrosoftDocs/win32", "commit": "ca8274decead49403d70ceeed4af8d4ca74eaf11",
     "path": "desktop-src/WES/eventmanifestschema-tasktype-complextype.md"},
    {"fact": "keyword mask: a single bit, bits 0–47", "repo": "MicrosoftDocs/win32", "commit": "ca8274decead49403d70ceeed4af8d4ca74eaf11",
     "path": "desktop-src/WES/eventmanifestschema-keywordtype-complextype.md"},
    {"fact": "event message: at most 100 insertion strings", "repo": "MicrosoftDocs/win32", "commit": "ca8274decead49403d70ceeed4af8d4ca74eaf11",
     "path": "desktop-src/WES/eventmanifestschema-eventdefinitiontype-complextype.md"},
    {"fact": "channel name < 255 characters, no > < & \" | \\ : ` ? * or control characters; Operational channels share one ETW session",
     "repo": "MicrosoftDocs/win32", "commit": "ca8274decead49403d70ceeed4af8d4ca74eaf11",
     "path": "desktop-src/WES/eventmanifestschema-channeltype-complextype.md"},
    {"fact": "win:UnicodeString renders as xs:string, win:Xml or win:Json", "repo": "MicrosoftDocs/win32", "commit": "ca8274decead49403d70ceeed4af8d4ca74eaf11",
     "path": "desktop-src/WES/eventmanifestschema-inputtype-complextype.md"},
    {"fact": "EventWrite: at most 128 data descriptors; an event larger than 64 KB minus header fails", "repo": "MicrosoftDocs/sdk-api",
     "commit": "656e9656bfaef34dd29cd7ee9e1146aec17e924c", "path": "sdk-api-src/content/evntprov/nf-evntprov-eventwrite.md"},
]

ETW_TYPE = "win:UnicodeString"


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


# --- the ATT&CK overlay: Byakugan's derivation, ported verbatim ---------------------------------
# byakugan/build_data_model.py — ATT&CK data-source name -> object key (overlaps fold onto CAR).
_ATTACK_OVERLAP = {
    "file": "file", "process": "process", "driver": "driver", "module": "module",
    "service": "service", "windows registry": "registry",
    "network traffic": "flow", "logon session": "user_session",
}


def _attack_key(att_name: str) -> str:
    low = att_name.strip().lower()
    if low in _ATTACK_OVERLAP:
        return _ATTACK_OVERLAP[low]
    return re.sub(r"[^a-z0-9]+", "_", low).strip("_")


def _attack_action_for(component_name: str, object_name: str) -> str:
    """byakugan/build_data_model.py _action_for: component name (minus the object prefix) -> verb."""
    s = component_name.lower()
    op = object_name.lower()
    if s.startswith(op):
        s = s[len(op):].strip()
    checks = [
        ("creat", "create"), ("deletion", "delete"), ("delet", "delete"),
        ("terminat", "terminate"), ("modif", "modify"), ("authenticat", "authenticate"),
        ("enumerat", "enumerate"), ("execut", "execute"), ("metadata", "metadata"),
        ("access", "access"), ("connect", "connect"), ("load", "load"),
        ("start", "start"), ("stop", "stop"), ("bind", "bind"), ("listen", "listen"),
        ("lock", "lock"), ("enable", "enable"), ("disable", "disable"),
        ("power", "power_state"), ("deploy", "deploy"),
    ]
    for kw, verb in checks:
        if kw in s:
            return verb
    return re.sub(r"[^a-z0-9]+", "_", s).strip("_") or "activity"


def load_attack() -> dict:
    """{object_key: {data_source, definition, components: {action: [{name, type, description}]}}}."""
    ads = _yaml(BYK_DIR / "attack_data_sources_objects.yaml")
    out: dict = {}
    for a in ads:
        k = _attack_key(a["name"])
        comps: dict = {}
        for c in a.get("data_components") or []:
            act = _attack_action_for(c["name"], a["name"])
            comps.setdefault(act, []).append({
                "name": c["name"], "type": c.get("type"),
                "description": (c.get("description") or "").strip(),
            })
        out[k] = {"data_source": a["name"], "definition": (a.get("definition") or "").strip(),
                  "components": comps}
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


_BAD_NAME_CHARS = re.compile(r'[><&"|\\:`?*\x00-\x1f]')


def validate(car, vocab, schema_objects, schema_actions, attack, reg, tpl, pin) -> tuple[list[str], list[str]]:
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

    # --- the action vocabulary: car-vocab == pinned CAR ∪ ATT&CK overlay; schema == car-vocab -----
    for o in car_objs:
        pinned = set(car[o]["actions"])
        voc = set(vocab.get(o, []))
        if not pinned <= voc:
            errors.append(f"{o}: pinned CAR actions {sorted(pinned - voc)} missing from car-vocab")
        derived = set((attack.get(o) or {}).get("components", {}))
        if pinned | derived != voc:
            errors.append(f"{o}: pinned CAR ∪ ATT&CK-derived actions {sorted(pinned | derived)} != car-vocab "
                          f"{sorted(voc)} — the overlay derivation no longer reproduces the vocabulary")
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

    # --- provider / channel ---------------------------------------------------------------------
    prov = reg["provider"]
    for label, val in (("provider name", prov["name"]), ("channel name", prov["channel"]["name"])):
        if len(val) >= LIMITS["channel_name_max_chars"] or _BAD_NAME_CHARS.search(val.replace("/", "")):
            errors.append(f"{label} {val!r} violates the manifest naming rules")
    if not prov["channel"]["name"].startswith(prov["name"] + "/"):
        warnings.append("channel name does not follow the <provider>/<type> convention")
    if not re.fullmatch(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", str(prov["guid"])):
        errors.append(f"provider guid {prov['guid']!r} is not a GUID")

    # --- objects: task / base / keyword ------------------------------------------------------
    width = reg["id_scheme"]["object_range_width"]
    tlo, thi = reg["id_scheme"]["task_range"]
    klo, khi = reg["id_scheme"]["keyword_bits"]
    if (tlo, thi) != LIMITS["task_range"] or (klo, khi) != LIMITS["keyword_bits"]:
        errors.append("id_scheme task_range/keyword_bits disagree with the documented limits")
    seen_task, seen_base, seen_kw, seen_sym = set(), set(), set(), set()
    all_ranged = list(reg["objects"]) + list(reg.get("promoted_objects") or []) + [
        {"name": f"reserved {r['range']}", "task": r["task"], "base": r["range"][0], "keyword": r["keyword"],
         "keyword_symbol": r["keyword_symbol"]} for r in reg.get("reserved_ranges") or []]
    for o in all_ranged:
        if not tlo <= o["task"] <= thi:
            errors.append(f"{o['name']}: task {o['task']} outside {tlo}–{thi}")
        if o["base"] % width:
            errors.append(f"{o['name']}: base {o['base']} must be a multiple of {width}")
        kw = int(o["keyword"])
        if kw == 0 or kw & (kw - 1):
            errors.append(f"{o['name']}: keyword {kw:#x} must be a single bit")
        elif not klo <= kw.bit_length() - 1 <= khi:
            errors.append(f"{o['name']}: keyword bit {kw.bit_length() - 1} outside provider-defined bits {klo}–{khi}")
        for key, bag in (("task", seen_task), ("base", seen_base), ("keyword", seen_kw), ("keyword_symbol", seen_sym)):
            if o[key] in bag:
                errors.append(f"{o['name']}: duplicate {key} {o[key]}")
            bag.add(o[key])
    for i, o in enumerate(reg["objects"], start=1):
        if o["task"] != i:
            errors.append(f"{o['name']}: task {o['task']} is not its ordinal {i} (numbering rule)")
        if o["base"] != 900 + width * i:
            errors.append(f"{o['name']}: base {o['base']} is not {900 + width * i} (numbering rule)")
        if int(o["keyword"]) != 1 << (i - 1):
            errors.append(f"{o['name']}: keyword is not bit {i - 1} (numbering rule)")

    # --- actions: one opcode per action name in the union vocabulary ---------------------------
    olo, ohi = reg["id_scheme"]["opcode_range"]
    if (olo, ohi) != LIMITS["opcode_range"]:
        errors.append("id_scheme opcode_range disagrees with the documented limits")
    union = sorted({a for o in vocab for a in vocab[o]})
    ops = {a["name"]: a for a in reg["actions"]}
    if sorted(ops) != union:
        errors.append(f"registry actions {sorted(set(ops) ^ set(union))} differ from the car-vocab union")
    vals = [a["opcode"] for a in reg["actions"]]
    if len(set(vals)) != len(vals):
        errors.append("duplicate opcode value")
    for a in reg["actions"]:
        if not olo <= a["opcode"] <= ohi:
            errors.append(f"action {a['name']}: opcode {a['opcode']} outside {olo}–{ohi}")
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
        if not o or e["object"] not in car:
            continue
        off = e["id"] - o["base"]
        prov_kind = "car" if e["action"] in car[e["object"]]["actions"] else "superset"
        if e.get("provenance") != prov_kind:
            errors.append(f"event {e['id']} {e['object']}/{e['action']}: provenance says {e.get('provenance')}, "
                          f"the pinned model says {prov_kind}")
        lo, hi = (lo_car, hi_car) if prov_kind == "car" else (lo_sup, hi_sup)
        if not lo <= off <= hi:
            errors.append(f"event {e['id']} {e['object']}/{e['action']} ({prov_kind}): offset {off} outside {lo}–{hi}")

    # --- templates: a format for exactly the pinned fields -------------------------------------
    if tpl.get("type") != ETW_TYPE:
        errors.append(f"templates.yaml type must be {ETW_TYPE}")
    formats = tpl["formats"]
    if "text" not in formats:
        errors.append("templates.yaml must define the default format `text`")
    for f, spec in formats.items():
        if spec.get("pattern"):
            try:
                re.compile(spec["pattern"])
            except re.error as exc:
                errors.append(f"format {f}: bad pattern ({exc})")
    if sorted(tpl["objects"]) != sorted(car_objs):
        errors.append(f"templates.yaml objects {sorted(tpl['objects'])} != pinned CAR objects")
    for o in car_objs:
        names = [f["name"] for f in car[o]["fields"]]
        if len(set(names)) != len(names):
            errors.append(f"{o}: duplicate field name in the pinned model")
        for fname, fmt in (tpl["objects"].get(o) or {}).items():
            if fname not in names:
                errors.append(f"templates {o}.{fname}: not a field of the pinned model")
            if fmt not in formats:
                errors.append(f"templates {o}.{fname}: unknown format {fmt}")
            if fmt == "text":
                warnings.append(f"templates {o}.{fname}: `text` is the default and need not be listed")
        n = len(names)
        if n > LIMITS["max_message_inserts"]:
            errors.append(f"{o}: {n} data items exceed the {LIMITS['max_message_inserts']} message insertion strings")
        if n > LIMITS["max_event_data_descriptors"]:
            errors.append(f"{o}: {n} data items exceed EventWrite's {LIMITS['max_event_data_descriptors']}")

    return errors, warnings


# ----------------------------------------------------------------------------- derivation


def derive(car, vocab, attack, reg, tpl, pin, cards, evidences) -> dict:
    formats = tpl["formats"]
    ops = {a["name"]: a for a in reg["actions"]}
    prov = reg["provider"]

    def card_text(o, a):
        return [f"{c['sensor']}" + (f" (Event {c['event']})" if c["event"] else "") for c in cards.get((o, a), [])]

    def evtx_text(o, a):
        return [{"when": str(r.get("when")), "evidence": r.get("evidence"), "time": r.get("time")}
                for r in evidences.get((o, a), [])]

    objects = []
    events = []
    for ro in reg["objects"]:
        o = ro["name"]
        c = car[o]
        att = attack.get(o) or {}
        fmts = tpl["objects"].get(o) or {}
        fields = []
        for j, f in enumerate(c["fields"], start=1):
            fmt = fmts.get(f["name"], "text")
            fields.append({"index": j, "name": f["name"], "type": ETW_TYPE, "format": fmt,
                           "pattern": formats[fmt].get("pattern"), "basis": formats[fmt]["basis"],
                           "description": f["description"],
                           "example": None if f["example"] is None else str(f["example"])})
        acts = []
        for e in sorted((e for e in reg["events"] if e["object"] == o), key=lambda e: e["id"]):
            a = e["action"]
            comps = (att.get("components") or {}).get(a, [])
            if e["provenance"] == "car":
                definition = c["action_descriptions"].get(a, "")
            else:
                definition = " / ".join(f"ATT&CK data component “{cp['name']}”: {cp['description']}" for cp in comps)
            row = {"id": e["id"], "action": a, "opcode": ops[a]["opcode"], "opcode_symbol": ops[a]["symbol"],
                   "provenance": e["provenance"],
                   "symbol": f"{prov['symbol']}_{o.upper()}_{a.upper()}",
                   "definition": definition,
                   "attack_components": comps,
                   "sensor_cards": card_text(o, a), "evtx_bindings": evtx_text(o, a)}
            acts.append(row)
            events.append({"id": e["id"], "object": o, "task": ro["task"], "action": a, "opcode": ops[a]["opcode"],
                           "provenance": e["provenance"], "keyword": f"{int(ro['keyword']):#018x}",
                           "symbol": row["symbol"], "template": f"{prov['symbol']}_T_{o.upper()}",
                           "definition": definition, "attack_components": comps,
                           "sensor_cards": row["sensor_cards"], "evtx_bindings": row["evtx_bindings"]})
        objects.append({
            "key": o, "name": c["name"], "description": c["description"], "task": ro["task"], "base": ro["base"],
            "range": [ro["base"], ro["base"] + reg["id_scheme"]["object_range_width"] - 1],
            "keyword": f"{int(ro['keyword']):#018x}", "keyword_symbol": ro["keyword_symbol"],
            "task_symbol": f"{prov['symbol']}_TASK_{o.upper()}",
            "template": f"{prov['symbol']}_T_{o.upper()}",
            "data_items": len(fields),
            "attack_data_source": att.get("data_source"),
            "attack_definition": att.get("definition"),
            "events": acts, "fields": fields, "source_file": c["source_file"],
        })

    actions = []
    for a in sorted(reg["actions"], key=lambda a: a["opcode"]):
        users = [o["key"] for o in objects if any(e["action"] == a["name"] for e in o["events"])]
        kind = "car" if any(a["name"] in car[o]["actions"] for o in car) else "superset"
        actions.append({"name": a["name"], "opcode": a["opcode"], "symbol": a["symbol"], "provenance": kind,
                        "objects": users})

    return {
        "generated_by": "tools/carmodel.py generate — do not edit by hand",
        "schema_version": reg["schema_version"],
        "pins": {
            "car": {"url": pin["car_submodule"]["url"], "commit": pin["car_submodule"]["commit"],
                    "path": "model/sources/car"},
            "byakugan": {"url": pin["repository"], "commit": pin["commit"], "path": "model/sources/byakugan"},
        },
        "provider": prov,
        "manifest": {"path": str(OUT_MAN.relative_to(ROOT)).replace("\\", "/"),
                     "resource_dll": prov["resource_dll"],
                     "install_dir": "%ProgramFiles%\\Get-Sybers\\MitreCAR"},
        "id_scheme": reg["id_scheme"],
        "limits": {k: (list(v) if isinstance(v, tuple) else v) for k, v in LIMITS.items()},
        "limit_sources": LIMIT_SOURCES,
        "type": ETW_TYPE,
        "channel_keyword": f"{CHANNEL_KEYWORD:#018x}",
        "formats": formats,
        "counts": {"objects": len(objects), "fields": sum(len(o["fields"]) for o in objects),
                   "events": len(events), "events_car": sum(e["provenance"] == "car" for e in events),
                   "events_superset": sum(e["provenance"] == "superset" for e in events),
                   "opcodes": len(actions)},
        "actions": actions,
        "objects": objects,
        "events": events,
        "promoted_objects": reg.get("promoted_objects") or [],
        "reserved_ranges": reg.get("reserved_ranges") or [],
    }


# ----------------------------------------------------------------------------- rendering: markdown


def _cell(v) -> str:
    if v is None:
        return ""
    s = str(v).replace("\r", " ").replace("\n", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def _bindings(e) -> str:
    parts = []
    for b in e["evtx_bindings"]:
        mark = "" if b["evidence"] == "definitive" else " ‡"
        parts.append(_cell(b["when"]) + mark)
    return "; ".join(parts)


def _definition(e) -> str:
    if e["provenance"] == "car":
        extra = ""
        if e["attack_components"]:
            extra = " *(also ATT&CK: " + ", ".join(f"“{c['name']}”" for c in e["attack_components"]) + ")*"
        return _cell(e["definition"]) + extra
    return _cell(e["definition"])


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
      f"`byakugan car-vocab` from the ATT&CK data-component overlay (`superset`) — each overlay action is shown with the "
      f"ATT&CK data component it derives from. The three *promoted* objects in `car-actions.schema.json` "
      f"(group, scheduled_job, user_account) have no CAR field set and are **reserved**, not defined — §6.")
    w(f"- **An event is the CAR object (Task), the action (Opcode) and the object's complete property set** — nothing else. "
      f"Observed time and host are the event's own `TimeCreated` and `Computer`, plus the CAR `fqdn`/`hostname` "
      f"properties where the model has them.")
    w(f"- **Every property is `{m['type']}`** with a declared value **format** (§5): the brief requires *empty = not observed*, "
      f"which only a string can express (an ETW integer, boolean or FILETIME cannot be empty, and the model itself uses the "
      f"empty state — `file.signature_valid`: *empty if file is not signed*).")
    w(f"- **Numbering follows the pinned sources' own order** (`model/eventids.yaml` header): EventID = object base + offset, "
      f"offsets {m['id_scheme']['offsets']['car'][0]}–{m['id_scheme']['offsets']['car'][1]} for pinned-CAR actions and "
      f"{m['id_scheme']['offsets']['superset'][0]}–{m['id_scheme']['offsets']['superset'][1]} for overlay actions, both in "
      f"car-vocab (alphabetical) order; **Task** = the object's ordinal; **Opcode** = the action, one value per name across "
      f"all objects; **Keyword** = one bit per object. Filter by object (Task or Keyword), by action (Opcode), or slice by ID range.")
    w(f"- **Provider** `{p['name']}` · **channel** `{p['channel']['name']}` (type {p['channel']['type']}) · "
      f"provider GUID `{p['guid']}` · manifest `{m['manifest']['path']}` → `{m['manifest']['resource_dll']}`.")
    w("")
    w("## 2. Objects → Task, ID range, Keyword")
    w("")
    w("| Task | Object | EventIDs | Keyword | Properties | Events (car + superset) | Template | ATT&CK data source | CAR description |")
    w("|---:|---|---|---|---:|---|---|---|---|")
    for o in m["objects"]:
        ncar = sum(e["provenance"] == "car" for e in o["events"])
        nsup = len(o["events"]) - ncar
        w(f"| {o['task']} | **{o['key']}** | {o['range'][0]}–{o['range'][1]} | `{o['keyword']}` | {len(o['fields'])} | "
          f"{len(o['events'])} ({ncar} + {nsup}) | `{o['template']}` | {_cell(o['attack_data_source']) or '—'} | {_cell(o['description'])} |")
    w("")
    w("## 3. Actions → Opcode")
    w("")
    w(f"Custom opcodes occupy {m['limits']['opcode_range'][0]}–{m['limits']['opcode_range'][1]} (ETW reserves 0–9). "
      "Pinned-CAR action names are alphabetical from 10; the five names only the overlay adds follow.")
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
      "that map is deliverable 5. Definitions per action are in §5.")
    w("")
    w("| EventID | Object | Action | Task | Opcode | Prov. | Symbol | Sensor cards | Byakugan evtx bindings |")
    w("|---:|---|---|---:|---:|---|---|---|---|")
    for e in m["events"]:
        w(f"| **{e['id']}** | {e['object']} | `{e['action']}` | {e['task']} | {e['opcode']} | {e['provenance']} | "
          f"`{e['symbol']}` | {_cell('; '.join(e['sensor_cards']))} | {_bindings(e)} |")
    w("")
    w("## 5. Templates — one per object, the complete CAR property set")
    w("")
    w(f"Field names, descriptions and examples are verbatim from the pinned CAR data model. Every data item is "
      f"`{m['type']}`; an empty string means *not observed*. The **Format** column is this project's decision "
      f"(`model/templates.yaml`), fixed by the CAR description or example:")
    w("")
    w("| Format | Rule | Basis |")
    w("|---|---|---|")
    for name, spec in m["formats"].items():
        w(f"| `{name}` | {_code(spec.get('pattern')) or 'free text'} | {_cell(spec['basis'])} |")
    w("")
    for i, o in enumerate(m["objects"], start=1):
        ids = ", ".join(str(e["id"]) for e in o["events"])
        w(f"### 5.{i} `{o['key']}` — Task {o['task']}, EventIDs {ids}")
        w("")
        w(f"{_cell(o['description'])}")
        if o["attack_data_source"]:
            w("")
            w(f"ATT&CK data source *{_cell(o['attack_data_source'])}*: {_cell(o['attack_definition'])}")
        w("")
        w(f"Source: `{o['source_file']}` · template `{o['template']}` ({o['data_items']} data items) · "
          f"keyword `{o['keyword']}` (`{o['keyword_symbol']}`)")
        w("")
        w("| EventID | Action | Opcode | Prov. | Definition |")
        w("|---:|---|---:|---|---|")
        for e in o["events"]:
            w(f"| **{e['id']}** | `{e['action']}` | {e['opcode']} | {e['provenance']} | {_definition(e)} |")
        w("")
        w("| # | Field | Format | CAR description | Example |")
        w("|---:|---|---|---|---|")
        for f in o["fields"]:
            w(f"| {f['index']} | `{f['name']}` | `{f['format']}` | {_cell(f['description'])} | {_cell(f['example'])} |")
        w("")
    w("## 6. Reserved — defined by number only")
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
    w("## 7. The manifest")
    w("")
    w(f"`{m['manifest']['path']}` is generated from this model: the provider, one Operational channel, "
      f"{c['objects']} tasks, {c['opcodes']} opcodes, {c['objects']} keywords, {c['objects']} templates and {c['events']} events, "
      f"with an en-US string table whose event messages list every property (`field: %n`). It compiles with `mc.exe` into a "
      f"code-free resource DLL (`{m['manifest']['resource_dll']}`) that `wevtutil im` registers — see `scripts/`.")
    w("")
    w("## 8. What the generator enforces, and where the limits come from")
    w("")
    w("- the object set is identical in the pinned CAR submodule, `car-vocab.json` and the registry;")
    w("- for every object, pinned CAR actions ∪ ATT&CK-derived actions (Byakugan's `_action_for`, ported verbatim) "
      "== `car-vocab` — so every overlay action is traceable to a named data component;")
    w("- every (object, action) in `car-vocab` has exactly one EventID and no EventID is outside it; the recorded provenance "
      "matches the pinned submodule; `car` offsets stay in 1–49 and `superset` in 50–99; Task, base and Keyword follow the "
      "object's ordinal;")
    w("- `car-actions.schema.json` agrees with `car-vocab` for the 13 CAR objects and adds exactly the registry's promoted objects;")
    w("- one Opcode per action name, one single-bit Keyword per object, provider/channel names legal, all symbols unique;")
    w("- every formatted field exists in the pinned model and every format exists; no template exceeds the insertion-string "
      "or data-descriptor limits;")
    w("- the submodule checkout and index match `PIN.yaml`; the committed outputs match a fresh generation.")
    w("")
    w("Limits, read from the MicrosoftDocs repositories (the `docs` branch heads on 2026-10-24):")
    w("")
    w("| Fact | Source |")
    w("|---|---|")
    for s in m["limit_sources"]:
        w(f"| {_cell(s['fact'])} | [`{s['repo']}` `{s['path']}`](https://github.com/{s['repo']}/blob/{s['commit']}/{s['path']}) |")
    w("")
    return "\n".join(L)


def _code(v) -> str:
    return f"`{v}`" if v not in (None, "") else ""


# ----------------------------------------------------------------------------- rendering: manifest


def render_manifest(m: dict) -> str:
    p = m["provider"]
    ch = p["channel"]
    dll = f"{m['manifest']['install_dir']}\\{m['manifest']['resource_dll']}"
    L: list[str] = []
    w = L.append
    w('<?xml version="1.0" encoding="UTF-8"?>')
    w("<!--")
    w("  GENERATED by `python tools/carmodel.py generate` from the pinned MITRE CAR data model - do not edit by hand.")
    w(f"  CAR @ {m['pins']['car']['commit']} ; Byakugan @ {m['pins']['byakugan']['commit']}")
    w(f"  {m['counts']['objects']} objects (tasks, keywords, templates), {m['counts']['opcodes']} opcodes, "
      f"{m['counts']['events']} events. Every data item is {m['type']}; empty = not observed.")
    w("  Build: scripts/Build-Manifest.ps1 (mc.exe -> rc.exe -> link.exe /noentry) ; install: scripts/Install-Provider.ps1 (wevtutil im).")
    w("-->")
    w('<instrumentationManifest')
    w('    xmlns="http://schemas.microsoft.com/win/2004/08/events"')
    w('    xmlns:win="http://manifests.microsoft.com/win/2004/08/windows/events"')
    w('    xmlns:xs="http://www.w3.org/2001/XMLSchema"')
    w('    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"')
    w('    xsi:schemaLocation="http://schemas.microsoft.com/win/2004/08/events eventman.xsd">')
    w("  <instrumentation>")
    w("    <events>")
    w(f"      <provider name={quoteattr(p['name'])} guid={quoteattr('{' + p['guid'] + '}')} symbol={quoteattr(p['symbol'])}")
    w(f"                resourceFileName={quoteattr(dll)} messageFileName={quoteattr(dll)}")
    w('                message="$(string.provider)">')
    w("        <channels>")
    w(f"          <channel name={quoteattr(ch['name'])} chid={quoteattr(ch['chid'])} symbol={quoteattr(ch['chid'])}")
    w(f"                   type={quoteattr(ch['type'])} enabled=\"true\" value=\"{ch['value']}\" message=\"$(string.channel)\">")
    w(f"            <logging><maxSize>{ch['max_size_bytes']}</maxSize></logging>")
    w("          </channel>")
    w("        </channels>")
    w("        <tasks>")
    for o in m["objects"]:
        w(f"          <task name={quoteattr(o['key'])} symbol={quoteattr(o['task_symbol'])} value=\"{o['task']}\" "
          f"message=\"$(string.task.{o['key']})\"/>")
    w("        </tasks>")
    w("        <opcodes>")
    for a in m["actions"]:
        w(f"          <opcode name={quoteattr(a['name'])} symbol={quoteattr(a['symbol'])} value=\"{a['opcode']}\" "
          f"message=\"$(string.opcode.{a['name']})\"/>")
    w("        </opcodes>")
    w("        <keywords>")
    for o in m["objects"]:
        w(f"          <keyword name={quoteattr(o['key'])} symbol={quoteattr(o['keyword_symbol'])} mask=\"{o['keyword']}\" "
          f"message=\"$(string.keyword.{o['key']})\"/>")
    w("        </keywords>")
    w("        <templates>")
    for o in m["objects"]:
        w(f"          <template tid={quoteattr(o['template'])}>")
        for f in o["fields"]:
            w(f"            <data name={quoteattr(f['name'])} inType=\"{f['type']}\" outType=\"xs:string\"/>")
        w("          </template>")
    w("        </templates>")
    w("        <events>")
    for e in m["events"]:
        w(f"          <event value=\"{e['id']}\" version=\"0\" symbol={quoteattr(e['symbol'])} channel={quoteattr(ch['chid'])}")
        w(f"                 level=\"win:Informational\" task={quoteattr(e['object'])} opcode={quoteattr(e['action'])} "
          f"keywords={quoteattr(e['object'])} template={quoteattr(e['template'])} message=\"$(string.event.{e['id']})\"/>")
    w("        </events>")
    w("      </provider>")
    w("    </events>")
    w("  </instrumentation>")
    w("  <localization>")
    w('    <resources culture="en-US">')
    w("      <stringTable>")
    w(f"        <string id=\"provider\" value={quoteattr(p['name'])}/>")
    w(f"        <string id=\"channel\" value={quoteattr(ch['type'])}/>")
    for o in m["objects"]:
        w(f"        <string id=\"task.{o['key']}\" value={quoteattr(o['key'])}/>")
    for a in m["actions"]:
        w(f"        <string id=\"opcode.{a['name']}\" value={quoteattr(a['name'])}/>")
    for o in m["objects"]:
        w(f"        <string id=\"keyword.{o['key']}\" value={quoteattr(o['key'])}/>")
    by_obj = {o["key"]: o for o in m["objects"]}
    for e in m["events"]:
        o = by_obj[e["object"]]
        msg = f"MITRE CAR {e['object']}/{e['action']}" + "".join(f"%n{f['name']}: %{f['index']}" for f in o["fields"])
        w(f"        <string id=\"event.{e['id']}\" value={quoteattr(msg)}/>")
    w("      </stringTable>")
    w("    </resources>")
    w("  </localization>")
    w("</instrumentationManifest>")
    return "\n".join(L) + "\n"


def check_manifest(xml_text: str, m: dict, errors: list[str]) -> None:
    """Structural self-check of the rendered manifest (mc.exe is the authority on Windows)."""
    try:
        root = ET.fromstring(xml_text.encode("utf-8"))
    except ET.ParseError as exc:
        errors.append(f"manifest is not well-formed XML: {exc}")
        return
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events"}
    events = root.findall(".//e:provider/e:events/e:event", ns)
    templates = {t.get("tid"): t for t in root.findall(".//e:provider/e:templates/e:template", ns)}
    strings = {s.get("id") for s in root.findall(".//e:stringTable/e:string", ns)}
    if len(events) != m["counts"]["events"]:
        errors.append(f"manifest has {len(events)} events, model has {m['counts']['events']}")
    seen = set()
    for ev in events:
        v = int(ev.get("value"))
        if v in seen:
            errors.append(f"manifest: duplicate event value {v}")
        seen.add(v)
        tid = ev.get("template")
        if tid not in templates:
            errors.append(f"manifest: event {v} references unknown template {tid}")
        ref = ev.get("message")
        sid = ref[len("$(string."):-1] if ref and ref.startswith("$(string.") else None
        if sid not in strings:
            errors.append(f"manifest: event {v} message {ref} has no string")
    for tid, t in templates.items():
        n = len(t.findall("e:data", ns))
        if n > LIMITS["max_message_inserts"]:
            errors.append(f"manifest: template {tid} has {n} data items (> {LIMITS['max_message_inserts']} inserts)")
        for d in t.findall("e:data", ns):
            if d.get("inType") != ETW_TYPE:
                errors.append(f"manifest: template {tid} data {d.get('name')} is {d.get('inType')}, not {ETW_TYPE}")


# ----------------------------------------------------------------------------- rendering: C#


def _cs(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_csharp(m: dict) -> str:
    p = m["provider"]
    L: list[str] = []
    w = L.append
    w("// <auto-generated>")
    w("//   GENERATED by `python tools/carmodel.py generate` from the pinned MITRE CAR data model - do not edit by hand.")
    w(f"//   CAR @ {m['pins']['car']['commit']} ; Byakugan @ {m['pins']['byakugan']['commit']}")
    w(f"//   {m['counts']['objects']} objects, {m['counts']['fields']} properties, {m['counts']['events']} events.")
    w("// </auto-generated>")
    w("using System;")
    w("using System.Collections.Generic;")
    w("")
    w("namespace GetSybersMitreCar.Writer")
    w("{")
    w("    /// <summary>One CAR object: its Task, Keyword and the ordered property set its template carries.</summary>")
    w("    public sealed class CarObject")
    w("    {")
    w("        public readonly string Name; public readonly int Task; public readonly ulong Keyword; public readonly string[] Fields;")
    w("        public CarObject(string name, int task, ulong keyword, string[] fields) { Name = name; Task = task; Keyword = keyword; Fields = fields; }")
    w("    }")
    w("")
    w("    /// <summary>One (object, action) event: the EventID and the descriptor values the manifest gives it.</summary>")
    w("    public sealed class CarEvent")
    w("    {")
    w("        public readonly int Id; public readonly string Object; public readonly string Action; public readonly int Task; public readonly int Opcode; public readonly ulong Keyword; public readonly string Symbol;")
    w("        public CarEvent(int id, string obj, string action, int task, int opcode, ulong keyword, string symbol) { Id = id; Object = obj; Action = action; Task = task; Opcode = opcode; Keyword = keyword; Symbol = symbol; }")
    w("    }")
    w("")
    w("    /// <summary>The CAR event-log model, as the manifest declares it.</summary>")
    w("    public static class CarModel")
    w("    {")
    w(f"        public const string ProviderName = {_cs(p['name'])};")
    w(f"        public static readonly Guid ProviderGuid = new Guid({_cs(p['guid'])});")
    w(f"        public const string ChannelName = {_cs(p['channel']['name'])};")
    w(f"        public const byte ChannelValue = {p['channel']['value']};")
    w(f"        public const byte Level = 4; // win:Informational")
    w(f"        public const ulong ChannelKeyword = 0x{CHANNEL_KEYWORD:016X}UL;")
    w("")
    w("        public static readonly CarObject[] Objects =")
    w("        {")
    for o in m["objects"]:
        fields = ", ".join(_cs(f["name"]) for f in o["fields"])
        w(f"            new CarObject({_cs(o['key'])}, {o['task']}, 0x{int(o['keyword'], 16):016X}UL, new[] {{ {fields} }}),")
    w("        };")
    w("")
    w("        public static readonly CarEvent[] Events =")
    w("        {")
    for e in m["events"]:
        w(f"            new CarEvent({e['id']}, {_cs(e['object'])}, {_cs(e['action'])}, {e['task']}, {e['opcode']}, "
          f"0x{int(e['keyword'], 16):016X}UL, {_cs(e['symbol'])}),")
    w("        };")
    w("")
    w("        private static readonly Dictionary<string, CarObject> _objects = Build(Objects);")
    w("        private static readonly Dictionary<string, CarEvent> _events = Build(Events);")
    w("")
    w("        public static CarObject Object(string name) { CarObject o; return _objects.TryGetValue(name, out o) ? o : null; }")
    w("        public static CarEvent Event(string obj, string action) { CarEvent e; return _events.TryGetValue(obj + \"/\" + action, out e) ? e : null; }")
    w("")
    w("        private static Dictionary<string, CarObject> Build(CarObject[] items)")
    w("        {")
    w("            var d = new Dictionary<string, CarObject>(StringComparer.Ordinal);")
    w("            foreach (var i in items) d[i.Name] = i;")
    w("            return d;")
    w("        }")
    w("")
    w("        private static Dictionary<string, CarEvent> Build(CarEvent[] items)")
    w("        {")
    w("            var d = new Dictionary<string, CarEvent>(StringComparer.Ordinal);")
    w("            foreach (var i in items) d[i.Object + \"/\" + i.Action] = i;")
    w("            return d;")
    w("        }")
    w("    }")
    w("}")
    return "\n".join(L) + "\n"


def render_json(m: dict) -> str:
    return json.dumps(m, indent=2, ensure_ascii=False) + "\n"


# ----------------------------------------------------------------------------- commands


def build() -> tuple[dict, list[str]]:
    car = load_pinned_car()
    vocab = load_vocab()
    schema_objects, schema_actions = load_schema_vocab()
    attack = load_attack()
    reg = load_registry()
    tpl = load_templates()
    pin = load_pin()
    errors, warnings = validate(car, vocab, schema_objects, schema_actions, attack, reg, tpl, pin)
    if errors:
        raise ModelError("model validation failed:\n  - " + "\n  - ".join(errors))
    model = derive(car, vocab, attack, reg, tpl, pin, load_sensor_cards(), load_evtx_evidences())
    man_errors: list[str] = []
    check_manifest(render_manifest(model), model, man_errors)
    if man_errors:
        raise ModelError("manifest self-check failed:\n  - " + "\n  - ".join(man_errors))
    return model, warnings


def outputs(model: dict) -> list[tuple[Path, str]]:
    return [(OUT_JSON, render_json(model)), (OUT_MD, render_markdown(model)), (OUT_MAN, render_manifest(model)),
            (OUT_CS, render_csharp(model))]


def cmd_generate(_: argparse.Namespace) -> int:
    model, warnings = build()
    for path, text in outputs(model):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for wmsg in warnings:
        print(f"warning: {wmsg}", file=sys.stderr)
    c = model["counts"]
    print(f"generated {', '.join(str(p.relative_to(ROOT)) for p, _ in outputs(model))}: "
          f"{c['objects']} objects, {c['fields']} fields, {c['events']} events "
          f"({c['events_car']} car + {c['events_superset']} superset), {c['opcodes']} opcodes")
    return 0


def cmd_check(_: argparse.Namespace) -> int:
    model, warnings = build()
    for wmsg in warnings:
        print(f"warning: {wmsg}", file=sys.stderr)
    stale = [str(p.relative_to(ROOT)) for p, text in outputs(model)
             if not p.exists() or p.read_text(encoding="utf-8") != text]
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
    print("(* = ATT&CK overlay action)")
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
