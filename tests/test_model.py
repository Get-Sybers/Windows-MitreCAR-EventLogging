"""Tests for the CAR event-log model: the pinned sources, the registries, the generator and the manifest agree.

Runs under `python -m unittest discover -s tests` (no third-party runner needed) and under pytest.
"""
from __future__ import annotations

import json
import re
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import carmodel  # noqa: E402

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events"}


def _inputs():
    return (carmodel.load_pinned_car(), carmodel.load_vocab(), *carmodel.load_schema_vocab(),
            carmodel.load_attack(), carmodel.load_registry(), carmodel.load_templates(), carmodel.load_pin())


class PinnedSourcesTest(unittest.TestCase):
    def setUp(self):
        self.car = carmodel.load_pinned_car()
        self.vocab = carmodel.load_vocab()
        self.schema_objects, self.schema_actions = carmodel.load_schema_vocab()
        self.attack = carmodel.load_attack()
        self.pin = carmodel.load_pin()

    def test_thirteen_car_objects(self):
        self.assertEqual(sorted(self.car), sorted(self.vocab))
        self.assertEqual(len(self.car), 13)

    def test_pinned_matrix_sizes(self):
        self.assertEqual(sum(len(s["actions"]) for s in self.car.values()), 50)
        self.assertEqual(sum(len(a) for a in self.vocab.values()), 73)
        self.assertEqual(sum(len(s["fields"]) for s in self.car.values()), 219)

    def test_overlay_actions_derive_from_attack_data_components(self):
        """Byakugan's _action_for, ported verbatim, must reproduce car-vocab from CAR ∪ ATT&CK."""
        for o in self.vocab:
            derived = set((self.attack.get(o) or {}).get("components", {}))
            self.assertEqual(set(self.car[o]["actions"]) | derived, set(self.vocab[o]), o)
        overlay = {(o, a) for o in self.vocab for a in self.vocab[o] if a not in self.car[o]["actions"]}
        self.assertEqual(len(overlay), 23)
        for o, a in overlay:
            comps = self.attack[o]["components"][a]
            self.assertTrue(all(c["description"] for c in comps), (o, a))

    def test_schema_vocabulary_matches_car_vocab_and_adds_only_promoted_objects(self):
        promoted = {"group", "scheduled_job", "user_account"}
        self.assertEqual(set(self.schema_objects), set(self.vocab) | promoted)
        for o in self.vocab:
            self.assertEqual(sorted(self.schema_actions[o]), sorted(self.vocab[o]), o)

    def test_pin_records_the_same_car_commit_as_the_submodule(self):
        self.assertEqual(self.pin["car_submodule"]["commit"], "1b922fe1527d956e222a99473472e594f10f610b")
        self.assertEqual(len(self.pin["commit"]), 40)
        self.assertEqual(set(self.pin["files"]), {"car-vocab.json", "car-actions.schema.json",
                                                   "attack_data_sources_objects.yaml", "matched-evidences.yaml"})


class RegistryTest(unittest.TestCase):
    def setUp(self):
        self.model, self.warnings = carmodel.build()

    def test_build_validates_without_warnings(self):
        self.assertEqual(self.warnings, [])

    def test_counts(self):
        c = self.model["counts"]
        self.assertEqual((c["objects"], c["fields"], c["events"], c["events_car"], c["events_superset"], c["opcodes"]),
                         (13, 219, 73, 50, 23, 46))

    def test_numbering_rule(self):
        order = ["process", "file", "flow", "registry", "module", "thread", "driver", "user_session", "service",
                 "authentication", "email", "http", "socket"]
        self.assertEqual([o["key"] for o in self.model["objects"]], order)
        for i, o in enumerate(self.model["objects"], start=1):
            self.assertEqual(o["task"], i)
            self.assertEqual(o["base"], 900 + 100 * i)
            self.assertEqual(int(o["keyword"], 16), 1 << (i - 1))
            car = [e for e in o["events"] if e["provenance"] == "car"]
            sup = [e for e in o["events"] if e["provenance"] == "superset"]
            self.assertEqual([e["action"] for e in car], sorted(e["action"] for e in car), o["key"])
            self.assertEqual([e["action"] for e in sup], sorted(e["action"] for e in sup), o["key"])
            self.assertEqual([e["id"] for e in car], list(range(o["base"] + 1, o["base"] + 1 + len(car))))
            self.assertEqual([e["id"] for e in sup], list(range(o["base"] + 50, o["base"] + 50 + len(sup))))

    def test_spot_ids(self):
        got = {(e["object"], e["action"]): e["id"] for e in self.model["events"]}
        self.assertEqual(got[("process", "create")], 1002)
        self.assertEqual(got[("process", "execute")], 1050)
        self.assertEqual(got[("file", "create")], 1102)
        self.assertEqual(got[("registry", "add")], 1301)
        self.assertEqual(got[("thread", "create")], 1501)
        self.assertEqual(got[("thread", "remote_create")], 1502)
        self.assertEqual(got[("user_session", "login")], 1702)
        self.assertEqual(got[("service", "create")], 1801)
        self.assertEqual(got[("socket", "bind")], 2201)
        self.assertNotIn(("registry", "edit"), got)

    def test_one_opcode_per_action_name(self):
        ops = {a["name"]: a["opcode"] for a in self.model["actions"]}
        for e in self.model["events"]:
            self.assertEqual(e["opcode"], ops[e["action"]])
        vals = list(ops.values())
        self.assertEqual(len(vals), len(set(vals)))
        self.assertTrue(all(10 <= v <= 239 for v in vals))
        self.assertEqual(ops["content"], 51)  # the first overlay-only name follows the 41 pinned-CAR names

    def test_keywords_are_distinct_single_bits(self):
        bits = []
        for o in self.model["objects"] + self.model["promoted_objects"] + self.model["reserved_ranges"]:
            kw = int(o["keyword"], 16) if isinstance(o["keyword"], str) else int(o["keyword"])
            self.assertEqual(kw & (kw - 1), 0, o)
            self.assertTrue(0 <= kw.bit_length() - 1 <= 47, o)
            bits.append(kw)
        self.assertEqual(len(bits), len(set(bits)))

    def test_every_template_field_is_a_pinned_car_field_in_pinned_order(self):
        car = carmodel.load_pinned_car()
        for o in self.model["objects"]:
            self.assertEqual([f["name"] for f in o["fields"]], [f["name"] for f in car[o["key"]]["fields"]], o["key"])
            self.assertEqual(o["data_items"], len(o["fields"]))
            self.assertLessEqual(o["data_items"], 100)
            self.assertEqual([f["index"] for f in o["fields"]], list(range(1, len(o["fields"]) + 1)), o["key"])

    def test_every_field_is_a_unicode_string_with_a_known_format(self):
        for o in self.model["objects"]:
            for f in o["fields"]:
                self.assertEqual(f["type"], "win:UnicodeString", f)
                self.assertIn(f["format"], self.model["formats"], f)

    def test_overlay_events_carry_their_attack_definition(self):
        for e in self.model["events"]:
            if e["provenance"] == "superset":
                self.assertTrue(e["attack_components"], e)
                self.assertIn("ATT&CK data component", e["definition"])
            else:
                self.assertTrue(e["definition"], e)


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.model, _ = carmodel.build()
        self.xml = carmodel.render_manifest(self.model)
        self.root = ET.fromstring(self.xml.encode("utf-8"))

    def test_counts(self):
        prov = self.root.find(".//e:provider", NS)
        self.assertEqual(prov.get("name"), "Get-Sybers-MitreCAR")
        self.assertEqual(prov.get("guid"), "{5bc454ac-3ed9-4b89-b9f4-af8202af0ed8}")
        self.assertEqual(len(prov.findall("e:channels/e:channel", NS)), 1)
        self.assertEqual(len(prov.findall("e:tasks/e:task", NS)), 13)
        self.assertEqual(len(prov.findall("e:opcodes/e:opcode", NS)), 46)
        self.assertEqual(len(prov.findall("e:keywords/e:keyword", NS)), 13)
        self.assertEqual(len(prov.findall("e:templates/e:template", NS)), 13)
        self.assertEqual(len(prov.findall("e:events/e:event", NS)), 73)

    def test_channel(self):
        ch = self.root.find(".//e:channel", NS)
        self.assertEqual(ch.get("name"), "Get-Sybers-MitreCAR/Operational")
        self.assertEqual(ch.get("type"), "Operational")
        self.assertEqual(ch.get("enabled"), "true")
        self.assertEqual(ch.get("value"), "16")

    def test_every_event_is_wired_to_its_task_opcode_keyword_template_and_message(self):
        tasks = {t.get("name"): int(t.get("value")) for t in self.root.findall(".//e:task", NS)}
        opcodes = {o.get("name"): int(o.get("value")) for o in self.root.findall(".//e:opcode", NS)}
        templates = {t.get("tid"): len(t.findall("e:data", NS)) for t in self.root.findall(".//e:template", NS)}
        strings = {s.get("id"): s.get("value") for s in self.root.findall(".//e:string", NS)}
        by_id = {e["id"]: e for e in self.model["events"]}
        for ev in self.root.findall(".//e:event", NS):
            e = by_id[int(ev.get("value"))]
            self.assertEqual(tasks[ev.get("task")], e["task"])
            self.assertEqual(opcodes[ev.get("opcode")], e["opcode"])
            self.assertEqual(ev.get("keywords"), e["object"])
            self.assertEqual(ev.get("template"), e["template"])
            msg = strings[f"event.{e['id']}"]
            inserts = sorted(int(n) for n in re.findall(r"%(\d+)", msg))
            self.assertEqual(inserts, list(range(1, templates[e["template"]] + 1)), e["id"])
            self.assertLessEqual(len(inserts), 100)

    def test_all_data_items_are_unicode_strings(self):
        for d in self.root.findall(".//e:data", NS):
            self.assertEqual(d.get("inType"), "win:UnicodeString")
            self.assertEqual(d.get("outType"), "xs:string")

    def test_symbols_unique(self):
        syms = [el.get("symbol") for el in self.root.iter() if el.get("symbol")]
        self.assertEqual(len(syms), len(set(syms)))


class DriftGateTest(unittest.TestCase):
    def test_committed_outputs_are_fresh(self):
        model, _ = carmodel.build()
        for path, text in carmodel.outputs(model):
            self.assertEqual(path.read_text(encoding="utf-8"), text, path)

    def test_generated_json_is_self_consistent(self):
        m = json.loads(carmodel.OUT_JSON.read_text(encoding="utf-8"))
        ids_from_objects = sorted(e["id"] for o in m["objects"] for e in o["events"])
        self.assertEqual(ids_from_objects, sorted(e["id"] for e in m["events"]))

    def test_validation_rejects_a_superset_id_in_the_car_offset_range(self):
        car, vocab, so, sa, attack, reg, tpl, pin = _inputs()
        for e in reg["events"]:
            if (e["object"], e["action"]) == ("process", "execute"):
                e["id"] = 1004
        errors, _ = carmodel.validate(car, vocab, so, sa, attack, reg, tpl, pin)
        self.assertTrue(any("outside 50–99" in err for err in errors), errors)

    def test_validation_rejects_a_missing_event(self):
        car, vocab, so, sa, attack, reg, tpl, pin = _inputs()
        reg["events"] = [e for e in reg["events"] if (e["object"], e["action"]) != ("email", "delete")]
        errors, _ = carmodel.validate(car, vocab, so, sa, attack, reg, tpl, pin)
        self.assertTrue(any("differ from the car-vocab matrix" in err for err in errors), errors)

    def test_validation_rejects_a_renumbered_task(self):
        car, vocab, so, sa, attack, reg, tpl, pin = _inputs()
        reg["objects"][0]["task"] = 10
        errors, _ = carmodel.validate(car, vocab, so, sa, attack, reg, tpl, pin)
        self.assertTrue(any("numbering rule" in err for err in errors), errors)


if __name__ == "__main__":
    unittest.main()
