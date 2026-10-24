"""Tests for the CAR event-log model: the pinned sources, the registries and the generator agree.

Runs under `python -m unittest discover -s tests` (no third-party test runner needed) and under pytest.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import carmodel  # noqa: E402


class PinnedSourcesTest(unittest.TestCase):
    def setUp(self):
        self.car = carmodel.load_pinned_car()
        self.vocab = carmodel.load_vocab()
        self.schema_objects, self.schema_actions = carmodel.load_schema_vocab()
        self.pin = carmodel.load_pin()

    def test_thirteen_car_objects(self):
        self.assertEqual(sorted(self.car), sorted(self.vocab))
        self.assertEqual(len(self.car), 13)

    def test_pinned_actions_are_a_subset_of_car_vocab(self):
        for o, spec in self.car.items():
            self.assertTrue(set(spec["actions"]) <= set(self.vocab[o]), o)

    def test_pinned_matrix_sizes(self):
        self.assertEqual(sum(len(s["actions"]) for s in self.car.values()), 50)
        self.assertEqual(sum(len(a) for a in self.vocab.values()), 73)
        self.assertEqual(sum(len(s["fields"]) for s in self.car.values()), 219)

    def test_schema_vocabulary_matches_car_vocab_and_adds_only_promoted_objects(self):
        promoted = {"group", "scheduled_job", "user_account"}
        self.assertEqual(set(self.schema_objects), set(self.vocab) | promoted)
        for o in self.vocab:
            self.assertEqual(sorted(self.schema_actions[o]), sorted(self.vocab[o]), o)

    def test_pin_records_the_same_car_commit_as_the_submodule(self):
        self.assertEqual(self.pin["car_submodule"]["commit"], "1b922fe1527d956e222a99473472e594f10f610b")
        self.assertEqual(len(self.pin["commit"]), 40)


class RegistryTest(unittest.TestCase):
    def setUp(self):
        self.model, self.warnings = carmodel.build()

    def test_build_validates_without_warnings(self):
        self.assertEqual(self.warnings, [])

    def test_counts(self):
        c = self.model["counts"]
        self.assertEqual((c["objects"], c["fields"], c["events"], c["events_car"], c["events_superset"], c["opcodes"]),
                         (13, 219, 73, 50, 23, 46))

    def test_task_is_eventid_div_100(self):
        for e in self.model["events"]:
            self.assertEqual(e["task"], e["id"] // 100, e)

    def test_eventids_unique_and_in_range(self):
        ids = [e["id"] for e in self.model["events"]]
        self.assertEqual(len(ids), len(set(ids)))
        by_obj = {o["key"]: o for o in self.model["objects"]}
        for e in self.model["events"]:
            lo, hi = by_obj[e["object"]]["range"]
            self.assertTrue(lo <= e["id"] <= hi, e)
            off = e["id"] - lo
            if e["provenance"] == "car":
                self.assertTrue(1 <= off <= 49, e)
            else:
                self.assertTrue(50 <= off <= 99, e)

    def test_brief_examples_hold_where_the_model_has_the_action(self):
        want = {("process", "create"): 1001, ("process", "terminate"): 1002,
                ("file", "create"): 1101, ("file", "delete"): 1102, ("file", "modify"): 1103,
                ("flow", "start"): 1201, ("flow", "end"): 1202,
                ("registry", "add"): 1301, ("module", "load"): 1401, ("thread", "remote_create"): 1501}
        got = {(e["object"], e["action"]): e["id"] for e in self.model["events"]}
        for k, v in want.items():
            self.assertEqual(got[k], v, k)
        self.assertNotIn(("registry", "edit"), got)  # the brief's "edit" is not a CAR action

    def test_one_opcode_per_action_name(self):
        ops = {a["name"]: a["opcode"] for a in self.model["actions"]}
        for e in self.model["events"]:
            self.assertEqual(e["opcode"], ops[e["action"]])
        vals = list(ops.values())
        self.assertEqual(len(vals), len(set(vals)))
        self.assertTrue(all(10 <= v <= 238 for v in vals))

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
            self.assertEqual(o["template_data_items"], len(self.model["envelope"]) + len(o["fields"]))
            self.assertLessEqual(o["template_data_items"], 99)
            indices = [f["index"] for f in self.model["envelope"]] + [f["index"] for f in o["fields"]]
            self.assertEqual(indices, list(range(1, len(indices) + 1)), o["key"])

    def test_field_types_are_win_types(self):
        for o in self.model["objects"]:
            for f in o["fields"]:
                self.assertTrue(f["in"].startswith("win:"), f)
                if f["out"]:
                    self.assertTrue(f["out"].startswith("win:"), f)


class DriftGateTest(unittest.TestCase):
    def test_committed_outputs_are_fresh(self):
        model, _ = carmodel.build()
        self.assertEqual(carmodel.OUT_JSON.read_text(encoding="utf-8"), carmodel.render_json(model))
        self.assertEqual(carmodel.OUT_MD.read_text(encoding="utf-8"), carmodel.render_markdown(model))

    def test_generated_json_is_self_consistent(self):
        m = json.loads(carmodel.OUT_JSON.read_text(encoding="utf-8"))
        ids_from_objects = sorted(e["id"] for o in m["objects"] for e in o["events"])
        self.assertEqual(ids_from_objects, sorted(e["id"] for e in m["events"]))

    def test_validation_rejects_a_superset_id_in_the_car_offset_range(self):
        car = carmodel.load_pinned_car()
        vocab = carmodel.load_vocab()
        so, sa = carmodel.load_schema_vocab()
        reg = carmodel.load_registry()
        tpl = carmodel.load_templates()
        pin = carmodel.load_pin()
        for e in reg["events"]:
            if (e["object"], e["action"]) == ("process", "execute"):
                e["id"] = 1004
        errors, _ = carmodel.validate(car, vocab, so, sa, reg, tpl, pin)
        self.assertTrue(any("outside 50–99" in err for err in errors), errors)

    def test_validation_rejects_a_missing_event(self):
        car = carmodel.load_pinned_car()
        vocab = carmodel.load_vocab()
        so, sa = carmodel.load_schema_vocab()
        reg = carmodel.load_registry()
        tpl = carmodel.load_templates()
        pin = carmodel.load_pin()
        reg["events"] = [e for e in reg["events"] if (e["object"], e["action"]) != ("email", "delete")]
        errors, _ = carmodel.validate(car, vocab, so, sa, reg, tpl, pin)
        self.assertTrue(any("differ from the car-vocab matrix" in err for err in errors), errors)


if __name__ == "__main__":
    unittest.main()
