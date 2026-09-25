"""Headless tests — no GUI required.

Run with:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import io
import os
import tempfile
import unittest
import zipfile
from xml.etree import ElementTree as ET

from app import generators as gen
from app.models import ConditionType, CustomDecoder, DetectionRule, RulePackProject
from app.persistence import load_project, save_project
from app.presets import list_presets, load_preset
from app.validator import ERROR, validate_pack


class PresetIntegrityTest(unittest.TestCase):
    def test_all_presets_load_and_validate(self):
        for name in list_presets():
            with self.subTest(preset=name):
                project = load_preset(name)
                self.assertGreater(project.chain.count_rules(), 0, name)
                for tech in project.chain.all_techniques():
                    self.assertGreater(len(tech.rules), 0,
                                       f"{name}: {tech.technique_id} has no rules")
                    self.assertTrue(tech.technique_id.startswith("T"), name)
                issues = validate_pack(project.chain, project.decoders, project.options)
                errors = [i for i in issues if i.severity == ERROR]
                self.assertEqual(errors, [], f"{name}: {errors}")

    def test_preset_rule_ids_unique(self):
        for name in list_presets():
            with self.subTest(preset=name):
                project = load_preset(name)
                ids = [r.rule_id for r in project.chain.all_rules()]
                self.assertEqual(len(ids), len(set(ids)), name)


class GeneratorTest(unittest.TestCase):
    def setUp(self):
        self.project = load_preset(list_presets()[0])

    def test_rules_xml_roundtrip(self):
        xml = gen.render_rules_xml(self.project.chain, self.project.options)
        root = ET.fromstring(xml)
        self.assertEqual(root.tag, "group")
        rules = root.findall("rule")
        self.assertEqual(len(rules), self.project.chain.count_rules())
        # Every rule has the core elements
        for rule in rules:
            self.assertIsNotNone(rule.find("decoded_as"))
            self.assertIsNotNone(rule.find("description"))
        # Spot-check a MITRE mapping survived
        self.assertTrue(any(r.find("mitre/id") is not None for r in rules))

    def test_rule_fields_render(self):
        chain = self.project.chain
        # add a frequency + field rule and verify exact XML shape
        tech = chain.all_techniques()[0]
        tech.rules.append(DetectionRule(
            rule_id=999001, level=12, groups=["test_group"],
            description="freq test", decoder="syslog",
            condition=ConditionType.FREQUENCY, pattern="beacon",
            field_name="url", frequency=5, timeframe=60,
            mitre_id="T1071.001", mitre_tactic="Command and Control",
        ))
        xml = gen.render_rules_xml(chain, self.project.options)
        root = ET.fromstring(xml)
        rule = next(r for r in root.findall("rule") if r.get("id") == "999001")
        self.assertEqual(rule.get("group"), "test_group")
        self.assertIsNotNone(rule.find("field"))
        self.assertEqual(rule.find("frequency").text, "5")
        self.assertEqual(rule.find("timeframe").text, "60")
        self.assertEqual(rule.find("mitre/id").text, "T1071.001")
        self.assertEqual(rule.find("mitre/tactic").text, "Command and Control")

    def test_decoders_xml(self):
        decs = [CustomDecoder(name="d1", prematch="x", regex="(y)", order="a")]
        xml = gen.render_decoders_xml(decs)
        root = ET.fromstring(xml)
        self.assertEqual(root.tag, "decoder_list")
        self.assertEqual(root.find("decoder").get("name"), "d1")

    def test_zip_export_contains_all_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = gen.build_pack_zip(
                self.project.chain, self.project.decoders, self.project.options, tmp
            )
            self.assertTrue(os.path.exists(zip_path))
            with zipfile.ZipFile(zip_path) as zf:
                names = zf.namelist()
            for expected in ("local_rules.xml", "local_decoders.xml",
                             "ossec.conf.snippet", "README.md", "rules.csv"):
                self.assertIn(expected, names, names)


class ValidatorTest(unittest.TestCase):
    def test_duplicate_ids_detected(self):
        project = load_preset(list_presets()[0])
        rules = project.chain.all_rules()
        rules[1].rule_id = rules[0].rule_id
        issues = validate_pack(project.chain, project.decoders, project.options)
        self.assertTrue(any(i.severity == ERROR and "Duplicate" in i.message for i in issues))

    def test_bad_level_and_regex(self):
        project = load_preset(list_presets()[0])
        rule = project.chain.all_rules()[0]
        rule.level = 99
        rule.pattern = "([unclosed"
        issues = validate_pack(project.chain, project.decoders, project.options)
        self.assertTrue(any("Level" in i.message for i in issues))
        self.assertTrue(any("Invalid pattern" in i.message for i in issues))

    def test_unknown_decoder_detected(self):
        project = load_preset(list_presets()[0])
        project.chain.all_rules()[0].decoder = "does_not_exist"
        issues = validate_pack(project.chain, project.decoders, project.options)
        self.assertTrue(any("does_not_exist" in i.message for i in issues))


class PersistenceTest(unittest.TestCase):
    def test_roundtrip(self):
        original = load_preset(list_presets()[0])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "proj.json")
            save_project(original, path)
            loaded = load_project(path)
        self.assertEqual(loaded.chain.name, original.chain.name)
        self.assertEqual(loaded.chain.count_rules(), original.chain.count_rules())
        self.assertEqual([d.name for d in loaded.decoders],
                         [d.name for d in original.decoders])
        self.assertEqual(loaded.options.base_rule_id, original.options.base_rule_id)

    def test_rejects_wrong_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.json")
            with io.open(path, "w", encoding="utf-8") as fh:
                fh.write('{"format": "something_else"}')
            with self.assertRaises(ValueError):
                load_project(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)