import copy
import json
import tempfile
import unittest
from pathlib import Path

from policy_delta.suite import SuiteError, load_suite


class SuiteLoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "before.hcl").write_text('path "kv/data/item" { capabilities = ["read"] }', encoding="utf-8")
        (self.root / "after.hcl").write_text('path "kv/data/item" { capabilities = ["read"] }', encoding="utf-8")
        self.data = {
            "version": 1,
            "name": "Example <suite>",
            "mounts": {"kv": {"version": 2, "secrets": {"item": {"password": "fake"}}}},
            "policies": {"before": {"reader": "before.hcl"}, "after": {"reader": "after.hcl"}},
            "principals": {"alice": ["reader"]},
            "cases": [{"id": "read", "principal": "alice", "method": "GET", "path": "kv/data/item", "expect": {"before": "allow", "after": "allow"}}],
        }

    def load(self, data=None):
        path = self.root / "suite.json"
        path.write_text(json.dumps(self.data if data is None else data), encoding="utf-8")
        return load_suite(path)

    def assert_invalid(self, mutate):
        data = copy.deepcopy(self.data)
        mutate(data)
        with self.assertRaises(SuiteError):
            self.load(data)

    def test_valid_suite_returns_resolved_metadata_and_default_expansion(self):
        result = self.load()
        self.assertEqual(result["_root"], self.root.resolve())
        self.assertEqual(len(result["_sha256"]), 64)
        self.assertIn('capabilities = ["read"]', result["_policy_texts"]["before"]["reader"])
        self.assertIs(result["cases"][0]["allow_expansion"], False)

    def test_rejects_unknown_structured_keys_and_bad_version(self):
        for mutator in (
            lambda d: d.update(extra=1),
            lambda d: d["mounts"]["kv"].update(extra=1),
            lambda d: d["cases"][0].update(extra=1),
            lambda d: d["cases"][0]["expect"].update(extra=1),
            lambda d: d.update(version=True),
            lambda d: d.update(name=""),
            lambda d: d.update(name="x" * 161),
        ):
            with self.subTest(mutator=mutator):
                self.assert_invalid(mutator)

    def test_rejects_duplicate_keys_and_nonfinite_numbers(self):
        path = self.root / "suite.json"
        for raw in ('{"version":1,"version":1}', '{"version":NaN}', '{"version":Infinity}'):
            with self.subTest(raw=raw):
                path.write_text(raw, encoding="utf-8")
                with self.assertRaises(SuiteError):
                    load_suite(path)
        path.write_text('{"version":' + "9" * 5000 + '}', encoding="utf-8")
        with self.assertRaises(SuiteError):
            load_suite(path)

    def test_rejects_size_and_count_bounds(self):
        self.assert_invalid(lambda d: d.update(cases=[]))
        self.assert_invalid(lambda d: d.update(cases=d["cases"] * 101))
        self.assert_invalid(lambda d: d["mounts"].update({f"m{i}": {"version": 1, "secrets": {}} for i in range(8)}))
        self.assert_invalid(lambda d: d["mounts"]["kv"].update(secrets={f"key{i}": {} for i in range(101)}))
        self.assert_invalid(lambda d: d["policies"]["before"].update({f"p{i}": "before.hcl" for i in range(16)}))
        self.assert_invalid(lambda d: d["principals"].update({f"p{i}": ["reader"] for i in range(16)}))
        (self.root / "before.hcl").write_text("x" * (256 * 1024 + 1), encoding="utf-8")
        with self.assertRaises(SuiteError):
            self.load()
        (self.root / "before.hcl").write_text("x", encoding="utf-8")
        (self.root / "suite.json").write_bytes(b" " * (1024 * 1024 + 1))
        with self.assertRaises(SuiteError):
            load_suite(self.root / "suite.json")

    def test_rejects_policy_path_escape_and_symlink_escape(self):
        self.assert_invalid(lambda d: d["policies"]["before"].update(reader="../outside.hcl"))
        self.assert_invalid(lambda d: d["policies"]["before"].update(reader=str(self.root / "before.hcl")))
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "policy.hcl"
            target.write_text("x", encoding="utf-8")
            (self.root / "escape.hcl").symlink_to(target)
            self.assert_invalid(lambda d: d["policies"]["before"].update(reader="escape.hcl"))

    def test_relative_policy_path_may_include_current_directory(self):
        self.data["policies"]["before"]["reader"] = "./before.hcl"
        self.assertIn("kv/data/item", self.load()["_policy_texts"]["before"]["reader"])

    def test_rejects_invalid_mount_secret_keys_and_values(self):
        for key in ("/key", "a//b", "a/../b", "a/%2f", "a?b", "a\\b", "é", "a\x01b"):
            with self.subTest(key=key):
                self.assert_invalid(lambda d: d["mounts"]["kv"].update(secrets={key: {}}))
        self.assert_invalid(lambda d: d["mounts"]["kv"].update(version=True))
        self.assert_invalid(lambda d: d["mounts"]["kv"].update(secrets={"key": [1]}))
        for name in ("sys", "auth", "cubbyhole", "identity"):
            with self.subTest(name=name):
                self.assert_invalid(lambda d: d["mounts"].update({name: {"version": 1, "secrets": {}}}))

    def test_rejects_unknown_names_and_duplicate_case_ids(self):
        self.assert_invalid(lambda d: d["principals"]["alice"].append("missing"))
        self.assert_invalid(lambda d: d["cases"][0].update(principal="missing"))
        self.assert_invalid(lambda d: d["policies"]["before"].update(root="before.hcl"))
        self.assert_invalid(lambda d: d["cases"].append(copy.deepcopy(d["cases"][0])))
        self.assert_invalid(lambda d: d["cases"][0].update(id="Bad ID"))

    def test_rejects_invalid_request_paths_and_method_body_pairs(self):
        for path in ("https://example.com/kv", "/kv/data/item", "kv//item", "kv/../item", "kv/data/%2f", "kv/data/a?b", "kv/data/a#b", "kv/data/a\\b", "kv/data/a\x01b", "kv/data/a b", "kv/data/é", "other/data/item", "kv/item"):
            with self.subTest(path=path):
                self.assert_invalid(lambda d: d["cases"][0].update(path=path))
        self.assert_invalid(lambda d: d["cases"][0].update(method="PUT"))
        self.assert_invalid(lambda d: d["cases"][0].update(body={}))
        self.assert_invalid(lambda d: d["cases"][0].update(method="POST"))
        self.assert_invalid(lambda d: d["cases"][0].update(method="POST", body=[]))
        self.assert_invalid(lambda d: d["cases"][0].update(allow_expansion=1))

    def test_malformed_json_types_raise_suite_error(self):
        for mutator in (
            lambda d: d["cases"][0].update(principal=[]),
            lambda d: d["cases"][0].update(method={}),
            lambda d: d["cases"][0]["expect"].update(before=[]),
        ):
            with self.subTest(mutator=mutator):
                self.assert_invalid(mutator)

    def test_rejects_unpaired_surrogates_and_control_characters(self):
        self.assert_invalid(lambda d: d.update(name="bad\ud800"))
        self.assert_invalid(lambda d: d["cases"][0].update(path="kv/data/bad\ud800"))
        self.assert_invalid(lambda d: d["cases"][0].update(path="kv/data/bad\x85"))
        self.assert_invalid(lambda d: d["policies"]["before"].update(reader="bad\ud800.hcl"))

    def test_rejects_overflowed_json_numbers_in_fixture_value(self):
        path = self.root / "suite.json"
        raw = json.dumps(self.data)
        raw = raw.replace('"password": "fake"', '"password": 1e999')
        path.write_text(raw, encoding="utf-8")
        with self.assertRaises(SuiteError):
            load_suite(path)


if __name__ == "__main__":
    unittest.main()
