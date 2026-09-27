import copy
from pathlib import Path
import tempfile
import unittest

from policy_delta.report import assess, render_html, write_reports


def example():
    return {
        "schema_version": 1, "suite_name": "Example <script>alert(1)</script>",
        "engine_version": "OpenBao 2.7.0", "suite_sha256": "a" * 64,
        "policy_sha256": {"before": {"build": "b" * 64}, "after": {"build": "c" * 64}},
        "cases": [{
            "id": "parameters", "principal": "builder", "method": "POST",
            "path": "legacy/release", "allow_expansion": False,
            "expect": {"before": "deny", "after": "deny"},
            "before": {"status": 403, "decision": "deny", "capabilities": ["update"]},
            "after": {"status": 204, "decision": "allow", "capabilities": ["update"]},
        }],
    }


class ReportTests(unittest.TestCase):
    def test_parameter_expansion_fails_despite_identical_capabilities(self):
        original = example()
        checked = assess(original)
        self.assertNotIn("summary", original)
        self.assertEqual(checked["summary"]["exit_code"], 1)
        self.assertEqual(checked["summary"]["capability_invisible_expansions"], 1)
        self.assertEqual(checked["summary"]["mismatches"], 1)

    def test_expansion_requires_explicit_case_approval_and_matching_expectation(self):
        report = example()
        report["cases"][0]["expect"]["after"] = "allow"
        self.assertEqual(assess(report)["summary"]["exit_code"], 1)
        report["cases"][0]["allow_expansion"] = True
        checked = assess(report)
        self.assertEqual(checked["summary"]["exit_code"], 0)
        self.assertEqual(checked["summary"]["expansions"], 1)
        self.assertIn("approved expansion", checked["cases"][0]["findings"])

    def test_error_takes_precedence_over_regression(self):
        report = example()
        failed = copy.deepcopy(report["cases"][0])
        failed["id"] = "missing-fixture"
        failed["after"] = {"status": 404, "decision": "error", "capabilities": ["read"], "error": "http_status"}
        report["cases"].append(failed)
        self.assertEqual(assess(report)["summary"]["exit_code"], 2)

    def test_unchanged_denial_is_a_pass(self):
        report = example()
        report["cases"][0]["after"] = copy.deepcopy(report["cases"][0]["before"])
        self.assertEqual(assess(report)["summary"]["exit_code"], 0)

    def test_html_escapes_metadata_and_error_codes(self):
        report = example()
        report["cases"][0]["path"] = '<img src=x onerror="alert(1)">'
        report["cases"][0]["before"]["error"] = '<script>boom()</script>'
        html = render_html(assess(report))
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn('href="report.json"', html)

    def test_output_never_overwrites_existing_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "review"
            write_reports(assess(example()), output)
            before = (output / "report.json").read_bytes()
            with self.assertRaises(FileExistsError):
                write_reports(assess(example()), output)
            self.assertEqual((output / "report.json").read_bytes(), before)
            self.assertTrue((output / "index.html").is_file())


if __name__ == "__main__":
    unittest.main()
