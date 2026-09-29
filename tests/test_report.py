import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from xml.etree import ElementTree as ET

from policy_delta import report as report_module
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
    def test_junit_case_outcomes_and_counts(self):
        report = example()
        unapproved = report["cases"][0]
        unapproved["id"] = "unapproved"
        approved = copy.deepcopy(unapproved)
        approved["id"] = "approved"
        approved["expect"]["after"] = "allow"
        approved["allow_expansion"] = True
        execution_error = copy.deepcopy(unapproved)
        execution_error["id"] = "execution-error"
        execution_error["before"] = {
            "status": 404,
            "decision": "error",
            "capabilities": ["read"],
            "error": "unexpected_status",
        }
        execution_error["body"] = {"value": "synthetic-body-marker"}
        execution_error["after"]["token"] = "synthetic-token-marker"
        passing = copy.deepcopy(unapproved)
        passing["id"] = "passing"
        passing["after"] = copy.deepcopy(passing["before"])
        report["cases"] = [unapproved, approved, execution_error, passing]

        xml = report_module.render_junit(assess(report))
        root = ET.fromstring(xml)
        suite = root.find("testsuite")
        self.assertEqual(root.tag, "testsuites")
        self.assertEqual(suite.attrib["tests"], "4")
        self.assertEqual(suite.attrib["failures"], "1")
        self.assertEqual(suite.attrib["errors"], "1")
        cases = {node.attrib["name"]: node for node in suite.findall("testcase")}
        self.assertEqual(set(cases), {"unapproved", "approved", "execution-error", "passing"})
        self.assertIsNotNone(cases["unapproved"].find("failure"))
        self.assertIsNone(cases["unapproved"].find("error"))
        self.assertIsNone(cases["approved"].find("failure"))
        self.assertIsNone(cases["approved"].find("error"))
        self.assertIn("approved expansion", cases["approved"].findtext("system-out"))
        self.assertIn("\nbefore:", cases["approved"].findtext("system-out"))
        self.assertIsNotNone(cases["execution-error"].find("error"))
        self.assertIsNone(cases["execution-error"].find("failure"))
        self.assertIsNone(cases["passing"].find("failure"))
        self.assertIsNone(cases["passing"].find("error"))
        self.assertNotIn("synthetic-body-marker", xml)
        self.assertNotIn("synthetic-token-marker", xml)

    def test_junit_replaces_xml_illegal_suite_name_characters(self):
        report = example()
        report["suite_name"] = "A\x00B\x1fC"
        xml = report_module.render_junit(assess(report))
        suite = ET.fromstring(xml).find("testsuite")
        self.assertEqual(suite.attrib["name"], "A\ufffdB\ufffdC")
        self.assertIn("A\ufffdB\ufffdC", suite.find("testcase").attrib["classname"])

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
            self.assertTrue((output / "junit.xml").is_file())

    def test_output_rolls_back_all_three_files_if_junit_write_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "review"
            original_replace = report_module.os.replace
            calls = 0

            def fail_third(source, destination):
                nonlocal calls
                calls += 1
                if calls == 3:
                    raise OSError("synthetic write failure")
                return original_replace(source, destination)

            with patch("policy_delta.report.os.replace", side_effect=fail_third):
                with self.assertRaisesRegex(OSError, "synthetic write failure"):
                    write_reports(assess(example()), output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
