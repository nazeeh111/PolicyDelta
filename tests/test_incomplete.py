"""Partial evidence survives lifecycle failures without inventing HTTP decisions."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from xml.etree import ElementTree as ET

from policy_delta import runner
from policy_delta.__main__ import main
from policy_delta.report import assess, render_html, render_junit
from test_runner import FakeProcess, suite


ALLOW = {"status": 200, "decision": "allow", "capabilities": ["read"]}
DENY = {"status": 403, "decision": "deny", "capabilities": ["deny"]}


class IncompleteRunTests(unittest.TestCase):
    def execute(self, *, readiness=None, cases=None, shutdown=None):
        processes = [FakeProcess(), FakeProcess()]
        with patch.object(runner, "_check_version", return_value="OpenBao 2.7.0"), \
             patch.object(runner, "_free_port", return_value=12345), \
             patch.object(runner, "_start_server", side_effect=processes), \
             patch.object(runner, "_wait_ready", side_effect=readiness), \
             patch.object(runner, "_admin", return_value={}), \
             patch.object(runner, "_run_case", side_effect=cases or [ALLOW, ALLOW, DENY, DENY]), \
             patch.object(runner, "_stop_server", side_effect=shutdown) as stop:
            report = runner.run_suite(suite(), Path("/synthetic/bao"))
        return report, stop.call_args_list

    def assert_no_private_values(self, report):
        encoded = json.dumps(report) + render_html(assess(report)) + render_junit(assess(report))
        for value in ("secret-marker", "token-marker", "private-server-output", "private-os-context"):
            self.assertNotIn(value, encoded)

    def test_second_variant_startup_preserves_before_and_marks_after_not_run(self):
        error = runner.RunError("startup_marker_timeout",
                                startup_diagnostics={"bytes_seen": 0, "drain_state": "eof"})
        report, stops = self.execute(readiness=[None, error])
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual([c["before"]["decision"] for c in report["cases"]], ["allow", "allow"])
        self.assertEqual([c["after"]["decision"] for c in report["cases"]], ["not_run", "not_run"])
        self.assertTrue(all(c["after"]["status"] is None for c in report["cases"]))
        self.assertEqual(report["execution"]["status"], "incomplete")
        self.assertEqual(report["execution"]["failures"][0], {
            "stage": "startup", "variant": "after", "code": "startup_marker_timeout",
            "startup_diagnostics": {"bytes_seen": 0, "drain_state": "eof"},
        })
        checked = assess(report)
        self.assertEqual(checked["summary"]["exit_code"], 2)
        self.assertEqual(checked["summary"]["not_run"], 2)
        self.assertEqual(checked["summary"]["mismatches"], 0)
        self.assertEqual(len(stops), 2)
        self.assert_no_private_values(report)

    def test_fixture_failure_keeps_completed_case_without_fabricating_denial(self):
        report, stops = self.execute(cases=[ALLOW, runner.RunError("admin_request_failed")])
        self.assertEqual(report["cases"][0]["before"], ALLOW)
        self.assertEqual(report["cases"][1]["before"]["decision"], "error")
        self.assertEqual(report["cases"][1]["before"]["error"], "observation_incomplete")
        self.assertTrue(all(c["after"]["decision"] == "not_run" for c in report["cases"]))
        failure = report["execution"]["failures"][0]
        self.assertEqual((failure["stage"], failure["variant"], failure["case_id"]),
                         ("case", "before", "second"))
        self.assertEqual(len(stops), 1)
        self.assert_no_private_values(report)

    def test_interrupt_retains_results_and_requests_cleanup(self):
        report, stops = self.execute(cases=[ALLOW, KeyboardInterrupt()])
        self.assertEqual(report["cases"][0]["before"], ALLOW)
        self.assertEqual(report["cases"][1]["before"]["decision"], "error")
        self.assertEqual(report["cases"][1]["before"]["error"], "observation_incomplete")
        self.assertEqual(report["execution"]["failures"][0]["code"], "interrupted")
        self.assertEqual(assess(report)["summary"]["exit_code"], 2)
        self.assertEqual(assess(report)["summary"]["mismatches"], 0)
        self.assertEqual(len(stops), 1)

    def test_cleanup_only_failure_is_a_run_error_not_a_rewritten_request(self):
        report, stops = self.execute(shutdown=[None, runner.RunError("shutdown_failed")])
        self.assertEqual(len(stops), 2)
        self.assertTrue(all(c["before"] == ALLOW and c["after"] == DENY for c in report["cases"]))
        checked = assess(report)
        self.assertEqual(checked["summary"]["errors"], 0)
        self.assertEqual(checked["summary"]["run_errors"], 1)
        self.assertEqual(checked["summary"]["exit_code"], 2)
        xml = ET.fromstring(render_junit(checked)).find("testsuite")
        self.assertEqual(xml.attrib["tests"], "3")
        self.assertEqual(xml.attrib["errors"], "1")
        self.assertEqual(len(xml.findall("testcase")), 3)
        self.assertIsNotNone(xml.findall("testcase")[-1].find("error"))
        self.assertIn("shutdown_failed", render_html(checked))
        self.assertIn("shutdown", render_html(checked))

    def test_cleanup_failure_does_not_replace_original_failure(self):
        report, _ = self.execute(readiness=runner.RunError("startup_marker_timeout"),
                                 shutdown=runner.RunError("shutdown_failed"))
        self.assertEqual([f["code"] for f in report["execution"]["failures"]],
                         ["startup_marker_timeout", "shutdown_failed"])
        self.assertEqual([f["stage"] for f in report["execution"]["failures"]],
                         ["startup", "shutdown"])

    def test_raw_os_errors_are_replaced_with_a_fixed_failure_code(self):
        report, _ = self.execute(cases=[ALLOW, OSError("private-os-context")])
        self.assertEqual(report["execution"]["failures"][0]["code"], "operation_failed")
        self.assert_no_private_values(report)

    def test_version_failure_keeps_an_unverified_engine_and_never_spawns(self):
        with patch.object(runner, "_check_version",
                          side_effect=runner.RunError("unsupported_engine_version")), \
             patch.object(runner, "_start_server") as start:
            report = runner.run_suite(suite(), Path("/synthetic/bao"))
        start.assert_not_called()
        self.assertIsNone(report["engine_version"])
        self.assertEqual(report["execution"]["failures"], [
            {"stage": "engine_version", "code": "unsupported_engine_version"}])
        self.assertTrue(all(c[v]["decision"] == "not_run"
                            for c in report["cases"] for v in ("before", "after")))

    def test_lifecycle_metadata_is_escaped_in_both_human_readable_formats(self):
        report, _ = self.execute(readiness=runner.RunError("startup_marker_timeout"))
        report["execution"]["failures"][0]["case_id"] = '<script>fixture</script>'
        report["execution"]["failures"][0]["code"] = "unsafe\x00code"
        checked = assess(report)
        html = render_html(checked)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;fixture&lt;/script&gt;", html)
        xml = ET.fromstring(render_junit(checked)).find("testsuite")
        self.assertIn("unsafe\ufffdcode", ET.tostring(xml, encoding="unicode"))

    def test_real_cli_missing_executable_publishes_three_incomplete_artifacts(self):
        example = Path(__file__).resolve().parents[1] / "examples/unchanged.json"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report"
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                code = main([str(example), "--bao", str(Path(temporary) / "missing-bao"),
                             "--output", str(output)])
            self.assertEqual(code, 2)
            self.assertEqual({f.name for f in output.iterdir()},
                             {"report.json", "index.html", "junit.xml"})
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["summary"]["exit_code"], 2)
            self.assertEqual(report["summary"]["not_run"], len(report["cases"]))
            self.assertEqual(report["summary"]["mismatches"], 0)
            self.assertEqual(report["execution"]["failures"][0]["code"], "version_check_failed")
            self.assertIn("version_check_failed", (output / "index.html").read_text())
            self.assertIsNotNone(ET.parse(output / "junit.xml").find(".//error"))
            original = (output / "report.json").read_bytes()
            with contextlib.redirect_stderr(captured):
                self.assertEqual(main([str(example), "--bao", "missing", "--output", str(output)]), 2)
            self.assertEqual((output / "report.json").read_bytes(), original)
