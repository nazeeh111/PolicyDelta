"""Exercise the installed CLI against real, disposable OpenBao processes."""
import argparse
from copy import deepcopy
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from unittest.mock import patch
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
CHANGES = {"sibling-prefix", "other-team", "forbidden-parameter", "missing-parameter"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bao", required=True, type=Path)
    args = parser.parse_args()
    bao = args.bao.resolve()
    with tempfile.TemporaryDirectory(prefix="policydelta-integration-") as temporary:
        root = Path(temporary)
        examples = root / "examples"
        shutil.copytree(ROOT / "examples", examples)

        def run(name, code):
            output = root / name
            # Execution away from the source tree verifies installed-package imports.
            result = subprocess.run([sys.executable, "-m", "policy_delta", str(examples / f"{name}.json"),
                                     "--bao", str(bao), "--output", str(output)],
                                    cwd=root, capture_output=True, text=True, timeout=120)
            assert result.returncode == code, (name, result.returncode, result.stdout, result.stderr)
            assert (output / "report.json").is_file(), (name, "no report", result.stdout, result.stderr)
            assert (output / "junit.xml").is_file(), (name, "no JUnit report", result.stdout, result.stderr)
            report = json.loads((output / "report.json").read_text())
            assert report["summary"]["exit_code"] == code
            serialized = (output / "report.json").read_text() + (output / "index.html").read_text() + (output / "junit.xml").read_text()
            for fixture_value in ("synthetic-fixture-only", "replacement-fixture", "reset-me"):
                assert fixture_value not in serialized, "fixture data leaked into report"
            print(f"{name}: exit {code}, {len(report['cases'])} cases")
            return report

        def junit(name, tests, failures, errors):
            suite = ET.parse(root / name / "junit.xml").getroot().find("testsuite")
            assert suite is not None
            observed = tuple(int(suite.attrib[key]) for key in ("tests", "failures", "errors"))
            assert observed == (tests, failures, errors), (name, observed)
            assert len(suite.findall("testcase")) == tests
            return {case.attrib["name"]: case for case in suite.findall("testcase")}

        expanded = run("expansion", 1)
        expansion_cases = junit("expansion", 11, 4, 0)
        assert {name for name, case in expansion_cases.items() if case.find("failure") is not None} == CHANGES
        assert expanded["summary"]["errors"] == 0
        assert expanded["summary"]["mismatches"] == 4
        changed = {c["id"] for c in expanded["cases"] if "unapproved expansion" in c["findings"]}
        assert changed == CHANGES, changed
        invisible = {c["id"] for c in expanded["cases"] if "capabilities unchanged" in c["findings"]}
        assert invisible == {"forbidden-parameter", "missing-parameter"}, invisible
        for case in expanded["cases"]:
            if case["id"] in {"delete-fixture", "read-after-delete"}:
                assert case["before"]["decision"] == case["after"]["decision"] == "allow"
        unchanged = run("unchanged", 0)
        junit("unchanged", 11, 0, 0)
        assert unchanged["summary"]["expansions"] == 0
        approved = run("approved", 0)
        approved_cases = junit("approved", 11, 0, 0)
        assert "approved expansion" in approved_cases["sibling-prefix"].findtext("system-out")
        assert approved["summary"]["expansions"] == 4
        assert approved["summary"]["unapproved_expansions"] == 0

        base = json.loads((examples / "unchanged.json").read_text())
        missing = deepcopy(base)
        missing["cases"] = [dict(base["cases"][0], path="ci/data/build/absent")]
        (examples / "missing.json").write_text(json.dumps(missing))
        error = run("missing", 2)
        missing_cases = junit("missing", 1, 0, 1)
        assert missing_cases["build-read"].find("error") is not None
        assert error["cases"][0]["before"]["status"] == 404
        assert error["cases"][0]["before"]["decision"] == "error"

        mixed = deepcopy(json.loads((examples / "expansion.json").read_text()))
        missing_case = dict(deepcopy(base["cases"][0]), id="missing-fixture", path="ci/data/build/absent")
        mixed["cases"] = [next(case for case in mixed["cases"] if case["id"] == "sibling-prefix"), missing_case]
        (examples / "mixed.json").write_text(json.dumps(mixed))
        run("mixed", 2)
        mixed_cases = junit("mixed", 2, 1, 1)
        assert mixed_cases["sibling-prefix"].find("failure") is not None
        assert mixed_cases["missing-fixture"].find("error") is not None

        # Dev mode has a default secret/ mount. Explicit fixtures must reset it too.
        default = deepcopy(base)
        default["mounts"]["secret"] = default["mounts"].pop("ci")
        default["cases"] = [dict(base["cases"][0], path="secret/data/build/job")]
        (examples / "policies/default.hcl").write_text('path "secret/data/build/*" { capabilities = ["read"] }\n')
        default["policies"] = {v: {"build": "policies/default.hcl"} for v in ("before", "after")}
        (examples / "default.json").write_text(json.dumps(default))
        run("default", 0)

        # A report collision must fail before even trying the deliberately missing runtime.
        original = (root / "unchanged/report.json").read_bytes()
        collision = subprocess.run([sys.executable, "-m", "policy_delta", str(examples / "unchanged.json"),
                                    "--bao", str(root / "missing-bao"), "--output", str(root / "unchanged")],
                                   cwd=root, capture_output=True, text=True, timeout=10)
        assert collision.returncode == 2 and "already exists" in collision.stderr
        assert (root / "unchanged/report.json").read_bytes() == original
        invalid = deepcopy(base)
        invalid["cases"] = []
        (examples / "invalid.json").write_text(json.dumps(invalid))
        invalid_run = subprocess.run([sys.executable, "-m", "policy_delta", str(examples / "invalid.json"),
                                      "--bao", str(root / "missing-bao"), "--output", str(root / "invalid")],
                                     cwd=root, capture_output=True, text=True, timeout=10)
        assert invalid_run.returncode == 2 and "cases must" in invalid_run.stderr
        assert not (root / "invalid").exists()
        print("Collision protection and validation-before-execution passed.")

        from policy_delta.runner import run_suite, RunError
        from policy_delta.suite import load_suite
        received = []

        class ForeignListener(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append("GET")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

            def do_POST(self):
                received.append("POST")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args):
                pass

        foreign = HTTPServer(("127.0.0.1", 0), ForeignListener)
        listener = threading.Thread(target=foreign.serve_forever, daemon=True)
        listener.start()
        try:
            with patch("policy_delta.runner._free_port", return_value=foreign.server_port):
                try:
                    run_suite(load_suite(examples / "unchanged.json"), bao)
                except RunError as error:
                    assert str(error) == "server_exited_during_startup", str(error)
                else:
                    raise AssertionError("Occupied port was accepted")
            assert received == [], "Requests were sent to an unrelated listener"
            print("Startup collision rejected; unrelated listener received zero requests.")
        finally:
            foreign.shutdown()
            foreign.server_close()
            listener.join(timeout=2)



if __name__ == "__main__":
    main()
