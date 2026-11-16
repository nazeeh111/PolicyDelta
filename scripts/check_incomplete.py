"""Fault-injected CLI journeys with actual disposable OpenBao processes.

Run after installing the package. Disruptions are injected into the runner, not
represented as naturally occurring engine failures. No production inputs.
"""
import argparse
import contextlib
import io
import json
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree as ET

import policy_delta
from policy_delta import runner
from policy_delta.__main__ import main as cli

ROOT = Path(__file__).resolve().parents[1]


def check(bao: Path, output: Path) -> dict:
    output.mkdir()  # Never reuse or delete an earlier evidence directory.
    summaries = []
    for mode in ("startup", "interrupted", "shutdown"):
        processes, tokens = [], []
        ready_calls = case_calls = stop_calls = 0
        start, ready = runner._start_server, runner._wait_ready
        run_case, stop, token_hex = runner._run_case, runner._stop_server, runner.secrets.token_hex

        def remember_start(*args):
            process = start(*args)
            processes.append(process)
            return process

        def remember_token(*args):
            value = token_hex(*args)
            tokens.append(value)
            return value

        def controlled_ready(*args):
            nonlocal ready_calls
            ready_calls += 1
            if mode == "startup" and ready_calls == 2:
                raise runner.RunError("injected_startup_failure")
            return ready(*args)

        def controlled_case(*args):
            nonlocal case_calls
            case_calls += 1
            if mode == "interrupted" and case_calls == 2:
                raise KeyboardInterrupt
            return run_case(*args)

        def controlled_stop(*args):
            nonlocal stop_calls
            stop(*args)
            stop_calls += 1
            if mode == "shutdown" and stop_calls == 2:
                raise runner.RunError("shutdown_failed")

        captured = io.StringIO()
        destination = output / mode
        with patch.object(runner, "_start_server", side_effect=remember_start), \
             patch.object(runner, "_wait_ready", side_effect=controlled_ready), \
             patch.object(runner, "_run_case", side_effect=controlled_case), \
             patch.object(runner, "_stop_server", side_effect=controlled_stop), \
             patch.object(runner.secrets, "token_hex", side_effect=remember_token), \
             contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            code = cli([str(ROOT / "examples/unchanged.json"), "--bao", str(bao),
                        "--output", str(destination)])
        assert code == 2, (mode, code, captured.getvalue())
        assert processes and all(p.poll() is not None for p in processes), "Owned process remains"
        report = json.loads((destination / "report.json").read_text())
        assert report["execution"]["status"] == "incomplete"
        assert report["summary"]["exit_code"] == 2
        testcase = ET.parse(destination / "junit.xml").find("testsuite")
        assert testcase is not None and int(testcase.attrib["errors"]) > 0
        assert len(testcase.findall("testcase")) == len(report["cases"]) + 1
        serialized = captured.getvalue() + "".join(
            (destination / name).read_text() for name in ("report.json", "index.html", "junit.xml"))
        for private in [*tokens, "synthetic-fixture-only", "replacement-fixture", "reset-me"]:
            assert private not in serialized, "Sensitive synthetic value retained"
        if mode == "startup":
            assert all(c["before"]["decision"] in {"allow", "deny"} for c in report["cases"])
            assert all(c["after"]["decision"] == "not_run" for c in report["cases"])
        elif mode == "interrupted":
            assert report["cases"][0]["before"]["decision"] in {"allow", "deny"}
            assert report["cases"][1]["before"]["decision"] == "error"
            assert report["cases"][1]["before"]["error"] == "observation_incomplete"
            assert all(c["before"]["decision"] == "not_run" for c in report["cases"][2:])
        else:
            assert report["summary"]["not_run"] == report["summary"]["errors"] == 0
            assert all(c[v]["decision"] in {"allow", "deny"}
                       for c in report["cases"] for v in ("before", "after"))
        summaries.append({"mode": mode, "cli_exit": code, "summary": report["summary"],
                          "execution": report["execution"],
                          "owned_processes": len(processes), "all_owned_processes_stopped": True,
                          "synthetic_value_exclusion": True})
    result = {"package_source": policy_delta.__file__, "engine": str(bao),
              "scope": "Actual OpenBao, with explicitly injected lifecycle disruptions", "journeys": summaries}
    (output / "checks.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bao", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.bao.resolve(), args.output), indent=2))
