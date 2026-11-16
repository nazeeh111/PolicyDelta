"""Classify observed requests and render a portable, value-free review artifact."""
from copy import deepcopy
from html import escape
import json
import os
from pathlib import Path
import tempfile
from xml.etree import ElementTree as ET


VERDICTS = {0: "Expectations met", 1: "Policy change needs review", 2: "Execution incomplete"}


def assess(report: dict) -> dict:
    result = deepcopy(report)
    totals = dict(errors=0, mismatches=0, expansions=0, unapproved_expansions=0,
                  restrictions=0, capability_invisible_expansions=0, not_run=0,
                  run_errors=len(result.get("execution", {}).get("failures", [])))
    for case in result["cases"]:
        before, after = case["before"], case["after"]
        findings = []
        if "not_run" in (before["decision"], after["decision"]):
            totals["not_run"] += 1
            findings.append("not run")
        if {"error", "not_run"} & {before["decision"], after["decision"]}:
            totals["errors"] += 1
            findings.append("execution error")
        if any(case[v]["decision"] in {"allow", "deny"} and case[v]["decision"] != case["expect"][v]
               for v in ("before", "after")):
            totals["mismatches"] += 1
            findings.append("expectation mismatch")
        if before["decision"] == "deny" and after["decision"] == "allow":
            totals["expansions"] += 1
            if case["allow_expansion"]:
                findings.append("approved expansion")
            else:
                totals["unapproved_expansions"] += 1
                findings.append("unapproved expansion")
            if set(before["capabilities"]) == set(after["capabilities"]):
                totals["capability_invisible_expansions"] += 1
                findings.append("capabilities unchanged")
        if before["decision"] == "allow" and after["decision"] == "deny":
            totals["restrictions"] += 1
            findings.append("access restricted")
        case["findings"] = findings
    totals["exit_code"] = 2 if totals["errors"] or totals["run_errors"] else 1 if totals["mismatches"] or totals["unapproved_expansions"] else 0
    result["summary"] = totals
    return result


def render_html(report: dict) -> str:
    def e(value):
        return escape(str(value), quote=True)

    def observation(case, variant):
        observed = case[variant]
        decision = observed["decision"]
        tone = decision if decision in {"allow", "deny", "error"} else "error"
        capabilities = ", ".join(observed["capabilities"]) or ("not observed" if decision == "not_run" else "none reported")
        error = f'<br><span class="error">{e(observed["error"])}</span>' if observed.get("error") else ""
        return (f'<span class="decision {tone}">{e(decision.replace("_", " "))}</span> '
                f'<span class="code">HTTP {e(observed["status"] if observed["status"] is not None else "unavailable")}</span>'
                f'<div class="detail">Expected {e(case["expect"][variant])}<br>Capabilities: {e(capabilities)}{error}</div>')

    rows = []
    first_finding = ""
    for number, case in enumerate(report["cases"], 1):
        if case["findings"] and not first_finding:
            first_finding = f'<a class="first-finding" href="#request-{number}">Review first finding</a>'
        findings = "<br>".join(e(item) for item in case["findings"]) or "Expectations met"
        rows.append(
            f'<tr id="request-{number}" role="row"><th scope="row" role="rowheader">{e(case["id"])}<span class="detail">{e(case["principal"])}</span></th>'
            f'<td role="cell" class="request"><b class="method">{e(case["method"])}</b><code>{e(case["path"])}</code></td>'
            f'<td role="cell"><span class="mobile-label" aria-hidden="true">Before</span>{observation(case, "before")}</td>'
            f'<td role="cell"><span class="mobile-label" aria-hidden="true">After</span>{observation(case, "after")}</td>'
            f'<td role="cell" class="finding"><span class="mobile-label" aria-hidden="true">Finding</span>{findings}</td></tr>'
        )
    summary = report["summary"]
    lifecycle_counts = ""
    if "not_run" in summary and "run_errors" in summary:
        lifecycle_counts = f' · {summary["not_run"]} cases not fully run · {summary["run_errors"]} lifecycle errors'
    verdict = VERDICTS[summary["exit_code"]]
    failures = report.get("execution", {}).get("failures", [])
    lifecycle = ""
    if failures:
        entries = "".join(
            f'<li><b>{e(f["stage"])}</b>'
            f' · {e(f.get("variant", "run"))}'
            f'{(" · " + e(f["case_id"])) if "case_id" in f else ""}'
            f' · <code>{e(f["code"])}</code>'
            f'{(" · " + e(f["reason"])) if "reason" in f else ""}'
            f'{("<br><code>" + e(json.dumps(f["startup_diagnostics"], sort_keys=True)) + "</code>") if "startup_diagnostics" in f else ""}'
            f'{("<br>Owned child at cleanup: <code>" + e(json.dumps(f["owned_process"], sort_keys=True)) + "</code>. PID may be reused; verify identity before action.") if "owned_process" in f else ""}</li>'
            for f in failures
        )
        lifecycle = (
            '<section aria-label="Run lifecycle"><h2>Run incomplete</h2>'
            '<p>Completed observations are retained. Not run means no decision was observed, not a denial.</p>'
            f'<ul>{entries}</ul></section>'
        )
    hashes = "".join(f'<dt>{e(variant)} / {e(name)}</dt><dd><code>{e(digest)}</code></dd>'
                     for variant, policies in report["policy_sha256"].items() for name, digest in policies.items())
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(report["suite_name"])} · PolicyDelta</title><style>
:root{{color-scheme:light;--ink:#202724;--muted:#59635d;--line:#ccd3cb;--paper:#f5f4ee}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 system-ui,sans-serif}}
main{{max-width:1500px;margin:auto;padding:38px 36px 64px}}header{{border-bottom:2px solid var(--ink);padding-bottom:22px;display:flex;justify-content:space-between;gap:20px;align-items:baseline}}
.brand{{font-weight:800;font-size:21px;letter-spacing:-.6px}}a{{color:#174c67;text-underline-offset:4px}}a:focus-visible,summary:focus-visible{{outline:3px solid #174c67;outline-offset:5px}}
.eyebrow{{text-transform:uppercase;letter-spacing:.12em;font-size:11px;font-weight:700;color:var(--muted)}}h1{{font-size:clamp(28px,4vw,48px);line-height:1.12;letter-spacing:-1.4px;margin:10px 0 15px;overflow-wrap:anywhere}}h2{{font-size:21px;font-weight:650;margin:0}}
.intro{{padding:30px 0 25px}}.verdict{{display:flex;flex-wrap:wrap;align-items:baseline;gap:12px 28px;border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:18px 0;margin-bottom:25px}}.counts{{color:var(--muted);font-size:14px}}
.table-wrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;text-align:left;min-width:840px}}thead{{font-size:11px;letter-spacing:.06em;text-transform:uppercase}}th,td{{padding:17px 12px;vertical-align:top;border-bottom:1px solid var(--line)}}th:first-child,td:first-child{{padding-left:0}}tbody th{{font-weight:650;min-width:135px}}tbody tr:hover{{background:#eeeee5}}td{{font-size:13px}}code,.code{{font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}}td code{{display:block;margin-top:6px;max-width:250px}}.method{{font-size:11px}}.detail{{display:block;color:var(--muted);font-size:12px;font-weight:400;margin-top:8px}}.decision{{font-weight:750;text-transform:uppercase;font-size:11px;letter-spacing:.03em;margin-right:5px}}.allow{{color:#216846}}.deny{{color:#7c3f24}}.error{{color:#a52029}}
.scope{{max-width:830px;font-size:13px;color:var(--muted);margin:28px 0}}details{{border-top:1px solid var(--line);padding-top:16px}}summary{{cursor:pointer;font-weight:650}}dl{{display:grid;grid-template-columns:minmax(120px,220px) 1fr;gap:8px 20px;font-size:12px}}dd{{margin:0;min-width:0}}footer{{font-size:12px;color:var(--muted);margin-top:30px}}@media(max-width:700px){{main{{padding:24px 18px}}header{{align-items:center;font-size:12px}}h1{{letter-spacing:-.6px}}dl{{display:block}}dd{{margin-bottom:12px}}}}

.mobile-label{{display:none}}.first-finding{{display:inline-block;margin:12px 0}}
@media screen and (max-width:920px){{
.table-wrap{{overflow:visible}}
.table-wrap table,.table-wrap tbody{{display:block;min-width:0;width:100%}}
.table-wrap thead{{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}}
.table-wrap tbody tr{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));padding:14px 0;border-bottom:1px solid var(--line);scroll-margin-top:12px}}
.table-wrap tbody th,.table-wrap tbody td{{width:auto;min-width:0;padding:6px 8px;border:0;overflow-wrap:anywhere;vertical-align:top}}
.table-wrap tbody th,.table-wrap .request,.table-wrap .finding{{grid-column:1/-1}}
.mobile-label{{display:block;font-weight:650;color:var(--muted);font-size:12px;margin-bottom:4px}}
.table-wrap .finding{{border-left:2px solid var(--line);margin:4px 8px;padding:4px 8px}}
}}
</style></head><body><main><header><span class="brand">PolicyDelta</span><a href="report.json">Read the JSON evidence</a></header>
<section class="intro"><div class="eyebrow">Before / after policy review</div><h1>{e(report["suite_name"])}</h1><span class="detail">{e(report["engine_version"] or "Engine not verified")} · Disposable local servers · {len(report["cases"])} declared requests</span></section>
<section class="verdict"><h2>{e(verdict)}</h2><span class="code">Exit {summary["exit_code"]}</span><span class="counts">{summary["expansions"]} newly allowed · {summary["unapproved_expansions"]} unapproved expansions · {summary["restrictions"]} newly denied · {summary["mismatches"]} expectation mismatches · {summary["errors"]} case execution errors{lifecycle_counts}</span></section>
{lifecycle}
{first_finding}
<div class="table-wrap" tabindex="0" role="region" aria-label="Request comparisons"><table role="table"><thead role="rowgroup"><tr role="row"><th scope="col" role="columnheader">Case / principal</th><th scope="col" role="columnheader">Request</th><th scope="col" role="columnheader">Before</th><th scope="col" role="columnheader">After</th><th scope="col" role="columnheader">Finding</th></tr></thead><tbody role="rowgroup">{''.join(rows)}</tbody></table></div>
<p class="scope">Results cover these declared requests and fixtures. They do not establish all possible access, production behavior, or complete policy safety. A deny requires HTTP 403; missing data, setup failures, and other errors do not count as successful denial tests. Request bodies, returned secret values, and tokens are excluded from this report.</p>
<details><summary>Input identities</summary><dl><dt>Suite SHA-256</dt><dd><code>{e(report["suite_sha256"])}</code></dd>{hashes}</dl></details>
<footer>{summary["capability_invisible_expansions"]} newly allowed request(s) have unchanged capability lists.</footer></main></body></html>'''


def _xml_safe(value: object, *, attribute: bool = False) -> str:
    """Replace controls, surrogates, and noncharacters before XML serialization."""
    safe = []
    for character in str(value):
        codepoint = ord(character)
        if ((codepoint < 0x20 and (attribute or codepoint not in (9, 10, 13)))
                or 0x7F <= codepoint <= 0x9F
                or 0xD800 <= codepoint <= 0xDFFF
                or 0xFDD0 <= codepoint <= 0xFDEF
                or codepoint & 0xFFFF in (0xFFFE, 0xFFFF)):
            safe.append("\ufffd")
        else:
            safe.append(character)
    return "".join(safe)


def render_junit(report: dict) -> str:
    """Render assessed policy cases as one JUnit testcase each."""
    outcomes = []
    for case in report["cases"]:
        findings = case["findings"]
        if "execution error" in findings:
            outcomes.append("error")
        elif "expectation mismatch" in findings or "unapproved expansion" in findings:
            outcomes.append("failure")
        else:
            outcomes.append("pass")
    failures = report.get("execution", {}).get("failures", [])
    counts = {
        "tests": str(len(outcomes) + len(failures)),
        "failures": str(outcomes.count("failure")),
        "errors": str(outcomes.count("error") + len(failures)),
    }
    root = ET.Element("testsuites", counts)
    suite_name = _xml_safe(report["suite_name"], attribute=True)
    suite = ET.SubElement(root, "testsuite", {"name": suite_name, **counts})
    for case, outcome in zip(report["cases"], outcomes):
        item = ET.SubElement(
            suite, "testcase", {"classname": f"PolicyDelta.{suite_name}",
                                "name": _xml_safe(case["id"], attribute=True)}
        )
        evidence = [f"{case['method']} {case['path']} · principal {case['principal']}"]
        for variant in ("before", "after"):
            observed = case[variant]
            status = observed["status"] if observed["status"] is not None else "unavailable"
            line = (f"{variant}: expected {case['expect'][variant]}, observed "
                    f"{observed['decision']} (HTTP {status})")
            if observed.get("error"):
                line += f"; error {observed['error']}"
            evidence.append(line)
        if case["findings"]:
            evidence.append("Findings: " + ", ".join(case["findings"]))
        detail = _xml_safe("\n".join(evidence))
        if outcome != "pass":
            message = ("execution error" if outcome == "error" else
                       ", ".join(finding for finding in case["findings"]
                                 if finding in ("expectation mismatch", "unapproved expansion")))
            ET.SubElement(item, outcome, {"message": message}).text = detail
        ET.SubElement(item, "system-out").text = detail
    for number, failure in enumerate(failures, 1):
        detail = _xml_safe(json.dumps(failure, sort_keys=True))
        item = ET.SubElement(suite, "testcase", {
            "classname": f"PolicyDelta.{suite_name}.execution",
            "name": _xml_safe(f"run {number}: {failure['stage']}", attribute=True),
        })
        ET.SubElement(item, "error", {"message": _xml_safe(failure["code"], attribute=True)}).text = detail
    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


def write_reports(report: dict, output: Path) -> None:
    """Fresh directories only; atomic files; remove our incomplete output on failure."""
    payloads = {
        "report.json": json.dumps(report, indent=2, allow_nan=False) + "\n",
        "index.html": render_html(report),
        "junit.xml": render_junit(report),
    }
    output.mkdir(mode=0o700)
    owned = []
    try:
        for name, payload in payloads.items():
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output, delete=False) as stream:
                temporary = Path(stream.name)
                owned.append(temporary)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            destination = output / name
            os.replace(temporary, destination)
            owned.append(destination)
    except BaseException:
        for path in owned:
            path.unlink(missing_ok=True)
        output.rmdir()
        raise
