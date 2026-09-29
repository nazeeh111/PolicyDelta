"""Classify observed requests and render a portable, value-free review artifact."""
from copy import deepcopy
from html import escape
import json
import os
from pathlib import Path
import tempfile
from xml.etree import ElementTree as ET


def assess(report: dict) -> dict:
    result = deepcopy(report)
    totals = dict(errors=0, mismatches=0, expansions=0, unapproved_expansions=0,
                  restrictions=0, capability_invisible_expansions=0)
    for case in result["cases"]:
        before, after = case["before"], case["after"]
        findings = []
        if "error" in (before["decision"], after["decision"]):
            totals["errors"] += 1
            findings.append("execution error")
        if any(case[v]["decision"] != case["expect"][v] for v in ("before", "after")):
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
    totals["exit_code"] = 2 if totals["errors"] else 1 if totals["mismatches"] or totals["unapproved_expansions"] else 0
    result["summary"] = totals
    return result


def render_html(report: dict) -> str:
    def e(value):
        return escape(str(value), quote=True)

    def observation(case, variant):
        observed = case[variant]
        decision = observed["decision"]
        tone = decision if decision in {"allow", "deny", "error"} else "error"
        capabilities = ", ".join(observed["capabilities"]) or "none reported"
        error = f'<br><span class="error">{e(observed["error"])}</span>' if observed.get("error") else ""
        return (f'<span class="decision {tone}">{e(decision)}</span> '
                f'<span class="code">HTTP {e(observed["status"] if observed["status"] is not None else "unavailable")}</span>'
                f'<div class="detail">Expected {e(case["expect"][variant])}<br>Capabilities: {e(capabilities)}{error}</div>')

    rows = []
    for case in report["cases"]:
        findings = "<br>".join(e(item) for item in case["findings"]) or "Expectations met"
        rows.append(
            f'<tr><th scope="row">{e(case["id"])}<span class="detail">{e(case["principal"])}</span></th>'
            f'<td><b class="method">{e(case["method"])}</b><code>{e(case["path"])}</code></td>'
            f'<td>{observation(case, "before")}</td><td>{observation(case, "after")}</td><td>{findings}</td></tr>'
        )
    summary = report["summary"]
    verdict = {0: "Expectations met", 1: "Policy change needs review", 2: "Execution incomplete"}[summary["exit_code"]]
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
.scroll-hint{{display:none}}.table-wrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;text-align:left;min-width:840px}}thead{{font-size:11px;letter-spacing:.06em;text-transform:uppercase}}th,td{{padding:17px 12px;vertical-align:top;border-bottom:1px solid var(--line)}}th:first-child,td:first-child{{padding-left:0}}tbody th{{font-weight:650;min-width:135px}}tbody tr:hover{{background:#eeeee5}}td{{font-size:13px}}code,.code{{font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}}td code{{display:block;margin-top:6px;max-width:250px}}.method{{font-size:11px}}.detail{{display:block;color:var(--muted);font-size:12px;font-weight:400;margin-top:8px}}.decision{{font-weight:750;text-transform:uppercase;font-size:11px;letter-spacing:.03em;margin-right:5px}}.allow{{color:#216846}}.deny{{color:#7c3f24}}.error{{color:#a52029}}
.scope{{max-width:830px;font-size:13px;color:var(--muted);margin:28px 0}}details{{border-top:1px solid var(--line);padding-top:16px}}summary{{cursor:pointer;font-weight:650}}dl{{display:grid;grid-template-columns:minmax(120px,220px) 1fr;gap:8px 20px;font-size:12px}}dd{{margin:0;min-width:0}}footer{{font-size:12px;color:var(--muted);margin-top:30px}}@media(max-width:700px){{.scroll-hint{{display:block;font-size:12px;color:var(--muted)}}main{{padding:24px 18px}}header{{align-items:center;font-size:12px}}h1{{letter-spacing:-.6px}}dl{{display:block}}dd{{margin-bottom:12px}}}}
</style></head><body><main><header><span class="brand">PolicyDelta</span><a href="report.json">Read the JSON evidence</a></header>
<section class="intro"><div class="eyebrow">Before / after policy review</div><h1>{e(report["suite_name"])}</h1><span class="detail">{e(report["engine_version"])} · Disposable local servers · {len(report["cases"])} declared requests</span></section>
<section class="verdict"><h2>{e(verdict)}</h2><span class="counts">{summary["expansions"]} newly allowed · {summary["restrictions"]} newly denied · {summary["mismatches"]} expectation mismatches · {summary["errors"]} execution errors</span></section>
<p class="scroll-hint">Scroll horizontally to compare the two revisions.</p>
<div class="table-wrap" tabindex="0" role="region" aria-label="Request comparison, scroll horizontally on narrow screens"><table><thead><tr><th scope="col">Case / principal</th><th scope="col">Request</th><th scope="col">Before</th><th scope="col">After</th><th scope="col">Finding</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
<p class="scope">Results cover these declared requests and fixtures. They do not establish all possible access, production behavior, or complete policy safety. A deny requires HTTP 403; missing data, setup failures, and other errors do not count as successful denial tests. Request bodies, returned secret values, and tokens are excluded from this report.</p>
<details><summary>Input identities</summary><dl><dt>Suite SHA-256</dt><dd><code>{e(report["suite_sha256"])}</code></dd>{hashes}</dl></details>
<footer>Exit code {summary["exit_code"]}. {summary["capability_invisible_expansions"]} newly allowed request(s) have unchanged capability lists.</footer></main></body></html>'''


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
    counts = {
        "tests": str(len(outcomes)),
        "failures": str(outcomes.count("failure")),
        "errors": str(outcomes.count("error")),
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
