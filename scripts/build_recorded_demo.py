"""Package retained synthetic evidence for a read-only Pages preview."""

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOTICE = (
    '<aside class="scope" aria-label="Recorded example">'
    '<strong>Recorded synthetic example.</strong> Retained OpenBao 2.7.0 results; '
    'this page does not evaluate policies. '
    '<a href="https://github.com/nazeeh111/PolicyDelta#try-the-example">'
    'Run the example locally</a>. '
    '<a href="junit.xml">JUnit evidence</a>.</aside>'
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New output directory")
    output = parser.parse_args().output
    payloads = {".nojekyll": b""}
    for directory, prefix in (("example", ""), ("current-example", "current/")):
        source = ROOT / "docs" / directory
        page = (source / "index.html").read_text(encoding="utf-8")
        if page.count("</header>") != 1:
            raise ValueError(f"Expected one report header in {directory}; inspect the recorded template")
        payloads[prefix + "index.html"] = page.replace("</header>", "</header>" + NOTICE).encode("utf-8")
        for name in ("report.json", "junit.xml"):
            payloads[prefix + name] = (source / name).read_bytes()
    output.mkdir(parents=True)
    for name, content in payloads.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    print(f"Recorded example: {output / 'index.html'}")


if __name__ == "__main__":
    main()
