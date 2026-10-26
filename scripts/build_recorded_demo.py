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
    source = ROOT / "docs" / "example"
    page = (source / "index.html").read_text(encoding="utf-8")
    if page.count("</header>") != 1:
        raise ValueError("Expected one report header; inspect the recorded template")
    payloads = {
        "index.html": page.replace("</header>", "</header>" + NOTICE).encode("utf-8"),
        "report.json": (source / "report.json").read_bytes(),
        "junit.xml": (source / "junit.xml").read_bytes(),
        ".nojekyll": b"",
    }
    output.mkdir(parents=True)
    for name, content in payloads.items():
        (output / name).write_bytes(content)
    print(f"Recorded example: {output / 'index.html'}")


if __name__ == "__main__":
    main()
