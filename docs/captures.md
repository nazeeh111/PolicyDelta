# Current recorded report and captures

The current example retains an actual synthetic 11-case OpenBao 2.7.0 run from installed PolicyDelta **0.2.2.dev0**, wheel SHA-256 `5784ffc1729280cc9907b31f522b1416acb0f817e7ddc37a1ce4a45d0845464b`. The report uses schema **2**, records `execution.status: completed`, and exits **1** for four unapproved deny-to-allow expansions. These are deliberate policy-change findings, not runtime failures. No engine was rerun to add these files or images. The final documentation-bearing wheel has a different metadata identity while retaining the same CLI and report-renderer bytes.

The [HTML](current-example/index.html), [JSON](current-example/report.json) and [JUnit XML](current-example/junit.xml) are exact retained output bytes. The Pages preview adds a recorded-example notice to its copy of the HTML; its JSON and JUnit remain exact. The earlier `docs/example/` reports and their original live demo are historical and unchanged.

The unmodified [desktop capture](images/current-report-0.2.2-dev.png) is 1280 × 633 pixels. The [phone capture](images/current-report-phone-0.2.2-dev.png) uses a 390 × 844 CSS-pixel viewport and shows the focused comparison table panned 49 pixels to the right. It intentionally clips columns within that scroll region. The document remains 390 pixels wide; the table region is 354 pixels wide with 840 pixels of content. Two actual ArrowRight key presses moved its scroll position from 0 to 49.

Both captures were inspected from the running report in an isolated, headless **Chrome 157** session on 2026-11-16. The scroll region has `role="region"`, `tabindex="0"` and the label “Request comparison, scroll horizontally on narrow screens.” These checks establish the observed desktop/phone rendering and keyboard scroll behavior. They do not certify assistive-technology support, physical-device behavior or complete accessibility. The automatic scan left obscured/offscreen color contrast unresolved.

## Reproduce with an existing engine

Use a trusted current-source installation and an already available OpenBao 2.7.0 executable. This recipe acquires no runtime automatically:

```sh
policy-delta --version
policy-delta examples/expansion.json --bao /absolute/path/to/existing/bao --output review-expansion-current
```

Exit 1 is expected for the four unapproved expansions. Open `review-expansion-current/index.html` beside its `report.json` and `junit.xml`. To view the retained evidence without running OpenBao, serve `docs/current-example/` with a local HTTP server or open its HTML directly. At 390 CSS pixels, focus the comparison region and press ArrowRight to reveal the remaining columns. Use a new output directory for any rerun. Different environments are new observations and should retain their own evidence.

## Exact identities

| Artifact | SHA-256 |
| --- | --- |
| `current-example/index.html` | `d6fb0c5828f76b8ee0f7dcbd37bd96e68584c091007b2d8839de7ad9e521a7dd` |
| `current-example/report.json` | `38e671a6ff1bd612e81c3da6a713de43e4856aecc1e05e2491b2981227ab3b92` |
| `current-example/junit.xml` | `87bf8d957f48bd0d3aaee8650de9b9d10c71c103e50151505cfd2091dd958d16` |
| `images/current-report-0.2.2-dev.png` | `7d48378b3b9b511965557d58d777764db9d972b9f68ab891002d33924cf0e0a7` |
| `images/current-report-phone-0.2.2-dev.png` | `7c51f49a015fdf0a45de79439d95bdf85f6355dca1c43d72e5879247be1aa2f8` |
| Renderer `policy_delta/report.py` | `f98ed5addbc452b0dec750e08ecebf5b8ba18c86d54780850faccf2e4d03afdc` |

Hashes identify bytes, not producer authenticity or universal policy safety. Reports contain synthetic case names and paths; the supported runner omits tokens, bodies and returned values.
