"""Command-line entry point."""
import argparse
import json
from pathlib import Path
import sys

from . import __version__


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compare real OpenBao requests against two policy revisions in disposable local servers.")
    parser.add_argument("suite", type=Path, help="JSON fixture suite")
    parser.add_argument("--bao", required=True, type=Path, help="OpenBao 2.7.0 executable")
    parser.add_argument("--output", required=True, type=Path, help="New report directory; existing paths are never overwritten")
    parser.add_argument("--version", action="version", version=f"PolicyDelta {__version__}")
    args = parser.parse_args(argv)
    from .suite import load_suite, SuiteError
    from .runner import run_suite, RunError
    from .report import assess, write_reports
    try:
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("Output path already exists; choose a new report directory.")
        suite = load_suite(args.suite)
        report = assess(run_suite(suite, args.bao))
        write_reports(report, args.output)
    except (SuiteError, RunError, ValueError, OSError) as error:
        print(f"PolicyDelta: {error}", file=sys.stderr)
        if isinstance(error, RunError) and error.startup_diagnostics is not None:
            print("PolicyDelta startup: " + json.dumps(error.startup_diagnostics, sort_keys=True),
                  file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("PolicyDelta: interrupted; owned server cleanup requested.", file=sys.stderr)
        return 2
    summary = report["summary"]
    print(f'{len(report["cases"])} cases; {summary["expansions"]} newly allowed; '
          f'{summary["mismatches"]} expectation mismatches; {summary["errors"]} errors.')
    print(f'Report: {(args.output / "index.html").resolve()}')
    return summary["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
