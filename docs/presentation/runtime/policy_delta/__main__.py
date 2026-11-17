"""Command-line entry point."""
import argparse
import json
from pathlib import Path
import sys

from . import __version__


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare policy revisions by exercising synthetic requests in disposable local OpenBao servers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Exit 0: expectations met; all access expansions explicitly approved.\n"
                "Exit 1: expectation mismatch or unapproved deny-to-allow change.\n"
                "Exit 2: input, execution or report publication could not complete.\n"
                "Only an observed HTTP 403 is a denial. Use synthetic fixtures; case names and paths remain visible.")
    )
    parser.add_argument("suite", type=Path, help="Synthetic JSON suite; policy paths are relative to this file")
    parser.add_argument("--bao", required=True, type=Path, help="Existing OpenBao 2.7.0 executable for owned loopback dev servers")
    parser.add_argument("--output", required=True, type=Path, help="New directory in an existing parent; writes HTML, JSON and JUnit XML")
    parser.add_argument("--version", action="version", version=f"PolicyDelta {__version__}")
    args = parser.parse_args(argv)
    from .suite import load_suite, SuiteError
    from .runner import run_suite, RunError
    from .report import assess, write_reports, VERDICTS
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
    print(f'{VERDICTS[summary["exit_code"]]} (exit {summary["exit_code"]}).')
    print(f'{len(report["cases"])} cases; {summary["expansions"]} newly allowed '
          f'({summary["unapproved_expansions"]} unapproved); '
          f'{summary["mismatches"]} expectation mismatches.')
    print(f'Execution: {report["execution"]["status"]}; {summary["errors"]} case errors; '
          f'{summary["not_run"]} cases not fully run; {summary["run_errors"]} lifecycle errors.')
    print(f'Report: {(args.output / "index.html").resolve()}')
    print(f'Evidence: {(args.output / "report.json").resolve()}')
    print(f'JUnit: {(args.output / "junit.xml").resolve()}')
    return summary["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
