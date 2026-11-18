"""Command line entry point.

Exit codes follow the usual monitoring convention: 0 means no problem worth
acting on, 1 means at least one warning or critical finding, 2 is reserved for
the auditor itself failing. ``info`` findings never change the exit code.
"""

import argparse
import json
import sys

from .auditor import audit

# The exit code a finding severity contributes to.
_EXIT_BY_SEVERITY = {"critical": 1, "warning": 1, "info": 0}


def _parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="volt-watch",
        description="Audit a Tailscale-managed Linux host for health and safety problems.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the findings as JSON instead of plain text",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the plain-text report; the exit code still reports problems",
    )
    return parser.parse_args(argv)


def _counts(findings):
    counts = {"total": len(findings), "critical": 0, "warning": 0, "info": 0}
    for finding in findings:
        counts[finding["severity"]] += 1
    return counts


def _report(findings):
    for finding in findings:
        print(f"{finding['severity']:<9} {finding['check']}: {finding['message']}")
        if finding["remedy"]:
            print(f"          remedy: {finding['remedy']}")
    print(f"{len(findings)} finding(s)")


def main(argv=None, findings=None) -> int:
    """Run the audit and print the report.

    ``findings`` is a test seam: when supplied, the audit is skipped and those
    findings are reported instead.
    """
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    if findings is None:
        findings = [f.as_dict() for f in audit()]

    counts = _counts(findings)

    if args.json:
        print(json.dumps({"findings": findings, "counts": counts}, indent=2))
    elif not args.quiet:
        _report(findings)

    worst = max((_EXIT_BY_SEVERITY[f["severity"]] for f in findings), default=0)
    return worst


if __name__ == "__main__":
    sys.exit(main())
