"""CLI entry point for the Custom Detection Validator."""

from __future__ import annotations

import argparse
import sys

from cdv import __version__
from cdv.output.formatter import format_json, format_terminal
from cdv.validators.engine import ValidationEngine


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cdv",
        description=(
            "Custom Detection Validator - Pre-validate KQL queries for "
            "Microsoft Defender XDR custom detection rules."
        ),
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        "-f", "--file",
        help="Path to a .kql file containing the query",
    )
    input_group.add_argument(
        "-q", "--query",
        help="KQL query string (use quotes)",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show parsed query details for debugging",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Launch web UI in browser (http://127.0.0.1:8471)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8471,
        help="Port for web UI (default: 8471)",
    )

    args = parser.parse_args(argv)

    # Web UI mode
    if args.web:
        from cdv.web import serve
        serve(port=args.port)
        return 0

    # Get query text
    kql_text = _read_query(args)
    if kql_text is None:
        parser.print_help()
        return 2

    kql_text = kql_text.strip()
    if not kql_text:
        print("Error: Empty query", file=sys.stderr)
        return 2

    # Validate
    engine = ValidationEngine()
    report = engine.validate(kql_text)

    # Output
    if args.json_output:
        print(format_json(report))
    else:
        format_terminal(report, no_color=args.no_color, verbose=args.verbose)

    # Exit code
    if report.has_errors:
        return 1
    if report.has_warnings:
        return 2
    return 0


def _read_query(args: argparse.Namespace) -> str | None:
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        except OSError as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)

    if args.query:
        return args.query

    # Try stdin
    if not sys.stdin.isatty():
        return sys.stdin.read()

    return None


if __name__ == "__main__":
    sys.exit(main())
