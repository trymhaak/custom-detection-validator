"""Output formatting: terminal and JSON."""

from __future__ import annotations

import json
import os
import sys
from typing import TextIO

from cdv import __version__
from cdv.validators.base import Category, Severity, ValidationReport


# ANSI color codes
class _Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


class _NoColors:
    RED = ""
    GREEN = ""
    YELLOW = ""
    CYAN = ""
    BOLD = ""
    DIM = ""
    RESET = ""


def _should_use_color(no_color_flag: bool) -> bool:
    if no_color_flag:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty"):
        return False
    return sys.stdout.isatty()


def format_terminal(
    report: ValidationReport,
    no_color: bool = False,
    verbose: bool = False,
    out: TextIO | None = None,
) -> None:
    """Format and print validation results to terminal."""
    if out is None:
        out = sys.stdout

    c = _Colors() if _should_use_color(no_color) else _NoColors()

    # Header
    out.write(f"\n{c.BOLD}{'=' * 55}{c.RESET}\n")
    out.write(f"{c.BOLD}  Custom Detection Validator  v{__version__}{c.RESET}\n")
    out.write(f"{c.BOLD}{'=' * 55}{c.RESET}\n\n")

    # Query info
    parsed = report.parsed_query
    if parsed:
        if parsed.primary_table:
            out.write(f"  Source table:  {c.BOLD}{parsed.primary_table}{c.RESET}")
            if len(parsed.source_tables) > 1:
                others = ", ".join(parsed.source_tables[1:])
                out.write(f" (+ {others})")
            out.write("\n")

        if parsed.projected_columns:
            cols = ", ".join(parsed.projected_columns[:8])
            if len(parsed.projected_columns) > 8:
                cols += f" (+{len(parsed.projected_columns) - 8} more)"
            out.write(f"  Output columns: {cols}\n")
        elif parsed.has_implicit_columns:
            out.write(f"  Output columns: {c.DIM}all (no explicit project){c.RESET}\n")

    out.write("\n")

    # Group results by category
    categories = [
        (Category.TABLE, "Table"),
        (Category.REQUIRED_COLUMNS, "Required Columns"),
        (Category.NON_SUPPORTED_COLUMNS, "Non-Supported Columns"),
        (Category.NRT_ELIGIBILITY, "NRT Eligibility"),
        (Category.ACTION_REQUIREMENTS, "Available Actions"),
        (Category.BEST_PRACTICES, "Best Practices"),
    ]

    for cat, cat_name in categories:
        cat_results = [r for r in report.results if r.category == cat]
        if not cat_results:
            continue

        out.write(f"  {c.BOLD}--- {cat_name} {'-' * (45 - len(cat_name))}{c.RESET}\n\n")

        for r in cat_results:
            if r.passed:
                icon = f"{c.GREEN}PASS{c.RESET}"
            elif r.severity == Severity.ERROR:
                icon = f"{c.RED}FAIL{c.RESET}"
            elif r.severity == Severity.WARNING:
                icon = f"{c.YELLOW}WARN{c.RESET}"
            else:
                icon = f"{c.CYAN}INFO{c.RESET}"

            out.write(f"    {icon}  {r.rule_id}  {r.message}\n")
            if r.suggestion:
                for line in r.suggestion.split("\n"):
                    out.write(f"          {c.DIM}{line}{c.RESET}\n")

        out.write("\n")

    # Verbose: show parsed query details
    if verbose and parsed:
        out.write(f"  {c.BOLD}--- Debug Info {'-' * 37}{c.RESET}\n\n")
        out.write(f"    Tables: {parsed.source_tables}\n")
        out.write(f"    Projected: {parsed.projected_columns}\n")
        out.write(f"    Operators: {parsed.operators_used}\n")
        out.write(f"    Has join: {parsed.has_join}\n")
        out.write(f"    Has union: {parsed.has_union}\n")
        out.write(f"    Has summarize: {parsed.has_summarize}\n")
        out.write(f"    Has project: {parsed.has_project}\n")
        out.write(f"    Has comments: {parsed.has_comments}\n")
        out.write(f"    Implicit columns: {parsed.has_implicit_columns}\n")
        out.write(f"    Filters on Timestamp: {parsed.filters_on_timestamp}\n")
        out.write(f"    Timestamp manipulated: {parsed.timestamp_manipulated}\n")
        out.write(f"    Uses arg_max(Timestamp): {parsed.uses_arg_max_timestamp}\n")
        out.write("\n")

    # Summary
    out.write(f"{c.BOLD}{'=' * 55}{c.RESET}\n")
    err = report.error_count
    warn = report.warning_count
    if err > 0:
        out.write(f"  {c.RED}Result: {err} error(s), {warn} warning(s){c.RESET}\n")
    elif warn > 0:
        out.write(f"  {c.YELLOW}Result: 0 errors, {warn} warning(s){c.RESET}\n")
    else:
        out.write(f"  {c.GREEN}Result: All checks passed{c.RESET}\n")
    out.write(f"{c.BOLD}{'=' * 55}{c.RESET}\n\n")


def format_json(report: ValidationReport) -> str:
    """Format validation results as JSON."""
    parsed = report.parsed_query

    nrt_results = [r for r in report.results if r.category == Category.NRT_ELIGIBILITY]
    nrt_eligible = all(r.passed for r in nrt_results) if nrt_results else False

    data = {
        "version": __version__,
        "source_tables": parsed.source_tables if parsed else [],
        "primary_table": parsed.primary_table if parsed else "",
        "projected_columns": parsed.projected_columns if parsed else [],
        "implicit_columns": parsed.has_implicit_columns if parsed else False,
        "results": [
            {
                "passed": r.passed,
                "severity": r.severity.value,
                "category": r.category.value,
                "rule_id": r.rule_id,
                "message": r.message,
                "suggestion": r.suggestion,
                "doc_url": r.doc_url,
            }
            for r in report.results
        ],
        "summary": {
            "errors": report.error_count,
            "warnings": report.warning_count,
            "info": report.info_count,
            "nrt_eligible": nrt_eligible,
        },
    }

    return json.dumps(data, indent=2)
