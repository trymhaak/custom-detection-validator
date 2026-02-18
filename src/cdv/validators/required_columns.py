"""Validate required columns for custom detection rules."""

from __future__ import annotations

from cdv.parser.query_model import ParsedQuery
from cdv.rules.columns import IMPACTED_ASSET_COLUMNS
from cdv.rules.tables import classify_table
from cdv.validators.base import (
    BaseValidator,
    Category,
    Severity,
    ValidationResult,
)

DOC_URL = "https://learn.microsoft.com/defender-xdr/custom-detection-rules#required-columns-in-the-query-results"


class RequiredColumnsValidator(BaseValidator):
    def validate(self, parsed: ParsedQuery) -> list[ValidationResult]:
        results: list[ValidationResult] = []

        if not parsed.primary_table:
            return results

        tc = classify_table(parsed.primary_table)
        output_columns = self._get_output_columns(parsed)

        # RC001: Timestamp / TimeGenerated present
        ts_col = tc.required_timestamp
        ts_present = self._column_present(ts_col, output_columns, parsed)
        if ts_present:
            results.append(ValidationResult(
                passed=True,
                severity=Severity.ERROR,
                category=Category.REQUIRED_COLUMNS,
                rule_id="RC001",
                message=f"{ts_col} column present",
            ))
        else:
            results.append(ValidationResult(
                passed=False,
                severity=Severity.ERROR,
                category=Category.REQUIRED_COLUMNS,
                rule_id="RC001",
                message=f"{ts_col} column missing from query output",
                suggestion=f"Add '{ts_col}' to your project statement or remove the project to include all columns",
                doc_url=DOC_URL,
            ))

        # RC002: Timestamp not manipulated
        if parsed.timestamp_manipulated:
            results.append(ValidationResult(
                passed=False,
                severity=Severity.ERROR,
                category=Category.REQUIRED_COLUMNS,
                rule_id="RC002",
                message=f"{ts_col} appears to be manipulated (assigned a new value)",
                suggestion=f"Return {ts_col} exactly as it appears in the raw event. Do not use 'extend {ts_col} = ...' or 'project {ts_col} = ...'",
                doc_url=DOC_URL,
            ))
        else:
            results.append(ValidationResult(
                passed=True,
                severity=Severity.ERROR,
                category=Category.REQUIRED_COLUMNS,
                rule_id="RC002",
                message=f"{ts_col} is not manipulated",
            ))

        # RC003: Event identification columns
        if tc.required_event_id_columns:
            missing_id_cols = []
            for col in tc.required_event_id_columns:
                if not self._column_present(col, output_columns, parsed):
                    missing_id_cols.append(col)

            if missing_id_cols:
                results.append(ValidationResult(
                    passed=False,
                    severity=Severity.ERROR,
                    category=Category.REQUIRED_COLUMNS,
                    rule_id="RC003",
                    message=f"Missing event ID column(s): {', '.join(missing_id_cols)}",
                    suggestion=(
                        f"For {tc.category} tables, the query must return: "
                        f"{ts_col} + {', '.join(tc.required_event_id_columns)}"
                    ),
                    doc_url=DOC_URL,
                ))
            else:
                results.append(ValidationResult(
                    passed=True,
                    severity=Severity.ERROR,
                    category=Category.REQUIRED_COLUMNS,
                    rule_id="RC003",
                    message=f"Event ID columns present: {ts_col} + {', '.join(tc.required_event_id_columns)}",
                ))
        else:
            results.append(ValidationResult(
                passed=True,
                severity=Severity.ERROR,
                category=Category.REQUIRED_COLUMNS,
                rule_id="RC003",
                message=f"Event ID: only {ts_col} required for {tc.category} tables",
            ))

        # RC004: At least one impacted asset column
        found_assets = [
            col for col in output_columns
            if col in IMPACTED_ASSET_COLUMNS
        ]
        if found_assets or parsed.has_implicit_columns:
            if parsed.has_implicit_columns:
                msg = "Impacted asset columns available (all columns returned implicitly)"
            else:
                msg = f"Impacted asset column(s): {', '.join(found_assets)}"
            results.append(ValidationResult(
                passed=True,
                severity=Severity.ERROR,
                category=Category.REQUIRED_COLUMNS,
                rule_id="RC004",
                message=msg,
            ))
        else:
            results.append(ValidationResult(
                passed=False,
                severity=Severity.ERROR,
                category=Category.REQUIRED_COLUMNS,
                rule_id="RC004",
                message="No impacted asset column found in query output",
                suggestion=(
                    "Add at least one of: "
                    + ", ".join(sorted(IMPACTED_ASSET_COLUMNS))
                ),
                doc_url=DOC_URL,
            ))

        # RC005: Summarize losing Timestamp
        if parsed.has_summarize and not parsed.uses_arg_max_timestamp:
            ts_in_by = ts_col in parsed.summarize_by_columns
            ts_in_agg = ts_col in parsed.summarize_agg_columns
            if not ts_in_by and not ts_in_agg and not parsed.has_project:
                results.append(ValidationResult(
                    passed=False,
                    severity=Severity.WARNING,
                    category=Category.REQUIRED_COLUMNS,
                    rule_id="RC005",
                    message=f"'summarize' may drop {ts_col} from output",
                    suggestion=(
                        f"Use arg_max to preserve {ts_col}: "
                        f"summarize ({ts_col}, ReportId)=arg_max({ts_col}, ReportId), ... by ..."
                    ),
                    doc_url=DOC_URL,
                ))

        # RC006: Project removing required columns
        if parsed.has_project and parsed.projected_columns:
            all_required = {ts_col} | set(tc.required_event_id_columns)
            projected_set = set(parsed.projected_columns)
            missing = all_required - projected_set

            if missing and not parsed.has_summarize:
                results.append(ValidationResult(
                    passed=False,
                    severity=Severity.ERROR,
                    category=Category.REQUIRED_COLUMNS,
                    rule_id="RC006",
                    message=f"'project' excludes required column(s): {', '.join(sorted(missing))}",
                    suggestion=f"Add {', '.join(sorted(missing))} to your project statement",
                    doc_url=DOC_URL,
                ))

        # RC007: Project-away removing required columns
        if parsed.has_project_away and parsed.project_away_columns:
            all_required = {ts_col} | set(tc.required_event_id_columns)
            removed = set(parsed.project_away_columns) & all_required

            if removed:
                results.append(ValidationResult(
                    passed=False,
                    severity=Severity.ERROR,
                    category=Category.REQUIRED_COLUMNS,
                    rule_id="RC007",
                    message=f"'project-away' removes required column(s): {', '.join(sorted(removed))}",
                    suggestion=f"Do not remove {', '.join(sorted(removed))} with project-away",
                    doc_url=DOC_URL,
                ))

        return results

    def _get_output_columns(self, parsed: ParsedQuery) -> set[str]:
        """Determine the set of columns in the query output."""
        if parsed.projected_columns:
            return set(parsed.projected_columns)
        if parsed.has_implicit_columns:
            # All table columns are returned - use all referenced columns as proxy
            return set(parsed.all_referenced_columns)
        return set(parsed.all_referenced_columns)

    def _column_present(
        self,
        column: str,
        output_columns: set[str],
        parsed: ParsedQuery,
    ) -> bool:
        """Check if a column is present in the output."""
        if parsed.has_implicit_columns:
            return True  # All columns from table are included
        return column in output_columns
