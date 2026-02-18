"""Validate columns that are not supported in custom detection rules.

Source: https://learn.microsoft.com/defender-xdr/custom-detection-rules
        https://learn.microsoft.com/defender-xdr/advanced-hunting-emailevents-table

Known restrictions:
- EmailEvents NRT: LatestDeliveryLocation and LatestDeliveryAction are
  excluded from Continuous (NRT) frequency.
- General: "Only columns that are generally available support
  Continuous (NRT) frequency."
"""

from __future__ import annotations

from cdv.parser.query_model import ParsedQuery
from cdv.rules.columns import NON_SUPPORTED_NRT_COLUMNS
from cdv.rules.tables import NRT_SUPPORTED_XDR, NRT_SUPPORTED_SENTINEL
from cdv.validators.base import (
    BaseValidator,
    Category,
    Severity,
    ValidationResult,
)

DOC_URL_NRT = "https://learn.microsoft.com/defender-xdr/custom-detection-rules#continuous-nrt-frequency"
DOC_URL_EMAIL = "https://learn.microsoft.com/defender-xdr/advanced-hunting-emailevents-table"


class NonSupportedColumnsValidator(BaseValidator):
    """Check for columns that have known restrictions in custom detection rules."""

    def validate(self, parsed: ParsedQuery) -> list[ValidationResult]:
        results: list[ValidationResult] = []

        if not parsed.primary_table:
            return results

        table = parsed.primary_table
        output_cols = self._get_output_columns(parsed)

        # NSC001: Check for NRT-excluded columns (e.g., EmailEvents)
        nrt_excluded = NON_SUPPORTED_NRT_COLUMNS.get(table, set())
        if nrt_excluded:
            found_excluded = output_cols & nrt_excluded
            if found_excluded:
                cols_str = ", ".join(sorted(found_excluded))
                results.append(ValidationResult(
                    passed=False,
                    severity=Severity.WARNING,
                    category=Category.NON_SUPPORTED_COLUMNS,
                    rule_id="NSC001",
                    message=f"NRT-excluded column(s) in output: {cols_str}",
                    suggestion=(
                        f"{cols_str} {'is' if len(found_excluded) == 1 else 'are'} "
                        f"not supported in Continuous (NRT) frequency for {table}. "
                        f"Remove {'it' if len(found_excluded) == 1 else 'them'} "
                        f"or use scheduled frequency."
                    ),
                    doc_url=DOC_URL_NRT,
                ))
            else:
                results.append(ValidationResult(
                    passed=True,
                    severity=Severity.WARNING,
                    category=Category.NON_SUPPORTED_COLUMNS,
                    rule_id="NSC001",
                    message=f"No NRT-excluded columns used for {table}",
                ))

        # NSC002: General NRT column support note
        # "Only columns that are generally available support Continuous (NRT) frequency."
        is_nrt_table = (
            table in NRT_SUPPORTED_XDR or table in NRT_SUPPORTED_SENTINEL
        )
        if is_nrt_table:
            results.append(ValidationResult(
                passed=True,
                severity=Severity.INFO,
                category=Category.NON_SUPPORTED_COLUMNS,
                rule_id="NSC002",
                message=(
                    f"NRT note: Only GA columns support Continuous (NRT) frequency. "
                    f"Preview-only columns may not work with NRT for {table}."
                ),
                doc_url=DOC_URL_NRT,
            ))

        # NSC003: EmailEvents Streaming API note
        if table == "EmailEvents":
            streaming_excluded = {"LatestDeliveryLocation", "LatestDeliveryAction"}
            found_streaming = output_cols & streaming_excluded
            if found_streaming:
                cols_str = ", ".join(sorted(found_streaming))
                results.append(ValidationResult(
                    passed=False,
                    severity=Severity.INFO,
                    category=Category.NON_SUPPORTED_COLUMNS,
                    rule_id="NSC003",
                    message=f"Streaming API excluded: {cols_str}",
                    suggestion=(
                        f"{cols_str} {'is' if len(found_streaming) == 1 else 'are'} "
                        f"not available in the Streaming API for EmailEvents."
                    ),
                    doc_url=DOC_URL_EMAIL,
                ))

        return results

    def _get_output_columns(self, parsed: ParsedQuery) -> set[str]:
        """Determine the set of columns in the query output."""
        if parsed.projected_columns:
            return set(parsed.projected_columns)
        # If no explicit project, check all referenced columns
        return set(parsed.all_referenced_columns)
