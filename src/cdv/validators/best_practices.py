"""Best practice checks for custom detection rules."""

from __future__ import annotations

from cdv.parser.query_model import ParsedQuery
from cdv.rules.tables import EMAILEVENTS_NRT_EXCLUDED_COLUMNS, classify_table
from cdv.validators.base import (
    BaseValidator,
    Category,
    Severity,
    ValidationResult,
)

DOC_URL = "https://learn.microsoft.com/defender-xdr/custom-detection-rules"


class BestPracticesValidator(BaseValidator):
    def validate(self, parsed: ParsedQuery) -> list[ValidationResult]:
        results: list[ValidationResult] = []

        if not parsed.primary_table:
            return results

        tc = classify_table(parsed.primary_table)

        # BP001: Timestamp filtering
        if parsed.filters_on_timestamp:
            results.append(ValidationResult(
                passed=False,
                severity=Severity.WARNING,
                category=Category.BEST_PRACTICES,
                rule_id="BP001",
                message="Query filters on Timestamp column",
                suggestion=(
                    "Avoid filtering on Timestamp. Custom detection data is "
                    "pre-filtered based on the detection frequency. "
                    "Use ingestion_time() instead for time filtering."
                ),
                doc_url=DOC_URL,
            ))

        # BP002: ingestion_time() usage
        if not parsed.uses_ingestion_time and not parsed.filters_on_timestamp:
            results.append(ValidationResult(
                passed=True,
                severity=Severity.INFO,
                category=Category.BEST_PRACTICES,
                rule_id="BP002",
                message="Consider using ingestion_time() for time-based filtering",
                suggestion=(
                    "For better performance, use 'where ingestion_time() > ago(1d)' "
                    "instead of Timestamp-based filtering."
                ),
                doc_url=DOC_URL,
            ))

        # BP003: Summarize without preserving required columns
        if parsed.has_summarize and not parsed.uses_arg_max_timestamp:
            ts_col = tc.required_timestamp
            summarize_output = set(parsed.summarize_by_columns) | set(parsed.summarize_agg_columns)

            if ts_col not in summarize_output:
                id_cols = list(tc.required_event_id_columns)
                missing = [ts_col] + [c for c in id_cols if c not in summarize_output]
                if missing:
                    results.append(ValidationResult(
                        passed=False,
                        severity=Severity.WARNING,
                        category=Category.BEST_PRACTICES,
                        rule_id="BP003",
                        message=f"'summarize' may lose required column(s): {', '.join(missing)}",
                        suggestion=(
                            f"Use arg_max to preserve columns: "
                            f"summarize ({', '.join(missing)})=arg_max({ts_col}, "
                            f"{', '.join(missing[1:]) if len(missing) > 1 else '...'}"
                            f"), ... by ..."
                        ),
                        doc_url=DOC_URL,
                    ))

        # BP004: Alert limit reminder
        has_filtering = any(
            op in parsed.operators_used
            for op in ("where", "summarize", "distinct", "top", "take", "limit", "sample")
        )
        if not has_filtering:
            results.append(ValidationResult(
                passed=True,
                severity=Severity.INFO,
                category=Category.BEST_PRACTICES,
                rule_id="BP004",
                message="No filtering/aggregation detected",
                suggestion=(
                    "Custom detection rules can generate max 150 alerts per run. "
                    "Consider adding filters to avoid excessive alerts."
                ),
                doc_url=DOC_URL,
            ))

        # BP005: EmailEvents NRT column exclusions
        if parsed.primary_table == "EmailEvents" and tc.supports_nrt:
            excluded_used = [
                col for col in parsed.all_referenced_columns
                if col in EMAILEVENTS_NRT_EXCLUDED_COLUMNS
            ]
            if excluded_used:
                results.append(ValidationResult(
                    passed=False,
                    severity=Severity.WARNING,
                    category=Category.BEST_PRACTICES,
                    rule_id="BP005",
                    message=f"EmailEvents columns not available in NRT: {', '.join(excluded_used)}",
                    suggestion=(
                        "LatestDeliveryLocation and LatestDeliveryAction are excluded "
                        "from NRT mode. If using NRT frequency, these columns will be empty."
                    ),
                    doc_url=DOC_URL,
                ))

        return results
