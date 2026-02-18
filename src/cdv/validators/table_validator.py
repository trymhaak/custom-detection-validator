"""Table validation: check if table is known and classify it."""

from __future__ import annotations

from cdv.parser.query_model import ParsedQuery
from cdv.rules.tables import (
    CATEGORY_DISPLAY_NAMES,
    classify_table,
)
from cdv.validators.base import (
    BaseValidator,
    Category,
    Severity,
    ValidationResult,
)

DOC_URL = "https://learn.microsoft.com/defender-xdr/custom-detection-rules"


class TableValidator(BaseValidator):
    def validate(self, parsed: ParsedQuery) -> list[ValidationResult]:
        results: list[ValidationResult] = []

        if not parsed.primary_table:
            results.append(ValidationResult(
                passed=False,
                severity=Severity.ERROR,
                category=Category.TABLE,
                rule_id="TBL001",
                message="No table found in query",
                suggestion="Query must start with a table name, e.g., 'DeviceEvents | where ...'",
                doc_url=DOC_URL,
            ))
            return results

        tc = classify_table(parsed.primary_table)

        # TBL001: Is it a known table?
        if tc.category == "unknown":
            results.append(ValidationResult(
                passed=False,
                severity=Severity.WARNING,
                category=Category.TABLE,
                rule_id="TBL001",
                message=f"'{parsed.primary_table}' is not a known Advanced Hunting table",
                suggestion=(
                    "If this is a custom Sentinel table, use the _CL suffix. "
                    "Otherwise, check the table name for typos."
                ),
                doc_url=DOC_URL,
            ))
        else:
            results.append(ValidationResult(
                passed=True,
                severity=Severity.INFO,
                category=Category.TABLE,
                rule_id="TBL001",
                message=f"'{parsed.primary_table}' is a known table",
            ))

        # TBL002: Table classification and requirements
        category_name = CATEGORY_DISPLAY_NAMES.get(tc.category, tc.category)
        required_cols = [tc.required_timestamp]
        if tc.required_event_id_columns:
            required_cols.extend(tc.required_event_id_columns)

        results.append(ValidationResult(
            passed=True,
            severity=Severity.INFO,
            category=Category.TABLE,
            rule_id="TBL002",
            message=(
                f"Table category: {category_name}. "
                f"Required columns: {', '.join(required_cols)}"
            ),
        ))

        # TBL003: NRT vs Scheduled support
        if tc.supports_nrt:
            freq_msg = "Supports both NRT (Continuous) and Scheduled frequency"
        else:
            freq_msg = "Supports Scheduled frequency only (not NRT-eligible)"

        results.append(ValidationResult(
            passed=True,
            severity=Severity.INFO,
            category=Category.TABLE,
            rule_id="TBL003",
            message=freq_msg,
        ))

        return results
