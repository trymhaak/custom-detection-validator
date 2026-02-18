"""Validate NRT (Continuous/Near Real-Time) frequency eligibility."""

from __future__ import annotations

from cdv.parser.query_model import ParsedQuery
from cdv.rules.columns import NON_SUPPORTED_NRT_COLUMNS
from cdv.rules.tables import (
    NRT_SUPPORTED_SENTINEL,
    NRT_SUPPORTED_XDR,
    classify_table,
)
from cdv.validators.base import (
    BaseValidator,
    Category,
    Severity,
    ValidationResult,
)

DOC_URL = "https://learn.microsoft.com/defender-xdr/custom-detection-rules#continuous-nrt-frequency"


class NrtEligibilityValidator(BaseValidator):
    def validate(self, parsed: ParsedQuery) -> list[ValidationResult]:
        results: list[ValidationResult] = []

        if not parsed.primary_table:
            return results

        # NRT001: Single table only
        if len(parsed.source_tables) == 1:
            results.append(ValidationResult(
                passed=True,
                severity=Severity.ERROR,
                category=Category.NRT_ELIGIBILITY,
                rule_id="NRT001",
                message="Single table query",
            ))
        else:
            results.append(ValidationResult(
                passed=False,
                severity=Severity.ERROR,
                category=Category.NRT_ELIGIBILITY,
                rule_id="NRT001",
                message=f"Query references {len(parsed.source_tables)} tables: {', '.join(parsed.source_tables)}",
                suggestion="NRT requires exactly one table. Remove joins/unions.",
                doc_url=DOC_URL,
            ))

        # NRT002: No join
        if parsed.has_join:
            results.append(ValidationResult(
                passed=False,
                severity=Severity.ERROR,
                category=Category.NRT_ELIGIBILITY,
                rule_id="NRT002",
                message="Query uses 'join' operator",
                suggestion="NRT does not support joins. Use scheduled frequency instead.",
                doc_url=DOC_URL,
            ))
        else:
            results.append(ValidationResult(
                passed=True,
                severity=Severity.ERROR,
                category=Category.NRT_ELIGIBILITY,
                rule_id="NRT002",
                message="No joins",
            ))

        # NRT003: No union
        if parsed.has_union:
            results.append(ValidationResult(
                passed=False,
                severity=Severity.ERROR,
                category=Category.NRT_ELIGIBILITY,
                rule_id="NRT003",
                message="Query uses 'union' operator",
                suggestion="NRT does not support unions. Use scheduled frequency instead.",
                doc_url=DOC_URL,
            ))
        else:
            results.append(ValidationResult(
                passed=True,
                severity=Severity.ERROR,
                category=Category.NRT_ELIGIBILITY,
                rule_id="NRT003",
                message="No unions",
            ))

        # NRT004: No externaldata
        if parsed.has_externaldata:
            results.append(ValidationResult(
                passed=False,
                severity=Severity.ERROR,
                category=Category.NRT_ELIGIBILITY,
                rule_id="NRT004",
                message="Query uses 'externaldata' operator",
                suggestion="NRT does not support externaldata. Use scheduled frequency instead.",
                doc_url=DOC_URL,
            ))
        else:
            results.append(ValidationResult(
                passed=True,
                severity=Severity.ERROR,
                category=Category.NRT_ELIGIBILITY,
                rule_id="NRT004",
                message="No externaldata",
            ))

        # NRT005: No comments
        if parsed.has_comments:
            results.append(ValidationResult(
                passed=False,
                severity=Severity.ERROR,
                category=Category.NRT_ELIGIBILITY,
                rule_id="NRT005",
                message="Query contains comment lines",
                suggestion="NRT does not allow comments. Remove all // and /* */ comments.",
                doc_url=DOC_URL,
            ))
        else:
            results.append(ValidationResult(
                passed=True,
                severity=Severity.ERROR,
                category=Category.NRT_ELIGIBILITY,
                rule_id="NRT005",
                message="No comment lines",
            ))

        # NRT006: Table supports NRT
        table = parsed.primary_table
        tc = classify_table(table)
        if tc.supports_nrt:
            results.append(ValidationResult(
                passed=True,
                severity=Severity.ERROR,
                category=Category.NRT_ELIGIBILITY,
                rule_id="NRT006",
                message=f"'{table}' supports NRT frequency",
            ))
        else:
            results.append(ValidationResult(
                passed=False,
                severity=Severity.ERROR,
                category=Category.NRT_ELIGIBILITY,
                rule_id="NRT006",
                message=f"'{table}' does not support NRT frequency",
                suggestion="Use scheduled frequency. See docs for NRT-supported tables.",
                doc_url=DOC_URL,
            ))

        # NRT007: EmailEvents specific column exclusions
        nrt_excluded = NON_SUPPORTED_NRT_COLUMNS.get(table, set())
        if nrt_excluded:
            excluded_used = [
                col for col in parsed.all_referenced_columns
                if col in nrt_excluded
            ]
            if excluded_used:
                results.append(ValidationResult(
                    passed=False,
                    severity=Severity.WARNING,
                    category=Category.NRT_ELIGIBILITY,
                    rule_id="NRT007",
                    message=f"EmailEvents NRT excludes columns: {', '.join(excluded_used)}",
                    suggestion=(
                        "LatestDeliveryLocation and LatestDeliveryAction are not "
                        "available in NRT mode for EmailEvents. Remove these columns "
                        "or use scheduled frequency."
                    ),
                    doc_url=DOC_URL,
                ))

        return results
