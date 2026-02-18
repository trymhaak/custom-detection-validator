"""Validate columns needed for specific response actions."""

from __future__ import annotations

from cdv.parser.query_model import ParsedQuery
from cdv.rules.columns import (
    ACTION_PERMISSIONS,
    DEVICE_ACTION_COLUMNS,
    EMAIL_ACTION_REQUIRED_COLUMNS,
    FILE_ACTION_COLUMNS,
    USER_COMPROMISE_COLUMNS,
    USER_DISABLE_COLUMNS,
    get_relevant_actions,
)
from cdv.validators.base import (
    BaseValidator,
    Category,
    Severity,
    ValidationResult,
)

DOC_URL = "https://learn.microsoft.com/defender-xdr/custom-detection-rules#4-specify-actions"


def _permissions_note(rule_id: str) -> str:
    """Build a permissions note for a given action rule ID."""
    perms = ACTION_PERMISSIONS.get(rule_id)
    if not perms:
        return ""
    return (
        f"RBAC: {perms['unified_rbac']}\n"
        f"Entra role: {perms['entra_role']}"
    )


def _permissions_doc_url(rule_id: str) -> str:
    """Return the doc URL for a given action's permissions."""
    perms = ACTION_PERMISSIONS.get(rule_id)
    if not perms:
        return ""
    return perms.get("doc_url", "")


class ActionColumnsValidator(BaseValidator):
    def validate(self, parsed: ParsedQuery) -> list[ValidationResult]:
        results: list[ValidationResult] = []

        if not parsed.primary_table:
            return results

        output_cols = self._get_output_columns(parsed)
        relevant = get_relevant_actions(parsed.primary_table)

        # ACT001: Device actions
        if "ACT001" in relevant:
            results.append(self._check_any(
                "ACT001",
                "Device actions (isolate, scan, investigate, restrict, collect package)",
                DEVICE_ACTION_COLUMNS,
                output_cols,
                parsed.has_implicit_columns,
            ))

        # ACT002: File actions
        if "ACT002" in relevant:
            act002 = self._check_any(
                "ACT002",
                "File actions (allow/block, quarantine)",
                FILE_ACTION_COLUMNS,
                output_cols,
                parsed.has_implicit_columns,
            )
            # Quarantine specifically also needs DeviceId alongside a hash
            if act002.passed and not parsed.has_implicit_columns:
                if "DeviceId" not in output_cols:
                    note = _permissions_note("ACT002")
                    act002 = ValidationResult(
                        passed=act002.passed,
                        severity=act002.severity,
                        category=act002.category,
                        rule_id=act002.rule_id,
                        message=act002.message,
                        suggestion=(
                            f"{note}\n"
                            f"Note: Quarantine file also requires DeviceId in the query output"
                        ),
                        doc_url=act002.doc_url,
                    )
            results.append(act002)

        # ACT003: User mark as compromised
        if "ACT003" in relevant:
            results.append(self._check_any(
                "ACT003",
                "Mark user as compromised",
                USER_COMPROMISE_COLUMNS,
                output_cols,
                parsed.has_implicit_columns,
            ))

        # ACT004: User disable / force reset
        if "ACT004" in relevant:
            results.append(self._check_any(
                "ACT004",
                "Disable user / Force password reset",
                USER_DISABLE_COLUMNS,
                output_cols,
                parsed.has_implicit_columns,
            ))

        # ACT005: Email actions (both columns required)
        if "ACT005" in relevant:
            results.append(self._check_all(
                "ACT005",
                "Email actions (move to folder, delete)",
                EMAIL_ACTION_REQUIRED_COLUMNS,
                output_cols,
                parsed.has_implicit_columns,
            ))

        return results

    def _check_any(
        self,
        rule_id: str,
        action_name: str,
        required_columns: set[str] | frozenset[str],
        output_cols: set[str],
        implicit: bool,
    ) -> ValidationResult:
        """Check if at least one of the required columns is present."""
        found = output_cols & required_columns
        if found or implicit:
            if implicit:
                detail = "available (all columns returned implicitly)"
            else:
                detail = f"available ({', '.join(sorted(found))})"
            return ValidationResult(
                passed=True,
                severity=Severity.INFO,
                category=Category.ACTION_REQUIREMENTS,
                rule_id=rule_id,
                message=f"{action_name}: {detail}",
                suggestion=_permissions_note(rule_id),
                doc_url=_permissions_doc_url(rule_id),
            )
        return ValidationResult(
            passed=False,  # Not available — shown as info, not error
            severity=Severity.INFO,
            category=Category.ACTION_REQUIREMENTS,
            rule_id=rule_id,
            message=f"{action_name}: not available (needs {' or '.join(sorted(required_columns))})",
            suggestion=f"To enable this action, include {' or '.join(sorted(required_columns))} in your query output",
        )

    def _check_all(
        self,
        rule_id: str,
        action_name: str,
        required_columns: set[str] | frozenset[str],
        output_cols: set[str],
        implicit: bool,
    ) -> ValidationResult:
        """Check if ALL required columns are present."""
        if implicit:
            return ValidationResult(
                passed=True,
                severity=Severity.INFO,
                category=Category.ACTION_REQUIREMENTS,
                rule_id=rule_id,
                message=f"{action_name}: available (all columns returned implicitly)",
                suggestion=_permissions_note(rule_id),
                doc_url=_permissions_doc_url(rule_id),
            )

        missing = required_columns - output_cols
        if not missing:
            return ValidationResult(
                passed=True,
                severity=Severity.INFO,
                category=Category.ACTION_REQUIREMENTS,
                rule_id=rule_id,
                message=f"{action_name}: available ({', '.join(sorted(required_columns))})",
                suggestion=_permissions_note(rule_id),
                doc_url=_permissions_doc_url(rule_id),
            )
        return ValidationResult(
            passed=False,  # Not available — shown as info, not error
            severity=Severity.INFO,
            category=Category.ACTION_REQUIREMENTS,
            rule_id=rule_id,
            message=f"{action_name}: not available (missing {', '.join(sorted(missing))})",
            suggestion=f"To enable this action, include {', '.join(sorted(missing))} in your query output",
        )

    def _get_output_columns(self, parsed: ParsedQuery) -> set[str]:
        if parsed.projected_columns:
            return set(parsed.projected_columns)
        return set(parsed.all_referenced_columns)
