"""Base types for validation results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from cdv.parser.query_model import ParsedQuery


class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class Category(Enum):
    TABLE = "table"
    REQUIRED_COLUMNS = "required_columns"
    NON_SUPPORTED_COLUMNS = "non_supported_columns"
    NRT_ELIGIBILITY = "nrt_eligibility"
    ACTION_REQUIREMENTS = "action_requirements"
    BEST_PRACTICES = "best_practices"


@dataclass
class ValidationResult:
    passed: bool
    severity: Severity
    category: Category
    rule_id: str
    message: str
    suggestion: str = ""
    doc_url: str = ""


@dataclass
class ValidationReport:
    query_text: str
    results: list[ValidationResult] = field(default_factory=list)
    parsed_query: ParsedQuery | None = None

    @property
    def has_errors(self) -> bool:
        return any(
            not r.passed and r.severity == Severity.ERROR
            for r in self.results
        )

    @property
    def has_warnings(self) -> bool:
        return any(
            not r.passed and r.severity == Severity.WARNING
            for r in self.results
        )

    @property
    def error_count(self) -> int:
        return sum(
            1 for r in self.results
            if not r.passed and r.severity == Severity.ERROR
        )

    @property
    def warning_count(self) -> int:
        return sum(
            1 for r in self.results
            if not r.passed and r.severity == Severity.WARNING
        )

    @property
    def info_count(self) -> int:
        return sum(
            1 for r in self.results
            if not r.passed and r.severity == Severity.INFO
        )


class BaseValidator:
    """Base class for validators."""

    def validate(self, parsed: ParsedQuery) -> list[ValidationResult]:
        raise NotImplementedError
