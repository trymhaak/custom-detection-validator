"""Validation engine: orchestrates all validators."""

from __future__ import annotations

from cdv.parser.extractor import extract
from cdv.parser.tokenizer import tokenize
from cdv.validators.action_columns import ActionColumnsValidator
from cdv.validators.base import BaseValidator, ValidationReport
from cdv.validators.best_practices import BestPracticesValidator
from cdv.validators.non_supported_columns import NonSupportedColumnsValidator
from cdv.validators.nrt_eligibility import NrtEligibilityValidator
from cdv.validators.required_columns import RequiredColumnsValidator
from cdv.validators.table_validator import TableValidator


class ValidationEngine:
    def __init__(self, validators: list[BaseValidator] | None = None):
        self.validators = validators or [
            TableValidator(),
            RequiredColumnsValidator(),
            NonSupportedColumnsValidator(),
            NrtEligibilityValidator(),
            ActionColumnsValidator(),
            BestPracticesValidator(),
        ]

    def validate(self, kql_text: str) -> ValidationReport:
        tokenized = tokenize(kql_text)
        parsed = extract(tokenized)

        results = []
        for validator in self.validators:
            results.extend(validator.validate(parsed))

        return ValidationReport(
            query_text=kql_text,
            results=results,
            parsed_query=parsed,
        )
