"""Data model representing a parsed KQL query."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParsedQuery:
    # Tables
    source_tables: list[str] = field(default_factory=list)  # all tables referenced
    primary_table: str = ""  # first/main table

    # Columns
    projected_columns: list[str] = field(default_factory=list)  # final output columns
    project_away_columns: list[str] = field(default_factory=list)  # columns removed
    summarize_by_columns: list[str] = field(default_factory=list)  # columns in summarize by
    summarize_agg_columns: list[str] = field(default_factory=list)  # columns from aggregations
    all_referenced_columns: list[str] = field(default_factory=list)  # all columns mentioned

    # Operators & structure
    has_join: bool = False
    has_union: bool = False
    has_externaldata: bool = False
    has_summarize: bool = False
    has_project: bool = False
    has_project_away: bool = False
    has_extend: bool = False
    has_invoke: bool = False
    has_comments: bool = False
    operators_used: list[str] = field(default_factory=list)

    # Specific checks
    filters_on_timestamp: bool = False
    timestamp_manipulated: bool = False  # extend Timestamp = ... or project Timestamp = expr
    uses_arg_max_timestamp: bool = False  # summarize (Timestamp, ...)=arg_max(Timestamp, ...)
    uses_ingestion_time: bool = False
    has_implicit_columns: bool = False  # no explicit project = all table columns returned

    # Raw text
    raw_text: str = ""
