"""Extract tables, columns, and operators from tokenized KQL text."""

from __future__ import annotations

import re

from cdv.parser.query_model import ParsedQuery
from cdv.parser.tokenizer import TokenizedQuery


# KQL tabular operators (used for operator detection)
KQL_TABULAR_OPERATORS = {
    "where", "project", "project-away", "project-keep", "project-rename",
    "project-reorder", "extend", "summarize", "join", "union", "sort",
    "order", "top", "take", "limit", "distinct", "count", "render",
    "invoke", "let", "parse", "parse-where", "mv-expand", "mv-apply",
    "make-series", "evaluate", "search", "find", "datatable", "externaldata",
    "as", "lookup", "sample", "sample-distinct", "serialize", "range",
    "print", "fork", "facet", "getschema",
}

# KQL keywords/functions to exclude from column name detection
KQL_KEYWORDS = {
    "and", "or", "not", "in", "between", "contains", "startswith",
    "endswith", "has", "has_any", "has_all", "matches", "regex", "true",
    "false", "ago", "now", "datetime", "timespan", "long", "int", "real",
    "string", "bool", "dynamic", "typeof", "toscalar", "iff", "iif",
    "case", "coalesce", "isempty", "isnotempty", "isnull", "isnotnull",
    "tolower", "toupper", "tostring", "toint", "tolong", "todouble",
    "todatetime", "totimespan", "tobool", "todecimal", "bin", "floor",
    "ceiling", "round", "strlen", "substring", "trim", "replace",
    "split", "strcat", "pack", "pack_array", "pack_all", "bag_pack",
    "extract", "extract_all", "parse_json", "parse_url", "parse_path",
    "parse_urlquery", "format_datetime", "format_timespan", "count",
    "dcount", "sum", "avg", "min", "max", "percentile", "percentiles",
    "stdev", "variance", "any", "arg_max", "arg_min", "make_list",
    "make_set", "make_bag", "countif", "dcountif", "sumif", "avgif",
    "ingestion_time", "kind", "inner", "outer", "leftouter", "rightouter",
    "leftanti", "rightanti", "leftsemi", "rightsemi", "fullouter",
    "innerunique", "hint", "shufflekey", "strategy", "broadcast",
    "asc", "desc", "nulls", "first", "last", "by", "on", "with",
    "type", "set", "bag", "array", "table", "database", "cluster",
}


def extract(tokenized: TokenizedQuery) -> ParsedQuery:
    """Extract structured information from tokenized KQL."""
    text = tokenized.cleaned_text
    parsed = ParsedQuery(raw_text=tokenized.original_text)
    parsed.has_comments = tokenized.has_comments

    # Remove let statements and find the main query body
    main_body = _strip_let_statements(text)

    # Extract tables
    _extract_tables(main_body, parsed)

    # Extract operators
    _extract_operators(main_body, parsed)

    # Extract columns
    _extract_columns(main_body, parsed)

    # Detect specific patterns
    _detect_patterns(main_body, parsed)

    return parsed


def _strip_let_statements(text: str) -> str:
    """Remove let statements and return the main query body."""
    # let name = expr;
    # Can span multiple lines, ends with ;
    result = re.sub(
        r'(?m)^\s*let\s+\w+\s*=\s*[^;]*;\s*',
        '',
        text,
    )
    return result.strip()


def _extract_tables(text: str, parsed: ParsedQuery) -> None:
    """Extract table names from the query."""
    tables: list[str] = []

    # Check for union first (union Table1, Table2, ...)
    union_match = re.search(
        r'\bunion\b\s+((?:kind\s*=\s*\w+\s+)?)([\w\s,]+?)(?:\||$)',
        text,
        re.IGNORECASE,
    )
    if union_match:
        parsed.has_union = True
        table_str = union_match.group(2)
        for t in table_str.split(","):
            name = t.strip()
            if name and _is_table_name(name):
                tables.append(name)

    # Primary table: first identifier before first pipe
    # Handle "union" at the start differently
    if text.lstrip().lower().startswith("union"):
        # Tables already extracted above
        pass
    else:
        # Standard: TableName | ...
        primary_match = re.match(r'\s*(\w+)\s*(?:\||$)', text)
        if primary_match:
            name = primary_match.group(1)
            if _is_table_name(name):
                if name not in tables:
                    tables.insert(0, name)

    # Join tables: join [kind=...] (TableName | ...)
    for join_match in re.finditer(
        r'\bjoin\b[^(]*\(\s*(\w+)',
        text,
        re.IGNORECASE,
    ):
        name = join_match.group(1)
        if _is_table_name(name):
            if name not in tables:
                tables.append(name)
            parsed.has_join = True

    # Also detect join without parentheses: join TableName on ...
    for join_match in re.finditer(
        r'\bjoin\b\s+(?:kind\s*=\s*\w+\s+)?(\w+)\s+on\b',
        text,
        re.IGNORECASE,
    ):
        name = join_match.group(1)
        if _is_table_name(name) and name not in tables:
            tables.append(name)
            parsed.has_join = True

    parsed.source_tables = tables
    parsed.primary_table = tables[0] if tables else ""


def _extract_operators(text: str, parsed: ParsedQuery) -> None:
    """Extract tabular operators used in the query."""
    operators: list[str] = []

    for match in re.finditer(r'\|\s*([\w-]+)', text):
        op = match.group(1).lower()
        if op in KQL_TABULAR_OPERATORS:
            operators.append(op)

    parsed.operators_used = operators
    parsed.has_join = parsed.has_join or "join" in operators
    parsed.has_union = parsed.has_union or "union" in operators
    parsed.has_externaldata = "externaldata" in operators
    parsed.has_summarize = "summarize" in operators
    parsed.has_project = "project" in operators or "project-keep" in operators
    parsed.has_project_away = "project-away" in operators
    parsed.has_extend = "extend" in operators
    parsed.has_invoke = "invoke" in operators


def _extract_columns(text: str, parsed: ParsedQuery) -> None:
    """Extract projected columns, summarize columns, and all referenced columns."""

    # --- Projected columns (from the last project/project-keep) ---
    project_matches = list(re.finditer(
        r'\|\s*project(?:-keep)?\s+([\s\S]*?)(?=\||$)',
        text,
    ))
    if project_matches:
        last_project = project_matches[-1].group(1).strip()
        parsed.projected_columns = _parse_column_list(last_project)
        parsed.has_implicit_columns = False
    else:
        parsed.has_implicit_columns = not parsed.has_summarize

    # --- Project-away columns ---
    for pa_match in re.finditer(
        r'\|\s*project-away\s+([\s\S]*?)(?=\||$)',
        text,
    ):
        parsed.project_away_columns = _parse_column_list(pa_match.group(1).strip())

    # --- Summarize columns ---
    if parsed.has_summarize:
        _extract_summarize_columns(text, parsed)

    # --- All referenced columns ---
    # Find PascalCase identifiers that look like column names
    all_cols: list[str] = []
    for match in re.finditer(r'\b([A-Z][a-zA-Z0-9_]*)\b', text):
        name = match.group(1)
        if (
            name.lower() not in KQL_KEYWORDS
            and name not in parsed.source_tables
            and not name.startswith("__STR")
            and name not in all_cols
        ):
            all_cols.append(name)
    parsed.all_referenced_columns = all_cols


def _extract_summarize_columns(text: str, parsed: ParsedQuery) -> None:
    """Extract columns from summarize expressions."""
    summarize_match = re.search(
        r'\|\s*summarize\s+([\s\S]*?)(?=\||$)',
        text,
    )
    if not summarize_match:
        return

    summarize_text = summarize_match.group(1).strip()

    # Split on "by" to get aggregations and grouping columns
    by_split = re.split(r'\bby\b', summarize_text, maxsplit=1)

    if len(by_split) == 2:
        agg_part = by_split[0].strip()
        by_part = by_split[1].strip()
        parsed.summarize_by_columns = _parse_column_list(by_part)
    else:
        agg_part = summarize_text
        by_part = ""

    # Extract column aliases from aggregations
    # Pattern: (Col1, Col2)=func(...) or Alias=func(...)
    agg_columns: list[str] = []

    # Tuple assignment: (Timestamp, ReportId)=arg_max(Timestamp, ReportId)
    for tuple_match in re.finditer(
        r'\(([^)]+)\)\s*=\s*(\w+)\s*\(',
        agg_part,
    ):
        cols = [c.strip() for c in tuple_match.group(1).split(",")]
        agg_columns.extend(cols)

    # Simple alias: Alias=func(...)
    for alias_match in re.finditer(
        r'(\w+)\s*=\s*\w+\s*\(',
        agg_part,
    ):
        name = alias_match.group(1)
        if name not in agg_columns:
            agg_columns.append(name)

    # Bare aggregation functions produce implicit columns: count() -> count_, dcount(X) -> dcount_X
    if re.search(r'(?<!\w)count\s*\(\s*\)', agg_part):
        agg_columns.append("count_")

    parsed.summarize_agg_columns = agg_columns

    # Determine final projected columns for summarized queries
    if not parsed.has_project:
        # After summarize, output = by_columns + agg_columns
        final_cols = list(parsed.summarize_by_columns) + agg_columns
        parsed.projected_columns = final_cols


def _detect_patterns(text: str, parsed: ParsedQuery) -> None:
    """Detect specific patterns relevant to custom detection validation."""

    # Timestamp filtering: where ... Timestamp ...
    if re.search(r'\|\s*where\b[^|]*\bTimestamp\b', text, re.IGNORECASE):
        parsed.filters_on_timestamp = True

    # Timestamp manipulation: extend Timestamp = ...
    if re.search(r'\|\s*extend\b[^|]*\bTimestamp\s*=', text):
        parsed.timestamp_manipulated = True
    # project Timestamp = expr (not just "project ..., Timestamp, ...")
    if re.search(r'\|\s*project\b[^|]*\bTimestamp\s*=\s*\w', text):
        parsed.timestamp_manipulated = True

    # arg_max(Timestamp, ...) pattern
    if re.search(r'arg_max\s*\(\s*Timestamp\b', text):
        parsed.uses_arg_max_timestamp = True

    # ingestion_time()
    if re.search(r'ingestion_time\s*\(\s*\)', text):
        parsed.uses_ingestion_time = True

    # externaldata detection (can appear without pipe)
    if re.search(r'\bexternaldata\b', text, re.IGNORECASE):
        parsed.has_externaldata = True


def _parse_column_list(text: str) -> list[str]:
    """Parse a comma-separated column list, handling aliases like 'Alias = expr'."""
    columns: list[str] = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        # Handle alias: NewName = OldName or NewName = expression
        alias_match = re.match(r'(\w+)\s*=', item)
        if alias_match:
            columns.append(alias_match.group(1))
        else:
            # Plain column name (may have trailing whitespace or function calls)
            name_match = re.match(r'(\w+)', item)
            if name_match:
                name = name_match.group(1)
                if name.lower() not in KQL_KEYWORDS:
                    columns.append(name)
    return columns


def _is_table_name(name: str) -> bool:
    """Heuristic: check if identifier looks like a table name."""
    if not name or name[0].islower():
        return False
    if name.lower() in KQL_KEYWORDS:
        return False
    if name.lower() in KQL_TABULAR_OPERATORS:
        return False
    if name.startswith("__STR"):
        return False
    return True
