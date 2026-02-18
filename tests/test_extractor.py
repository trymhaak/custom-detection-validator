"""Tests for the KQL extractor (parser)."""

from cdv.parser.extractor import extract
from cdv.parser.tokenizer import tokenize


def _parse(kql: str):
    """Helper: tokenize + extract."""
    return extract(tokenize(kql))


class TestTableExtraction:
    def test_simple_table(self):
        p = _parse("DeviceEvents | where ActionType == 'x'")
        assert p.primary_table == "DeviceEvents"
        assert p.source_tables == ["DeviceEvents"]

    def test_table_without_pipe(self):
        p = _parse("DeviceEvents")
        assert p.primary_table == "DeviceEvents"

    def test_join_tables(self):
        p = _parse("DeviceProcessEvents | join kind=inner (DeviceFileEvents) on DeviceId")
        assert p.primary_table == "DeviceProcessEvents"
        assert "DeviceFileEvents" in p.source_tables
        assert p.has_join is True

    def test_join_without_parens(self):
        p = _parse("DeviceEvents | join DeviceInfo on DeviceId")
        assert p.primary_table == "DeviceEvents"
        assert "DeviceInfo" in p.source_tables
        assert p.has_join is True

    def test_union_tables(self):
        p = _parse("union DeviceEvents, DeviceProcessEvents | where ActionType == 'x'")
        assert p.has_union is True
        assert "DeviceEvents" in p.source_tables
        assert "DeviceProcessEvents" in p.source_tables

    def test_no_table_found(self):
        p = _parse("| where x == 1")
        # Should not crash; primary_table may be empty
        assert p.primary_table == "" or p.source_tables == []


class TestLetStatements:
    def test_strips_let_statement(self):
        kql = "let threshold = 5;\nDeviceEvents | where count_ > threshold"
        p = _parse(kql)
        assert p.primary_table == "DeviceEvents"

    def test_strips_multiple_let_statements(self):
        kql = "let x = 5;\nlet y = ago(7d);\nDeviceEvents | where Timestamp > y"
        p = _parse(kql)
        assert p.primary_table == "DeviceEvents"

    def test_let_with_table_reference(self):
        kql = "let x = 5;\nDeviceProcessEvents | where ActionType == 'ProcessCreated'"
        p = _parse(kql)
        assert p.primary_table == "DeviceProcessEvents"


class TestOperatorExtraction:
    def test_where_operator(self):
        p = _parse("DeviceEvents | where ActionType == 'x'")
        assert "where" in p.operators_used

    def test_project_operator(self):
        p = _parse("DeviceEvents | project Timestamp, DeviceId, ReportId")
        assert "project" in p.operators_used
        assert p.has_project is True

    def test_project_away_operator(self):
        p = _parse("DeviceEvents | project-away ReportId")
        assert "project-away" in p.operators_used
        assert p.has_project_away is True

    def test_summarize_operator(self):
        p = _parse("DeviceEvents | summarize count() by DeviceId")
        assert "summarize" in p.operators_used
        assert p.has_summarize is True

    def test_extend_operator(self):
        p = _parse("DeviceEvents | extend NewCol = FileName")
        assert "extend" in p.operators_used
        assert p.has_extend is True

    def test_invoke_operator(self):
        p = _parse("DeviceProcessEvents | invoke FileProfile()")
        assert "invoke" in p.operators_used
        assert p.has_invoke is True

    def test_externaldata_detection(self):
        p = _parse("DeviceEvents | where DeviceId in (externaldata(DeviceId:string)[@'url'])")
        assert p.has_externaldata is True

    def test_multiple_operators(self):
        p = _parse("DeviceEvents | where ActionType == 'x' | project Timestamp, DeviceId | sort by Timestamp desc")
        assert "where" in p.operators_used
        assert "project" in p.operators_used
        assert "sort" in p.operators_used


class TestColumnExtraction:
    def test_project_columns(self):
        p = _parse("DeviceEvents | project Timestamp, DeviceId, ReportId, FileName")
        assert "Timestamp" in p.projected_columns
        assert "DeviceId" in p.projected_columns
        assert "ReportId" in p.projected_columns
        assert "FileName" in p.projected_columns

    def test_project_away_columns(self):
        p = _parse("DeviceEvents | project-away ReportId, DeviceId")
        assert "ReportId" in p.project_away_columns
        assert "DeviceId" in p.project_away_columns

    def test_last_project_wins(self):
        kql = "DeviceEvents | project Timestamp, DeviceId | project Timestamp, FileName"
        p = _parse(kql)
        assert "FileName" in p.projected_columns
        # DeviceId should not be in final projected since last project doesn't include it
        assert "DeviceId" not in p.projected_columns

    def test_project_with_alias(self):
        p = _parse("DeviceEvents | project TS = Timestamp, DeviceId")
        assert "TS" in p.projected_columns
        assert "DeviceId" in p.projected_columns

    def test_implicit_columns_without_project(self):
        p = _parse("DeviceEvents | where ActionType == 'x'")
        assert p.has_implicit_columns is True

    def test_no_implicit_columns_with_project(self):
        p = _parse("DeviceEvents | project Timestamp, DeviceId")
        assert p.has_implicit_columns is False


class TestSummarizeColumns:
    def test_summarize_by_columns(self):
        p = _parse("DeviceEvents | summarize count() by DeviceId, DeviceName")
        assert "DeviceId" in p.summarize_by_columns
        assert "DeviceName" in p.summarize_by_columns

    def test_summarize_count_implicit(self):
        p = _parse("DeviceEvents | summarize count() by DeviceId")
        assert "count_" in p.summarize_agg_columns

    def test_summarize_alias(self):
        p = _parse("DeviceEvents | summarize EventCount=count() by DeviceId")
        assert "EventCount" in p.summarize_agg_columns

    def test_summarize_arg_max_tuple(self):
        kql = "DeviceEvents | summarize (Timestamp, ReportId)=arg_max(Timestamp, ReportId), count() by DeviceId"
        p = _parse(kql)
        assert "Timestamp" in p.summarize_agg_columns
        assert "ReportId" in p.summarize_agg_columns
        assert p.uses_arg_max_timestamp is True

    def test_summarize_replaces_projected_columns(self):
        p = _parse("DeviceEvents | summarize count() by DeviceId")
        # After summarize (without project), projected should be by + agg columns
        assert "DeviceId" in p.projected_columns
        assert "count_" in p.projected_columns


class TestPatternDetection:
    def test_filters_on_timestamp(self):
        p = _parse("DeviceEvents | where Timestamp > ago(1d)")
        assert p.filters_on_timestamp is True

    def test_no_timestamp_filter(self):
        p = _parse("DeviceEvents | where ActionType == 'x'")
        assert p.filters_on_timestamp is False

    def test_timestamp_manipulated_extend(self):
        p = _parse("DeviceEvents | extend Timestamp = now()")
        assert p.timestamp_manipulated is True

    def test_timestamp_manipulated_project(self):
        p = _parse("DeviceEvents | project Timestamp = datetime(2024-01-01), DeviceId, ReportId")
        assert p.timestamp_manipulated is True

    def test_timestamp_not_manipulated(self):
        p = _parse("DeviceEvents | project Timestamp, DeviceId, ReportId")
        assert p.timestamp_manipulated is False

    def test_uses_arg_max_timestamp(self):
        p = _parse("DeviceEvents | summarize arg_max(Timestamp, *) by DeviceId")
        assert p.uses_arg_max_timestamp is True

    def test_uses_ingestion_time(self):
        p = _parse("DeviceEvents | where ingestion_time() > ago(1d)")
        assert p.uses_ingestion_time is True

    def test_no_ingestion_time(self):
        p = _parse("DeviceEvents | where Timestamp > ago(1d)")
        assert p.uses_ingestion_time is False

    def test_comments_detected(self):
        p = _parse("// comment\nDeviceEvents | where ActionType == 'x'")
        assert p.has_comments is True

    def test_no_comments(self):
        p = _parse("DeviceEvents | where ActionType == 'x'")
        assert p.has_comments is False


class TestAllReferencedColumns:
    def test_captures_pascalcase_columns(self):
        p = _parse("DeviceEvents | where ActionType == 'x' and FileName == 'cmd.exe'")
        assert "ActionType" in p.all_referenced_columns
        assert "FileName" in p.all_referenced_columns

    def test_excludes_tables(self):
        p = _parse("DeviceEvents | where ActionType == 'x'")
        assert "DeviceEvents" not in p.all_referenced_columns

    def test_excludes_keywords(self):
        p = _parse("DeviceEvents | where ActionType contains 'x'")
        # "contains" is a keyword and should not be in columns
        assert "ActionType" in p.all_referenced_columns
