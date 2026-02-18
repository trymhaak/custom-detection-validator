"""Tests for best practices validation rules BP001-BP005."""

from cdv.parser.extractor import extract
from cdv.parser.tokenizer import tokenize
from cdv.validators.best_practices import BestPracticesValidator


def _validate(kql: str):
    parsed = extract(tokenize(kql))
    return BestPracticesValidator().validate(parsed)


def _find(results, rule_id):
    return [r for r in results if r.rule_id == rule_id]


class TestBP001TimestampFiltering:
    def test_timestamp_filter_warns(self):
        results = _validate("DeviceEvents | where Timestamp > ago(1d)")
        bp001 = _find(results, "BP001")
        assert len(bp001) == 1
        assert bp001[0].passed is False
        assert bp001[0].severity.value == "warning"

    def test_no_timestamp_filter_no_warning(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        bp001 = _find(results, "BP001")
        assert len(bp001) == 0


class TestBP002IngestionTime:
    def test_no_time_filtering_suggests_ingestion_time(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        bp002 = _find(results, "BP002")
        assert len(bp002) == 1
        assert bp002[0].passed is True  # INFO, not a failure
        assert "ingestion_time" in bp002[0].suggestion

    def test_timestamp_filter_no_bp002(self):
        # If already filtering on Timestamp, BP001 fires instead
        results = _validate("DeviceEvents | where Timestamp > ago(1d)")
        bp002 = _find(results, "BP002")
        assert len(bp002) == 0

    def test_ingestion_time_used_no_bp002(self):
        results = _validate("DeviceEvents | where ingestion_time() > ago(1d)")
        bp002 = _find(results, "BP002")
        # Uses ingestion_time, so no suggestion needed
        # But BP002 fires when NOT using ingestion_time AND NOT filtering on Timestamp
        # Since we ARE using ingestion_time, BP002 should not fire
        # Looking at the logic: `if not parsed.uses_ingestion_time and not parsed.filters_on_timestamp`
        assert len(bp002) == 0


class TestBP003SummarizeLosingColumns:
    def test_summarize_losing_timestamp_warns(self):
        results = _validate("DeviceEvents | summarize count() by DeviceId")
        bp003 = _find(results, "BP003")
        assert len(bp003) == 1
        assert bp003[0].passed is False
        assert bp003[0].severity.value == "warning"
        assert "Timestamp" in bp003[0].message

    def test_summarize_with_arg_max_no_warning(self):
        kql = "DeviceEvents | summarize (Timestamp, ReportId)=arg_max(Timestamp, ReportId), count() by DeviceId"
        results = _validate(kql)
        bp003 = _find(results, "BP003")
        assert len(bp003) == 0

    def test_summarize_by_timestamp_no_warning(self):
        kql = "DeviceEvents | summarize count() by Timestamp, DeviceId"
        results = _validate(kql)
        bp003 = _find(results, "BP003")
        assert len(bp003) == 0

    def test_no_summarize_no_bp003(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        bp003 = _find(results, "BP003")
        assert len(bp003) == 0


class TestBP004AlertLimit:
    def test_no_filtering_shows_reminder(self):
        results = _validate("DeviceEvents")
        bp004 = _find(results, "BP004")
        assert len(bp004) == 1
        assert "150" in bp004[0].suggestion

    def test_where_filter_no_reminder(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        bp004 = _find(results, "BP004")
        assert len(bp004) == 0

    def test_summarize_no_reminder(self):
        results = _validate("DeviceEvents | summarize count() by DeviceId")
        bp004 = _find(results, "BP004")
        assert len(bp004) == 0

    def test_top_no_reminder(self):
        results = _validate("DeviceEvents | top 100 by Timestamp desc")
        bp004 = _find(results, "BP004")
        assert len(bp004) == 0


class TestBP005EmailEventsNRT:
    def test_email_events_nrt_excluded_column(self):
        kql = "EmailEvents | where LatestDeliveryLocation == 'Inbox'"
        results = _validate(kql)
        bp005 = _find(results, "BP005")
        assert len(bp005) == 1
        assert bp005[0].passed is False
        assert "LatestDeliveryLocation" in bp005[0].message

    def test_email_events_without_excluded_columns(self):
        kql = "EmailEvents | where Subject contains 'phishing'"
        results = _validate(kql)
        bp005 = _find(results, "BP005")
        assert len(bp005) == 0

    def test_non_email_table_no_bp005(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        bp005 = _find(results, "BP005")
        assert len(bp005) == 0
