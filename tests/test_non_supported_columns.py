"""Tests for non-supported columns validation rules NSC001-NSC003."""

from cdv.parser.extractor import extract
from cdv.parser.tokenizer import tokenize
from cdv.validators.non_supported_columns import NonSupportedColumnsValidator


def _validate(kql: str):
    parsed = extract(tokenize(kql))
    return NonSupportedColumnsValidator().validate(parsed)


def _find(results, rule_id):
    return [r for r in results if r.rule_id == rule_id]


class TestNSC001NRTExcludedColumns:
    """EmailEvents-specific NRT excluded columns."""

    def test_latest_delivery_location_warns(self):
        results = _validate(
            "EmailEvents | project Timestamp, NetworkMessageId, "
            "RecipientEmailAddress, ReportId, LatestDeliveryLocation"
        )
        nsc001 = _find(results, "NSC001")
        assert len(nsc001) == 1
        assert nsc001[0].passed is False
        assert "LatestDeliveryLocation" in nsc001[0].message

    def test_latest_delivery_action_warns(self):
        results = _validate(
            "EmailEvents | project Timestamp, NetworkMessageId, "
            "RecipientEmailAddress, ReportId, LatestDeliveryAction"
        )
        nsc001 = _find(results, "NSC001")
        assert len(nsc001) == 1
        assert nsc001[0].passed is False
        assert "LatestDeliveryAction" in nsc001[0].message

    def test_both_excluded_columns_warns(self):
        results = _validate(
            "EmailEvents | project Timestamp, NetworkMessageId, "
            "RecipientEmailAddress, ReportId, LatestDeliveryLocation, LatestDeliveryAction"
        )
        nsc001 = _find(results, "NSC001")
        assert len(nsc001) == 1
        assert nsc001[0].passed is False
        assert "LatestDeliveryAction" in nsc001[0].message
        assert "LatestDeliveryLocation" in nsc001[0].message

    def test_no_excluded_columns_passes(self):
        results = _validate(
            "EmailEvents | project Timestamp, NetworkMessageId, "
            "RecipientEmailAddress, ReportId, Subject"
        )
        nsc001 = _find(results, "NSC001")
        assert len(nsc001) == 1
        assert nsc001[0].passed is True

    def test_non_email_table_no_nsc001(self):
        """Non-EmailEvents tables should not generate NSC001 results."""
        results = _validate(
            "DeviceEvents | project Timestamp, DeviceId, ReportId"
        )
        nsc001 = _find(results, "NSC001")
        assert len(nsc001) == 0

    def test_excluded_column_referenced_but_not_projected(self):
        """If a column is in a where but not projected, it's in the output only if implicit."""
        results = _validate(
            "EmailEvents | where LatestDeliveryLocation == 'Quarantine' "
            "| project Timestamp, NetworkMessageId, RecipientEmailAddress, ReportId"
        )
        nsc001 = _find(results, "NSC001")
        assert len(nsc001) == 1
        assert nsc001[0].passed is True  # Not in projected output

    def test_severity_is_warning(self):
        results = _validate(
            "EmailEvents | project Timestamp, ReportId, LatestDeliveryLocation"
        )
        nsc001 = _find(results, "NSC001")
        assert nsc001[0].severity.value == "warning"


class TestNSC002GAColumnsNote:
    """General NRT GA column note for NRT-supported tables."""

    def test_nrt_table_gets_ga_note(self):
        results = _validate(
            "DeviceEvents | project Timestamp, DeviceId, ReportId"
        )
        nsc002 = _find(results, "NSC002")
        assert len(nsc002) == 1
        assert "GA columns" in nsc002[0].message

    def test_non_nrt_table_no_ga_note(self):
        """Tables that don't support NRT shouldn't get the GA note."""
        results = _validate(
            "DeviceTvmSoftwareInventory | project Timestamp, DeviceId, ReportId"
        )
        nsc002 = _find(results, "NSC002")
        assert len(nsc002) == 0

    def test_emailevents_gets_ga_note(self):
        results = _validate(
            "EmailEvents | project Timestamp, NetworkMessageId, ReportId"
        )
        nsc002 = _find(results, "NSC002")
        assert len(nsc002) == 1

    def test_sentinel_nrt_table_gets_ga_note(self):
        results = _validate(
            "SigninLogs | where TimeGenerated > ago(1h)"
        )
        nsc002 = _find(results, "NSC002")
        assert len(nsc002) == 1


class TestNSC003StreamingAPIExcluded:
    """EmailEvents Streaming API exclusion note."""

    def test_streaming_excluded_column_generates_note(self):
        results = _validate(
            "EmailEvents | project Timestamp, ReportId, LatestDeliveryLocation"
        )
        nsc003 = _find(results, "NSC003")
        assert len(nsc003) == 1
        assert nsc003[0].passed is False
        assert "Streaming API" in nsc003[0].message

    def test_no_streaming_excluded_no_note(self):
        results = _validate(
            "EmailEvents | project Timestamp, ReportId, Subject"
        )
        nsc003 = _find(results, "NSC003")
        assert len(nsc003) == 0

    def test_non_email_table_no_streaming_note(self):
        results = _validate(
            "DeviceEvents | project Timestamp, DeviceId, ReportId"
        )
        nsc003 = _find(results, "NSC003")
        assert len(nsc003) == 0


class TestIntegrationWithEngine:
    """Ensure the validator integrates properly with the engine."""

    def test_engine_includes_nsc_results(self):
        from cdv.validators.engine import ValidationEngine
        engine = ValidationEngine()
        report = engine.validate(
            "EmailEvents | project Timestamp, NetworkMessageId, "
            "RecipientEmailAddress, ReportId, LatestDeliveryLocation"
        )
        nsc_results = [r for r in report.results if r.category.value == "non_supported_columns"]
        assert len(nsc_results) > 0

    def test_engine_nsc_after_required_columns(self):
        """NSC results should appear after required columns in output."""
        from cdv.validators.engine import ValidationEngine
        engine = ValidationEngine()
        report = engine.validate(
            "EmailEvents | project Timestamp, NetworkMessageId, "
            "RecipientEmailAddress, ReportId, LatestDeliveryLocation"
        )
        categories_seen = []
        for r in report.results:
            if r.category.value not in categories_seen:
                categories_seen.append(r.category.value)
        rc_idx = categories_seen.index("required_columns")
        nsc_idx = categories_seen.index("non_supported_columns")
        assert nsc_idx == rc_idx + 1
