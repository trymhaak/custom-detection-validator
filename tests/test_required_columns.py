"""Tests for required columns validation rules RC001-RC007."""

from cdv.parser.extractor import extract
from cdv.parser.tokenizer import tokenize
from cdv.validators.required_columns import RequiredColumnsValidator


def _validate(kql: str):
    parsed = extract(tokenize(kql))
    return RequiredColumnsValidator().validate(parsed)


def _find(results, rule_id):
    return [r for r in results if r.rule_id == rule_id]


class TestRC001Timestamp:
    def test_timestamp_in_project_passes(self):
        results = _validate("DeviceEvents | project Timestamp, DeviceId, ReportId")
        rc001 = _find(results, "RC001")
        assert rc001[0].passed is True

    def test_timestamp_missing_from_project_fails(self):
        results = _validate("DeviceEvents | project FileName, DeviceId")
        rc001 = _find(results, "RC001")
        assert rc001[0].passed is False
        assert rc001[0].severity.value == "error"

    def test_implicit_columns_passes(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        rc001 = _find(results, "RC001")
        assert rc001[0].passed is True

    def test_sentinel_needs_time_generated(self):
        results = _validate("SecurityEvent | project TimeGenerated, EventID")
        rc001 = _find(results, "RC001")
        assert rc001[0].passed is True
        assert "TimeGenerated" in rc001[0].message

    def test_sentinel_missing_time_generated(self):
        results = _validate("SecurityEvent | project EventID")
        rc001 = _find(results, "RC001")
        assert rc001[0].passed is False
        assert "TimeGenerated" in rc001[0].message


class TestRC002TimestampManipulation:
    def test_no_manipulation_passes(self):
        results = _validate("DeviceEvents | project Timestamp, DeviceId, ReportId")
        rc002 = _find(results, "RC002")
        assert rc002[0].passed is True

    def test_extend_timestamp_fails(self):
        results = _validate("DeviceEvents | extend Timestamp = now()")
        rc002 = _find(results, "RC002")
        assert rc002[0].passed is False
        assert rc002[0].severity.value == "error"

    def test_project_timestamp_assignment_fails(self):
        results = _validate("DeviceEvents | project Timestamp = datetime(2024-01-01), DeviceId, ReportId")
        rc002 = _find(results, "RC002")
        assert rc002[0].passed is False


class TestRC003EventIDColumns:
    def test_mde_with_device_id_and_report_id_passes(self):
        results = _validate("DeviceEvents | project Timestamp, DeviceId, ReportId, FileName")
        rc003 = _find(results, "RC003")
        assert rc003[0].passed is True

    def test_mde_missing_report_id_fails(self):
        results = _validate("DeviceEvents | project Timestamp, DeviceId, FileName")
        rc003 = _find(results, "RC003")
        assert rc003[0].passed is False
        assert "ReportId" in rc003[0].message

    def test_mde_missing_device_id_fails(self):
        results = _validate("DeviceEvents | project Timestamp, ReportId, FileName")
        rc003 = _find(results, "RC003")
        assert rc003[0].passed is False
        assert "DeviceId" in rc003[0].message

    def test_alert_table_no_extra_ids_needed(self):
        results = _validate("AlertEvidence | project Timestamp, DeviceId")
        rc003 = _find(results, "RC003")
        assert rc003[0].passed is True

    def test_identity_table_needs_report_id(self):
        results = _validate("IdentityLogonEvents | project Timestamp, AccountUpn")
        rc003 = _find(results, "RC003")
        assert rc003[0].passed is False
        assert "ReportId" in rc003[0].message

    def test_implicit_columns_passes(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        rc003 = _find(results, "RC003")
        assert rc003[0].passed is True


class TestRC004ImpactedAssets:
    def test_device_id_is_impacted_asset(self):
        results = _validate("DeviceEvents | project Timestamp, DeviceId, ReportId")
        rc004 = _find(results, "RC004")
        assert rc004[0].passed is True

    def test_account_upn_is_impacted_asset(self):
        results = _validate("IdentityLogonEvents | project Timestamp, ReportId, AccountUpn")
        rc004 = _find(results, "RC004")
        assert rc004[0].passed is True

    def test_recipient_email_is_impacted_asset(self):
        results = _validate("EmailEvents | project Timestamp, ReportId, RecipientEmailAddress")
        rc004 = _find(results, "RC004")
        assert rc004[0].passed is True

    def test_no_impacted_asset_fails(self):
        results = _validate("DeviceEvents | project Timestamp, ReportId, FileName")
        rc004 = _find(results, "RC004")
        assert rc004[0].passed is False
        assert rc004[0].severity.value == "error"

    def test_implicit_columns_passes(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        rc004 = _find(results, "RC004")
        assert rc004[0].passed is True


class TestRC005SummarizeLosesTimestamp:
    def test_summarize_without_timestamp_warns(self):
        results = _validate("DeviceEvents | summarize count() by DeviceId")
        rc005 = _find(results, "RC005")
        assert len(rc005) == 1
        assert rc005[0].passed is False
        assert rc005[0].severity.value == "warning"

    def test_summarize_with_arg_max_no_warning(self):
        kql = "DeviceEvents | summarize (Timestamp, ReportId)=arg_max(Timestamp, ReportId), count() by DeviceId"
        results = _validate(kql)
        rc005 = _find(results, "RC005")
        assert len(rc005) == 0  # No warning when arg_max used

    def test_summarize_with_timestamp_in_by_no_warning(self):
        kql = "DeviceEvents | summarize count() by Timestamp, DeviceId"
        results = _validate(kql)
        rc005 = _find(results, "RC005")
        assert len(rc005) == 0


class TestRC006ProjectExcludesRequired:
    def test_project_missing_timestamp_fails(self):
        results = _validate("DeviceEvents | project DeviceId, ReportId, FileName")
        rc006 = _find(results, "RC006")
        assert len(rc006) == 1
        assert rc006[0].passed is False
        assert "Timestamp" in rc006[0].message

    def test_project_with_all_required_no_error(self):
        results = _validate("DeviceEvents | project Timestamp, DeviceId, ReportId, FileName")
        rc006 = _find(results, "RC006")
        assert len(rc006) == 0  # No error when all required present


class TestRC007ProjectAwayRequired:
    def test_project_away_report_id_fails(self):
        results = _validate("DeviceEvents | project-away ReportId")
        rc007 = _find(results, "RC007")
        assert len(rc007) == 1
        assert rc007[0].passed is False
        assert "ReportId" in rc007[0].message

    def test_project_away_timestamp_fails(self):
        results = _validate("DeviceEvents | project-away Timestamp")
        rc007 = _find(results, "RC007")
        assert len(rc007) == 1
        assert rc007[0].passed is False
        assert "Timestamp" in rc007[0].message

    def test_project_away_non_required_no_error(self):
        results = _validate("DeviceEvents | project-away FileName")
        rc007 = _find(results, "RC007")
        assert len(rc007) == 0
