"""Integration tests: full validation engine against realistic queries.

Covers the 15 verification scenarios from the implementation plan.
"""

from cdv.validators.engine import ValidationEngine


engine = ValidationEngine()


def _find(results, rule_id):
    return [r for r in results if r.rule_id == rule_id]


def _errors(report):
    return [r for r in report.results if not r.passed and r.severity.value == "error"]


def _warnings(report):
    return [r for r in report.results if not r.passed and r.severity.value == "warning"]


class TestScenario01ValidMDEQuery:
    """Simple valid MDE query with all required columns."""

    def test_no_errors(self):
        kql = "DeviceProcessEvents | where ActionType == 'ProcessCreated' | project Timestamp, DeviceId, ReportId, FileName"
        report = engine.validate(kql)
        assert report.error_count == 0

    def test_table_recognized(self):
        kql = "DeviceProcessEvents | where ActionType == 'ProcessCreated' | project Timestamp, DeviceId, ReportId, FileName"
        report = engine.validate(kql)
        tbl001 = _find(report.results, "TBL001")
        assert tbl001[0].passed is True

    def test_nrt_eligible(self):
        kql = "DeviceProcessEvents | where ActionType == 'ProcessCreated' | project Timestamp, DeviceId, ReportId, FileName"
        report = engine.validate(kql)
        nrt_failures = [r for r in report.results if r.category.value == "nrt_eligibility" and not r.passed]
        assert len(nrt_failures) == 0


class TestScenario02MissingColumns:
    """Query with project that removes required columns."""

    def test_missing_columns_detected(self):
        kql = "DeviceEvents | where ActionType == 'AntivirusDetection' | project FileName"
        report = engine.validate(kql)
        assert report.error_count > 0

    def test_timestamp_missing(self):
        kql = "DeviceEvents | where ActionType == 'AntivirusDetection' | project FileName"
        report = engine.validate(kql)
        rc001 = _find(report.results, "RC001")
        assert rc001[0].passed is False

    def test_device_id_missing(self):
        kql = "DeviceEvents | where ActionType == 'AntivirusDetection' | project FileName"
        report = engine.validate(kql)
        rc003 = _find(report.results, "RC003")
        assert rc003[0].passed is False

    def test_impacted_asset_missing(self):
        kql = "DeviceEvents | where ActionType == 'AntivirusDetection' | project FileName"
        report = engine.validate(kql)
        rc004 = _find(report.results, "RC004")
        assert rc004[0].passed is False


class TestScenario03JoinQuery:
    """Join query should be NRT-ineligible."""

    def test_nrt_ineligible(self):
        kql = "DeviceEvents | join DeviceInfo on DeviceId"
        report = engine.validate(kql)
        nrt002 = _find(report.results, "NRT002")
        assert nrt002[0].passed is False

    def test_multiple_tables_detected(self):
        kql = "DeviceEvents | join DeviceInfo on DeviceId"
        report = engine.validate(kql)
        nrt001 = _find(report.results, "NRT001")
        assert nrt001[0].passed is False


class TestScenario04SummarizeWithoutArgMax:
    """Summarize that drops Timestamp and ReportId."""

    def test_warns_about_lost_columns(self):
        kql = "DeviceEvents | summarize count() by DeviceId"
        report = engine.validate(kql)
        assert report.warning_count > 0

    def test_timestamp_loss_detected(self):
        kql = "DeviceEvents | summarize count() by DeviceId"
        report = engine.validate(kql)
        # Should have RC005 (warning about summarize dropping Timestamp)
        rc005 = _find(report.results, "RC005")
        assert len(rc005) == 1
        assert rc005[0].passed is False


class TestScenario05SummarizeWithArgMax:
    """Summarize with arg_max correctly preserves columns."""

    def test_no_timestamp_warning(self):
        kql = "DeviceEvents | summarize (Timestamp, ReportId)=arg_max(Timestamp, ReportId), count() by DeviceId | where count_ > 5"
        report = engine.validate(kql)
        rc005 = _find(report.results, "RC005")
        assert len(rc005) == 0  # No warning about losing Timestamp


class TestScenario06EmailQueryWithActions:
    """Email query with all needed columns for email actions."""

    def test_no_errors(self):
        kql = "EmailEvents | where Subject contains 'phishing' | project Timestamp, NetworkMessageId, RecipientEmailAddress, ReportId"
        report = engine.validate(kql)
        assert report.error_count == 0

    def test_email_actions_available(self):
        kql = "EmailEvents | where Subject contains 'phishing' | project Timestamp, NetworkMessageId, RecipientEmailAddress, ReportId"
        report = engine.validate(kql)
        act005 = _find(report.results, "ACT005")
        assert "available" in act005[0].message
        assert "not available" not in act005[0].message


class TestScenario07IdentityQuery:
    """Identity table query."""

    def test_no_errors(self):
        kql = "IdentityLogonEvents | where ActionType == 'LogonFailed' | project Timestamp, ReportId, AccountUpn"
        report = engine.validate(kql)
        assert report.error_count == 0

    def test_table_recognized(self):
        kql = "IdentityLogonEvents | where ActionType == 'LogonFailed' | project Timestamp, ReportId, AccountUpn"
        report = engine.validate(kql)
        tbl001 = _find(report.results, "TBL001")
        assert tbl001[0].passed is True


class TestScenario08CloudAppEvents:
    """CloudAppEvents query."""

    def test_no_errors(self):
        kql = "CloudAppEvents | where ActionType == 'FileDownloaded' | project Timestamp, ReportId, AccountObjectId"
        report = engine.validate(kql)
        assert report.error_count == 0

    def test_user_compromise_action_available(self):
        kql = "CloudAppEvents | where ActionType == 'FileDownloaded' | project Timestamp, ReportId, AccountObjectId"
        report = engine.validate(kql)
        act003 = _find(report.results, "ACT003")
        assert "available" in act003[0].message


class TestScenario09UnknownSentinelTable:
    """Custom Sentinel table with _CL suffix."""

    def test_table_recognized_as_sentinel(self):
        kql = "MyCustomTable_CL | where TimeGenerated > ago(1h)"
        report = engine.validate(kql)
        tbl001 = _find(report.results, "TBL001")
        assert tbl001[0].passed is True

    def test_uses_time_generated(self):
        kql = "MyCustomTable_CL | where TimeGenerated > ago(1h)"
        report = engine.validate(kql)
        tbl002 = _find(report.results, "TBL002")
        assert "TimeGenerated" in tbl002[0].message


class TestScenario10NRTEligible:
    """Simple NRT-eligible query."""

    def test_all_nrt_checks_pass(self):
        kql = "DeviceProcessEvents | where FileName == 'powershell.exe'"
        report = engine.validate(kql)
        nrt_results = [r for r in report.results if r.category.value == "nrt_eligibility"]
        nrt_failures = [r for r in nrt_results if not r.passed]
        assert len(nrt_failures) == 0


class TestScenario11NRTWithComments:
    """Query with comments should fail NRT."""

    def test_nrt_fails_with_comments(self):
        kql = "// Comment\nDeviceEvents | where ActionType == 'x'"
        report = engine.validate(kql)
        nrt005 = _find(report.results, "NRT005")
        assert nrt005[0].passed is False


class TestScenario12ProjectAwayRequired:
    """project-away that removes required columns."""

    def test_project_away_report_id_error(self):
        kql = "DeviceEvents | project-away ReportId"
        report = engine.validate(kql)
        rc007 = _find(report.results, "RC007")
        assert len(rc007) == 1
        assert rc007[0].passed is False
        assert rc007[0].severity.value == "error"


class TestScenario13LetStatement:
    """Query with let statement(s)."""

    def test_let_stripped_table_found(self):
        kql = "let x = 5;\nDeviceEvents | where Timestamp > ago(1d) | project Timestamp, DeviceId, ReportId"
        report = engine.validate(kql)
        assert report.parsed_query.primary_table == "DeviceEvents"

    def test_let_query_validates_correctly(self):
        kql = "let x = 5;\nDeviceEvents | where Timestamp > ago(1d) | project Timestamp, DeviceId, ReportId"
        report = engine.validate(kql)
        assert report.error_count == 0


class TestScenario14AlertTable:
    """Alert table has simpler requirements (only Timestamp)."""

    def test_no_errors(self):
        kql = "AlertEvidence | where Timestamp > ago(1h) | project Timestamp, DeviceId"
        report = engine.validate(kql)
        assert report.error_count == 0

    def test_no_report_id_needed(self):
        kql = "AlertEvidence | project Timestamp, DeviceId"
        report = engine.validate(kql)
        rc003 = _find(report.results, "RC003")
        assert rc003[0].passed is True


class TestScenario15Union:
    """Union query should be NRT-ineligible."""

    def test_nrt_ineligible(self):
        kql = "union DeviceEvents, DeviceProcessEvents | where ActionType == 'x'"
        report = engine.validate(kql)
        nrt003 = _find(report.results, "NRT003")
        assert nrt003[0].passed is False

    def test_multiple_tables_detected(self):
        kql = "union DeviceEvents, DeviceProcessEvents | where ActionType == 'x'"
        report = engine.validate(kql)
        nrt001 = _find(report.results, "NRT001")
        assert nrt001[0].passed is False


class TestOutputFormats:
    """Test JSON and terminal output don't crash."""

    def test_json_output(self):
        from cdv.output.formatter import format_json
        kql = "DeviceEvents | where ActionType == 'x'"
        report = engine.validate(kql)
        json_str = format_json(report)
        import json
        data = json.loads(json_str)
        assert "results" in data
        assert "summary" in data

    def test_terminal_output(self):
        from io import StringIO
        from cdv.output.formatter import format_terminal
        kql = "DeviceEvents | where ActionType == 'x'"
        report = engine.validate(kql)
        buf = StringIO()
        format_terminal(report, no_color=True, out=buf)
        output = buf.getvalue()
        assert "Custom Detection Validator" in output
