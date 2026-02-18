"""Tests for table validation rules TBL001-TBL003."""

from cdv.parser.extractor import extract
from cdv.parser.tokenizer import tokenize
from cdv.validators.table_validator import TableValidator


def _validate(kql: str):
    parsed = extract(tokenize(kql))
    return TableValidator().validate(parsed)


def _find(results, rule_id):
    return [r for r in results if r.rule_id == rule_id]


class TestTBL001KnownTable:
    def test_known_xdr_table_passes(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        tbl001 = _find(results, "TBL001")
        assert len(tbl001) == 1
        assert tbl001[0].passed is True

    def test_known_email_table_passes(self):
        results = _validate("EmailEvents | where Subject contains 'phishing'")
        tbl001 = _find(results, "TBL001")
        assert tbl001[0].passed is True

    def test_unknown_table_warns(self):
        results = _validate("FakeTable | where x == 1")
        tbl001 = _find(results, "TBL001")
        assert tbl001[0].passed is False
        assert tbl001[0].severity.value == "warning"

    def test_sentinel_cl_table_passes(self):
        results = _validate("MyCustomTable_CL | where TimeGenerated > ago(1h)")
        tbl001 = _find(results, "TBL001")
        assert tbl001[0].passed is True

    def test_known_sentinel_table_passes(self):
        results = _validate("SecurityEvent | where EventID == 4625")
        tbl001 = _find(results, "TBL001")
        assert tbl001[0].passed is True

    def test_no_table_errors(self):
        results = _validate("| where x == 1")
        tbl001 = _find(results, "TBL001")
        assert tbl001[0].passed is False
        assert tbl001[0].severity.value == "error"


class TestTBL002TableClassification:
    def test_mde_table_shows_device_requirements(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        tbl002 = _find(results, "TBL002")
        assert len(tbl002) == 1
        assert "DeviceId" in tbl002[0].message
        assert "ReportId" in tbl002[0].message

    def test_alert_table_shows_timestamp_only(self):
        results = _validate("AlertEvidence | where Timestamp > ago(1h)")
        tbl002 = _find(results, "TBL002")
        assert "Timestamp" in tbl002[0].message

    def test_sentinel_table_shows_time_generated(self):
        results = _validate("SecurityEvent | where EventID == 4625")
        tbl002 = _find(results, "TBL002")
        assert "TimeGenerated" in tbl002[0].message

    def test_identity_table_shows_report_id(self):
        results = _validate("IdentityLogonEvents | where ActionType == 'LogonFailed'")
        tbl002 = _find(results, "TBL002")
        assert "ReportId" in tbl002[0].message


class TestTBL003NRTSupport:
    def test_nrt_supported_table(self):
        results = _validate("DeviceProcessEvents | where FileName == 'powershell.exe'")
        tbl003 = _find(results, "TBL003")
        assert "NRT" in tbl003[0].message
        assert "Scheduled" in tbl003[0].message

    def test_nrt_not_supported_table(self):
        results = _validate("CampaignInfo | where x == 1")
        tbl003 = _find(results, "TBL003")
        assert "Scheduled" in tbl003[0].message
        assert "not NRT" in tbl003[0].message

    def test_sentinel_nrt_supported(self):
        results = _validate("CommonSecurityLog | where DeviceVendor == 'Palo Alto'")
        tbl003 = _find(results, "TBL003")
        assert "NRT" in tbl003[0].message
