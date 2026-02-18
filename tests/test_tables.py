"""Tests for table classification logic."""

from cdv.rules.tables import classify_table, is_sentinel_table


class TestClassifyMDETables:
    def test_device_events(self):
        tc = classify_table("DeviceEvents")
        assert tc.category == "mde"
        assert tc.required_timestamp == "Timestamp"
        assert "DeviceId" in tc.required_event_id_columns
        assert "ReportId" in tc.required_event_id_columns

    def test_device_process_events(self):
        tc = classify_table("DeviceProcessEvents")
        assert tc.category == "mde"
        assert tc.supports_nrt is True

    def test_device_tvm_not_nrt(self):
        tc = classify_table("DeviceTvmSoftwareInventory")
        assert tc.category == "mde"
        assert tc.supports_nrt is False


class TestClassifyAlertTables:
    def test_alert_info(self):
        tc = classify_table("AlertInfo")
        assert tc.category == "alert"
        assert tc.required_timestamp == "Timestamp"
        assert len(tc.required_event_id_columns) == 0

    def test_alert_evidence(self):
        tc = classify_table("AlertEvidence")
        assert tc.category == "alert"
        assert tc.supports_nrt is True


class TestClassifyOtherXDR:
    def test_email_events(self):
        tc = classify_table("EmailEvents")
        assert tc.category == "other_xdr"
        assert "ReportId" in tc.required_event_id_columns
        assert tc.supports_nrt is True

    def test_identity_logon_events(self):
        tc = classify_table("IdentityLogonEvents")
        assert tc.category == "other_xdr"
        assert "ReportId" in tc.required_event_id_columns
        assert tc.supports_nrt is True

    def test_cloud_app_events(self):
        tc = classify_table("CloudAppEvents")
        assert tc.category == "other_xdr"
        assert tc.supports_nrt is True

    def test_campaign_info_not_nrt(self):
        tc = classify_table("CampaignInfo")
        assert tc.category == "other_xdr"
        assert tc.supports_nrt is False

    def test_url_click_events(self):
        tc = classify_table("UrlClickEvents")
        assert tc.category == "other_xdr"
        assert tc.supports_nrt is True


class TestClassifySentinel:
    def test_custom_cl_table(self):
        tc = classify_table("MyCustomTable_CL")
        assert tc.category == "sentinel"
        assert tc.required_timestamp == "TimeGenerated"
        assert len(tc.required_event_id_columns) == 0

    def test_known_sentinel_table(self):
        tc = classify_table("SecurityEvent")
        assert tc.category == "sentinel"
        assert tc.required_timestamp == "TimeGenerated"

    def test_common_security_log(self):
        tc = classify_table("CommonSecurityLog")
        assert tc.category == "sentinel"
        assert tc.supports_nrt is True

    def test_syslog(self):
        tc = classify_table("Syslog")
        assert tc.category == "sentinel"
        assert tc.supports_nrt is False

    def test_sentinel_nrt_supported(self):
        tc = classify_table("AuditLogs")
        assert tc.category == "sentinel"
        assert tc.supports_nrt is True


class TestClassifyUnknown:
    def test_unknown_table(self):
        tc = classify_table("FakeTable")
        assert tc.category == "unknown"
        assert tc.required_timestamp == "Timestamp"
        assert tc.supports_nrt is False
        assert tc.supports_scheduled is True


class TestIsSentinelTable:
    def test_cl_suffix(self):
        assert is_sentinel_table("MyTable_CL") is True

    def test_known_sentinel(self):
        assert is_sentinel_table("SecurityEvent") is True

    def test_xdr_table(self):
        assert is_sentinel_table("DeviceEvents") is False

    def test_unknown_table(self):
        assert is_sentinel_table("RandomName") is False
