"""Tests for NRT eligibility validation rules NRT001-NRT007."""

from cdv.parser.extractor import extract
from cdv.parser.tokenizer import tokenize
from cdv.validators.nrt_eligibility import NrtEligibilityValidator


def _validate(kql: str):
    parsed = extract(tokenize(kql))
    return NrtEligibilityValidator().validate(parsed)


def _find(results, rule_id):
    return [r for r in results if r.rule_id == rule_id]


def _all_pass(results):
    return all(r.passed for r in results)


class TestNRT001SingleTable:
    def test_single_table_passes(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        nrt001 = _find(results, "NRT001")
        assert nrt001[0].passed is True

    def test_join_multiple_tables_fails(self):
        results = _validate("DeviceProcessEvents | join kind=inner (DeviceFileEvents) on DeviceId")
        nrt001 = _find(results, "NRT001")
        assert nrt001[0].passed is False

    def test_union_multiple_tables_fails(self):
        results = _validate("union DeviceEvents, DeviceProcessEvents | where ActionType == 'x'")
        nrt001 = _find(results, "NRT001")
        assert nrt001[0].passed is False


class TestNRT002NoJoin:
    def test_no_join_passes(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        nrt002 = _find(results, "NRT002")
        assert nrt002[0].passed is True

    def test_join_fails(self):
        results = _validate("DeviceEvents | join (DeviceInfo) on DeviceId")
        nrt002 = _find(results, "NRT002")
        assert nrt002[0].passed is False


class TestNRT003NoUnion:
    def test_no_union_passes(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        nrt003 = _find(results, "NRT003")
        assert nrt003[0].passed is True

    def test_union_fails(self):
        results = _validate("union DeviceEvents, DeviceProcessEvents")
        nrt003 = _find(results, "NRT003")
        assert nrt003[0].passed is False


class TestNRT004NoExternaldata:
    def test_no_externaldata_passes(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        nrt004 = _find(results, "NRT004")
        assert nrt004[0].passed is True

    def test_externaldata_fails(self):
        results = _validate("DeviceEvents | where DeviceId in (externaldata(DeviceId:string)[@'url'])")
        nrt004 = _find(results, "NRT004")
        assert nrt004[0].passed is False


class TestNRT005NoComments:
    def test_no_comments_passes(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        nrt005 = _find(results, "NRT005")
        assert nrt005[0].passed is True

    def test_single_line_comment_fails(self):
        results = _validate("// Comment\nDeviceEvents | where ActionType == 'x'")
        nrt005 = _find(results, "NRT005")
        assert nrt005[0].passed is False

    def test_block_comment_fails(self):
        results = _validate("/* block */\nDeviceEvents | where ActionType == 'x'")
        nrt005 = _find(results, "NRT005")
        assert nrt005[0].passed is False


class TestNRT006TableSupportsNRT:
    def test_device_events_supports_nrt(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        nrt006 = _find(results, "NRT006")
        assert nrt006[0].passed is True

    def test_device_process_events_supports_nrt(self):
        results = _validate("DeviceProcessEvents | where FileName == 'powershell.exe'")
        nrt006 = _find(results, "NRT006")
        assert nrt006[0].passed is True

    def test_email_events_supports_nrt(self):
        results = _validate("EmailEvents | where Subject contains 'phishing'")
        nrt006 = _find(results, "NRT006")
        assert nrt006[0].passed is True

    def test_campaign_info_not_nrt(self):
        results = _validate("CampaignInfo | where x == 1")
        nrt006 = _find(results, "NRT006")
        assert nrt006[0].passed is False

    def test_sentinel_nrt_supported(self):
        results = _validate("CommonSecurityLog | where DeviceVendor == 'Palo Alto'")
        nrt006 = _find(results, "NRT006")
        assert nrt006[0].passed is True

    def test_unknown_table_not_nrt(self):
        results = _validate("FakeTable | where x == 1")
        nrt006 = _find(results, "NRT006")
        assert nrt006[0].passed is False


class TestNRT007EmailEventsColumns:
    def test_email_events_with_excluded_column(self):
        kql = "EmailEvents | where LatestDeliveryLocation == 'Inbox'"
        results = _validate(kql)
        nrt007 = _find(results, "NRT007")
        assert len(nrt007) == 1
        assert nrt007[0].passed is False
        assert "LatestDeliveryLocation" in nrt007[0].message

    def test_email_events_without_excluded_columns(self):
        kql = "EmailEvents | where Subject contains 'phishing'"
        results = _validate(kql)
        nrt007 = _find(results, "NRT007")
        assert len(nrt007) == 0

    def test_non_email_table_no_nrt007(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        nrt007 = _find(results, "NRT007")
        assert len(nrt007) == 0


class TestFullNRTEligibility:
    def test_simple_nrt_eligible_query(self):
        kql = "DeviceProcessEvents | where FileName == 'powershell.exe'"
        results = _validate(kql)
        # All NRT checks should pass
        non_passed = [r for r in results if not r.passed]
        assert len(non_passed) == 0

    def test_nrt_ineligible_with_comments(self):
        kql = "// detect powershell\nDeviceEvents | where ActionType == 'x'"
        results = _validate(kql)
        nrt005 = _find(results, "NRT005")
        assert nrt005[0].passed is False

    def test_nrt_ineligible_unsupported_table(self):
        kql = "CampaignInfo | where x == 1"
        results = _validate(kql)
        nrt006 = _find(results, "NRT006")
        assert nrt006[0].passed is False
