"""Tests for action column validation rules ACT001-ACT005."""

from cdv.parser.extractor import extract
from cdv.parser.tokenizer import tokenize
from cdv.rules.columns import get_relevant_actions, get_table_product
from cdv.validators.action_columns import ActionColumnsValidator


def _validate(kql: str):
    parsed = extract(tokenize(kql))
    return ActionColumnsValidator().validate(parsed)


def _find(results, rule_id):
    return [r for r in results if r.rule_id == rule_id]


def _rule_ids(results):
    return {r.rule_id for r in results}


class TestACT001DeviceActions:
    def test_device_id_present(self):
        results = _validate("DeviceEvents | project Timestamp, DeviceId, ReportId")
        act001 = _find(results, "ACT001")
        assert "available" in act001[0].message
        assert "DeviceId" in act001[0].message

    def test_device_id_missing(self):
        results = _validate("DeviceEvents | project Timestamp, ReportId, FileName")
        act001 = _find(results, "ACT001")
        assert "not available" in act001[0].message

    def test_implicit_columns_available(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        act001 = _find(results, "ACT001")
        assert "available" in act001[0].message
        assert "implicitly" in act001[0].message


class TestACT002FileActions:
    def test_sha1_present(self):
        results = _validate("DeviceEvents | project Timestamp, DeviceId, ReportId, SHA1")
        act002 = _find(results, "ACT002")
        assert "available" in act002[0].message

    def test_sha256_present(self):
        results = _validate("DeviceEvents | project Timestamp, DeviceId, ReportId, SHA256")
        act002 = _find(results, "ACT002")
        assert "available" in act002[0].message

    def test_initiating_process_sha1_present(self):
        results = _validate("DeviceEvents | project Timestamp, DeviceId, ReportId, InitiatingProcessSHA1")
        act002 = _find(results, "ACT002")
        assert "available" in act002[0].message

    def test_no_hash_columns(self):
        results = _validate("DeviceEvents | project Timestamp, DeviceId, ReportId, FileName")
        act002 = _find(results, "ACT002")
        assert "not available" in act002[0].message

    def test_quarantine_hint_without_device_id(self):
        """SHA1 present but DeviceId missing -> quarantine hint shown."""
        results = _validate("DeviceEvents | project Timestamp, ReportId, SHA1")
        act002 = _find(results, "ACT002")
        assert act002[0].passed is True
        assert "Quarantine" in act002[0].suggestion

    def test_no_quarantine_hint_with_device_id(self):
        """SHA1 present and DeviceId present -> no quarantine hint."""
        results = _validate("DeviceEvents | project Timestamp, DeviceId, ReportId, SHA1")
        act002 = _find(results, "ACT002")
        assert act002[0].passed is True
        assert "Quarantine" not in act002[0].suggestion


class TestACT003UserCompromise:
    def test_account_object_id_present(self):
        results = _validate("CloudAppEvents | project Timestamp, ReportId, AccountObjectId")
        act003 = _find(results, "ACT003")
        assert "available" in act003[0].message

    def test_recipient_object_id_present(self):
        results = _validate("EmailEvents | project Timestamp, ReportId, RecipientObjectId, RecipientEmailAddress")
        act003 = _find(results, "ACT003")
        assert "available" in act003[0].message

    def test_no_object_id_columns(self):
        results = _validate("IdentityLogonEvents | project Timestamp, ReportId, AccountUpn")
        act003 = _find(results, "ACT003")
        assert "not available" in act003[0].message


class TestACT004UserDisable:
    def test_account_sid_present(self):
        results = _validate("IdentityLogonEvents | project Timestamp, ReportId, AccountSid, AccountUpn")
        act004 = _find(results, "ACT004")
        assert "available" in act004[0].message

    def test_no_sid_columns(self):
        results = _validate("IdentityLogonEvents | project Timestamp, ReportId, AccountUpn")
        act004 = _find(results, "ACT004")
        assert "not available" in act004[0].message


class TestACT005EmailActions:
    def test_both_email_columns_present(self):
        results = _validate("EmailEvents | project Timestamp, ReportId, NetworkMessageId, RecipientEmailAddress")
        act005 = _find(results, "ACT005")
        assert "available" in act005[0].message
        assert "not available" not in act005[0].message

    def test_missing_network_message_id(self):
        results = _validate("EmailEvents | project Timestamp, ReportId, RecipientEmailAddress")
        act005 = _find(results, "ACT005")
        assert "not available" in act005[0].message
        assert "NetworkMessageId" in act005[0].message

    def test_missing_recipient_email(self):
        results = _validate("EmailEvents | project Timestamp, ReportId, NetworkMessageId, DeviceId")
        act005 = _find(results, "ACT005")
        assert "not available" in act005[0].message
        assert "RecipientEmailAddress" in act005[0].message

    def test_implicit_columns_available(self):
        results = _validate("EmailEvents | where Subject contains 'phishing'")
        act005 = _find(results, "ACT005")
        assert "available" in act005[0].message
        assert "implicitly" in act005[0].message


# ---------------------------------------------------------------------------
# Table-to-product mapping tests
# ---------------------------------------------------------------------------


class TestGetTableProduct:
    """Verify get_table_product() for all product categories."""

    # MDE
    def test_device_events_is_mde(self):
        assert get_table_product("DeviceEvents") == "mde"

    def test_device_tvm_is_mde(self):
        assert get_table_product("DeviceTvmSoftwareInventory") == "mde"

    # MDO — prefix tables
    def test_email_events_is_mdo(self):
        assert get_table_product("EmailEvents") == "mdo"

    def test_email_attachment_info_is_mdo(self):
        assert get_table_product("EmailAttachmentInfo") == "mdo"

    # MDO — explicit mapping (no Email prefix)
    def test_url_click_events_is_mdo(self):
        assert get_table_product("UrlClickEvents") == "mdo"

    def test_campaign_info_is_mdo(self):
        assert get_table_product("CampaignInfo") == "mdo"

    def test_file_malicious_content_is_mdo(self):
        assert get_table_product("FileMaliciousContentInfo") == "mdo"

    def test_message_events_is_mdo(self):
        assert get_table_product("MessageEvents") == "mdo"

    def test_message_post_delivery_is_mdo(self):
        assert get_table_product("MessagePostDeliveryEvents") == "mdo"

    def test_message_url_info_is_mdo(self):
        assert get_table_product("MessageUrlInfo") == "mdo"

    # MDI
    def test_identity_logon_events_is_mdi(self):
        assert get_table_product("IdentityLogonEvents") == "mdi"

    def test_identity_info_is_mdi(self):
        assert get_table_product("IdentityInfo") == "mdi"

    # Cloud Apps / MDA
    def test_cloud_app_events_is_mda(self):
        assert get_table_product("CloudAppEvents") == "mda"

    def test_behavior_info_is_mda(self):
        assert get_table_product("BehaviorInfo") == "mda"

    def test_behavior_entities_is_mda(self):
        assert get_table_product("BehaviorEntities") == "mda"

    def test_oauth_app_info_is_mda(self):
        assert get_table_product("OAuthAppInfo") == "mda"

    # Entra ID — prefix tables
    def test_aad_signin_is_entra_id(self):
        assert get_table_product("AADSignInEventsBeta") == "entra_id"

    def test_aad_spn_signin_is_entra_id(self):
        assert get_table_product("AADSpnSignInEventsBeta") == "entra_id"

    def test_entra_signin_is_entra_id(self):
        assert get_table_product("EntraIdSignInEvents") == "entra_id"

    def test_entra_spn_signin_is_entra_id(self):
        assert get_table_product("EntraIdSpnSignInEvents") == "entra_id"

    # Entra ID — explicit mapping
    def test_graph_api_audit_is_entra_id(self):
        assert get_table_product("GraphApiAuditEvents") == "entra_id"

    # Defender for Cloud (NOT Cloud Apps)
    def test_cloud_audit_events_is_defender_for_cloud(self):
        assert get_table_product("CloudAuditEvents") == "defender_for_cloud"

    def test_cloud_process_events_is_defender_for_cloud(self):
        assert get_table_product("CloudProcessEvents") == "defender_for_cloud"

    def test_cloud_storage_is_defender_for_cloud(self):
        assert get_table_product("CloudStorageAggregatedEvents") == "defender_for_cloud"

    # Purview
    def test_data_security_behaviors_is_purview(self):
        assert get_table_product("DataSecurityBehaviors") == "purview"

    def test_data_security_events_is_purview(self):
        assert get_table_product("DataSecurityEvents") == "purview"

    # MSEM
    def test_exposure_graph_edges_is_msem(self):
        assert get_table_product("ExposureGraphEdges") == "msem"

    def test_exposure_graph_nodes_is_msem(self):
        assert get_table_product("ExposureGraphNodes") == "msem"

    # XDR Alert
    def test_alert_info_is_xdr_alert(self):
        assert get_table_product("AlertInfo") == "xdr_alert"

    def test_alert_evidence_is_xdr_alert(self):
        assert get_table_product("AlertEvidence") == "xdr_alert"

    # XDR platform
    def test_disruption_is_xdr(self):
        assert get_table_product("DisruptionAndResponseEvents") == "xdr"

    def test_ai_agents_info_is_xdr(self):
        assert get_table_product("AIAgentsInfo") == "xdr"

    # Sentinel
    def test_sentinel_cl_table(self):
        assert get_table_product("MyCustomTable_CL") == "sentinel"

    def test_sentinel_known_table(self):
        assert get_table_product("SecurityEvent") == "sentinel"

    # Unknown
    def test_unknown_table(self):
        assert get_table_product("SomeRandomTable") == "unknown"


# ---------------------------------------------------------------------------
# Table-aware action filtering tests
# ---------------------------------------------------------------------------


class TestTableAwareFiltering:
    """Verify that only relevant actions are shown per table product."""

    def test_email_events_only_act003_act005(self):
        """EmailEvents (MDO) should only show ACT003 + ACT005."""
        results = _validate("EmailEvents | project Timestamp, ReportId, RecipientEmailAddress")
        ids = _rule_ids(results)
        assert ids == {"ACT003", "ACT005"}

    def test_device_events_only_device_file_actions(self):
        """DeviceEvents (MDE) should show only ACT001 + ACT002."""
        results = _validate("DeviceEvents | project Timestamp, DeviceId, ReportId")
        ids = _rule_ids(results)
        assert ids == {"ACT001", "ACT002"}

    def test_identity_events_act003_act004(self):
        """IdentityLogonEvents (MDI) should show ACT003 + ACT004."""
        results = _validate("IdentityLogonEvents | project Timestamp, ReportId, AccountUpn")
        ids = _rule_ids(results)
        assert ids == {"ACT003", "ACT004"}

    def test_cloud_app_events_only_act003(self):
        """CloudAppEvents (MDA) should show only ACT003."""
        results = _validate("CloudAppEvents | project Timestamp, ReportId, AccountObjectId")
        ids = _rule_ids(results)
        assert ids == {"ACT003"}

    def test_alert_evidence_all_actions(self):
        """AlertEvidence (XDR alert) should show all 5 actions."""
        results = _validate("AlertEvidence | project Timestamp, DeviceId")
        ids = _rule_ids(results)
        assert ids == {"ACT001", "ACT002", "ACT003", "ACT004", "ACT005"}

    def test_unknown_table_all_actions(self):
        """Unknown tables should show all 5 actions (safe fallback)."""
        results = _validate("SomeRandomTable | project Timestamp, ReportId, DeviceId")
        ids = _rule_ids(results)
        assert ids == {"ACT001", "ACT002", "ACT003", "ACT004", "ACT005"}

    def test_sentinel_table_all_actions(self):
        """Sentinel tables should show all 5 actions."""
        results = _validate("MyCustomTable_CL | where TimeGenerated > ago(1h)")
        ids = _rule_ids(results)
        assert ids == {"ACT001", "ACT002", "ACT003", "ACT004", "ACT005"}

    def test_url_click_events_mdo_actions(self):
        """UrlClickEvents (MDO) should show ACT003 + ACT005."""
        results = _validate("UrlClickEvents | project Timestamp, ReportId, RecipientEmailAddress")
        ids = _rule_ids(results)
        assert ids == {"ACT003", "ACT005"}

    def test_entra_id_table_act003_act004(self):
        """AADSignInEventsBeta (Entra ID) should show ACT003 + ACT004."""
        results = _validate("AADSignInEventsBeta | project Timestamp, ReportId, AccountObjectId")
        ids = _rule_ids(results)
        assert ids == {"ACT003", "ACT004"}

    def test_exposure_graph_no_actions(self):
        """ExposureGraphNodes (MSEM) should show no actions."""
        results = _validate("ExposureGraphNodes | project Timestamp, ReportId")
        ids = _rule_ids(results)
        assert ids == set()

    def test_message_events_mdo_actions(self):
        """MessageEvents (MDO) should show ACT003 + ACT005."""
        results = _validate("MessageEvents | project Timestamp, ReportId, RecipientEmailAddress")
        ids = _rule_ids(results)
        assert ids == {"ACT003", "ACT005"}

    def test_data_security_events_purview_actions(self):
        """DataSecurityEvents (Purview) should show ACT001 + ACT003."""
        results = _validate("DataSecurityEvents | project Timestamp, ReportId, DeviceId, AccountObjectId")
        ids = _rule_ids(results)
        assert ids == {"ACT001", "ACT003"}


# ---------------------------------------------------------------------------
# RBAC permissions in output tests
# ---------------------------------------------------------------------------


class TestPermissionsInfo:
    """Verify that RBAC permissions are shown in suggestion for available actions."""

    def test_device_action_shows_rbac(self):
        results = _validate("DeviceEvents | project Timestamp, DeviceId, ReportId")
        act001 = _find(results, "ACT001")
        assert act001[0].passed is True
        assert "Response (manage)" in act001[0].suggestion
        assert "Security Operator" in act001[0].suggestion

    def test_email_action_shows_rbac(self):
        results = _validate("EmailEvents | project Timestamp, ReportId, NetworkMessageId, RecipientEmailAddress")
        act005 = _find(results, "ACT005")
        assert act005[0].passed is True
        assert "Email & collaboration advanced actions (manage)" in act005[0].suggestion
        assert "Search and Purge" in act005[0].suggestion

    def test_user_disable_shows_rbac(self):
        results = _validate("IdentityLogonEvents | project Timestamp, ReportId, AccountSid, AccountUpn")
        act004 = _find(results, "ACT004")
        assert act004[0].passed is True
        assert "Response (manage)" in act004[0].suggestion
        assert "User Administrator" in act004[0].suggestion

    def test_unavailable_action_shows_column_hint_not_rbac(self):
        """Unavailable actions should show column requirements, not RBAC info."""
        results = _validate("DeviceEvents | project Timestamp, DeviceId, ReportId, FileName")
        act002 = _find(results, "ACT002")
        assert act002[0].passed is False
        assert "To enable this action" in act002[0].suggestion

    def test_implicit_columns_shows_rbac(self):
        results = _validate("DeviceEvents | where ActionType == 'x'")
        act001 = _find(results, "ACT001")
        assert act001[0].passed is True
        assert "Response (manage)" in act001[0].suggestion
