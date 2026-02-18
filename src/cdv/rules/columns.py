"""Column sets for custom detection rule validation.

Source: https://learn.microsoft.com/defender-xdr/custom-detection-rules
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Impacted asset columns (at least one required for entity mapping)
# ---------------------------------------------------------------------------

IMPACTED_ASSET_COLUMNS: set[str] = {
    # Device
    "DeviceId",
    "DeviceName",
    "RemoteDeviceName",
    # Email / Mailbox
    "RecipientEmailAddress",
    "SenderFromAddress",
    "SenderMailFromAddress",
    # User identity (Object ID)
    "SenderObjectId",
    "RecipientObjectId",
    "AccountObjectId",
    # User identity (SID / UPN)
    "AccountSid",
    "AccountUpn",
    "InitiatingProcessAccountSid",
    "InitiatingProcessAccountUpn",
    "InitiatingProcessAccountObjectId",
}

# ---------------------------------------------------------------------------
# Action-specific column requirements
# ---------------------------------------------------------------------------

# Device actions: isolate, collect investigation package, run AV scan,
# initiate investigation, restrict app execution
DEVICE_ACTION_COLUMNS: set[str] = {"DeviceId"}

# File actions: allow/block, quarantine
FILE_ACTION_COLUMNS: set[str] = {
    "SHA1",
    "InitiatingProcessSHA1",
    "SHA256",
    "InitiatingProcessSHA256",
}

# User action: mark as compromised
USER_COMPROMISE_COLUMNS: set[str] = {
    "AccountObjectId",
    "InitiatingProcessAccountObjectId",
    "RecipientObjectId",
}

# User actions: disable user, force password reset (require SID)
USER_DISABLE_COLUMNS: set[str] = {
    "AccountSid",
    "InitiatingProcessAccountSid",
    "RequestAccountSid",
    "OnPremSid",
}

# Email actions: move to folder, delete (BOTH columns required)
EMAIL_ACTION_REQUIRED_COLUMNS: frozenset[str] = frozenset({
    "NetworkMessageId",
    "RecipientEmailAddress",
})

# ---------------------------------------------------------------------------
# Action descriptions for output
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Non-supported columns per table for custom detection rules (NRT)
# Source: https://learn.microsoft.com/defender-xdr/custom-detection-rules
#         https://learn.microsoft.com/defender-xdr/advanced-hunting-emailevents-table
#
# EmailEvents NRT: LatestDeliveryLocation and LatestDeliveryAction are
# explicitly excluded from Continuous (NRT) frequency.
# These columns are also not available in the Streaming API.
#
# General rule from MS Learn:
# "Only columns that are generally available support Continuous (NRT) frequency."
# ---------------------------------------------------------------------------

NON_SUPPORTED_NRT_COLUMNS: dict[str, set[str]] = {
    "EmailEvents": {
        "LatestDeliveryLocation",
        "LatestDeliveryAction",
    },
}

# ---------------------------------------------------------------------------
# Table-to-product mapping for action relevance filtering
# Source: https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables
# ---------------------------------------------------------------------------

# Explicit mapping for tables that don't follow prefix conventions
TABLE_TO_PRODUCT: dict[str, str] = {
    # MDO — tables without Email prefix
    "UrlClickEvents": "mdo",
    "CampaignInfo": "mdo",
    "FileMaliciousContentInfo": "mdo",
    "MessageEvents": "mdo",
    "MessagePostDeliveryEvents": "mdo",
    "MessageUrlInfo": "mdo",
    # Cloud Apps / MDA — tables without CloudApp prefix
    "BehaviorInfo": "mda",
    "BehaviorEntities": "mda",
    "OAuthAppInfo": "mda",
    # Entra ID — tables without AAD/Entra prefix
    "GraphApiAuditEvents": "entra_id",
    # Defender for Cloud — disambiguation from CloudAppEvents (MDA)
    "CloudAuditEvents": "defender_for_cloud",
    "CloudProcessEvents": "defender_for_cloud",
    "CloudStorageAggregatedEvents": "defender_for_cloud",
    # Microsoft Purview (Insider Risk Management)
    "DataSecurityBehaviors": "purview",
    "DataSecurityEvents": "purview",
    # Exposure Management (MSEM)
    "ExposureGraphEdges": "msem",
    "ExposureGraphNodes": "msem",
    # Defender XDR platform / cross-product
    "AlertInfo": "xdr_alert",
    "AlertEvidence": "xdr_alert",
    "DisruptionAndResponseEvents": "xdr",
    "AIAgentsInfo": "xdr",
}

# Prefix-based fallback for tables that follow naming conventions
PREFIX_TO_PRODUCT: dict[str, str] = {
    "Device": "mde",
    "Email": "mdo",
    "Identity": "mdi",
    "CloudApp": "mda",
    "AAD": "entra_id",
    "Entra": "entra_id",
    "Alert": "xdr_alert",
}

# Which actions are relevant per product
PRODUCT_RELEVANT_ACTIONS: dict[str, set[str]] = {
    "mde": {"ACT001", "ACT002"},
    "mdo": {"ACT003", "ACT005"},
    "mdi": {"ACT003", "ACT004"},
    "mda": {"ACT003"},
    "entra_id": {"ACT003", "ACT004"},
    "defender_for_cloud": {"ACT003"},
    "purview": {"ACT001", "ACT003"},
    "msem": set(),
    "xdr_alert": {"ACT001", "ACT002", "ACT003", "ACT004", "ACT005"},
    "xdr": {"ACT003"},
    "sentinel": {"ACT001", "ACT002", "ACT003", "ACT004", "ACT005"},
    "unknown": {"ACT001", "ACT002", "ACT003", "ACT004", "ACT005"},
}

ALL_ACTION_RULE_IDS: set[str] = {"ACT001", "ACT002", "ACT003", "ACT004", "ACT005"}


def get_table_product(table_name: str) -> str:
    """Determine which Defender product a table belongs to."""
    # 1. Check explicit mapping first
    if table_name in TABLE_TO_PRODUCT:
        return TABLE_TO_PRODUCT[table_name]

    # 2. Check Sentinel tables
    from cdv.rules.tables import is_sentinel_table
    if is_sentinel_table(table_name):
        return "sentinel"

    # 3. Check prefix-based mapping
    for prefix, product in PREFIX_TO_PRODUCT.items():
        if table_name.startswith(prefix):
            return product

    return "unknown"


def get_relevant_actions(table_name: str) -> set[str]:
    """Return the set of action rule IDs relevant for this table's product."""
    product = get_table_product(table_name)
    return PRODUCT_RELEVANT_ACTIONS.get(product, ALL_ACTION_RULE_IDS)


# ---------------------------------------------------------------------------
# RBAC permissions required per action (least privileged)
# Source: https://learn.microsoft.com/defender-xdr/custom-permissions-details
#         https://learn.microsoft.com/defender-xdr/custom-detection-rules
# ---------------------------------------------------------------------------

ACTION_PERMISSIONS: dict[str, dict[str, str]] = {
    "ACT001": {
        "unified_rbac": "Response (manage)",
        "entra_role": "Security Operator",
        "doc_url": "https://learn.microsoft.com/defender-xdr/custom-permissions-details",
    },
    "ACT002": {
        "unified_rbac": "Response (manage)",
        "entra_role": "Security Operator",
        "doc_url": "https://learn.microsoft.com/defender-xdr/custom-permissions-details",
    },
    "ACT003": {
        "unified_rbac": "Response (manage)",
        "entra_role": "Security Operator",
        "doc_url": "https://learn.microsoft.com/defender-xdr/custom-permissions-details",
    },
    "ACT004": {
        "unified_rbac": "Response (manage)",
        "entra_role": "User Administrator (Entra ID) / MDI sensor (AD)",
        "doc_url": "https://learn.microsoft.com/defender-for-identity/remediation-actions",
    },
    "ACT005": {
        "unified_rbac": "Email & collaboration advanced actions (manage)",
        "entra_role": "Search and Purge role",
        "doc_url": "https://learn.microsoft.com/defender-office-365/remediate-malicious-email-delivered-office-365",
    },
}

# ---------------------------------------------------------------------------
# Action descriptions for output
# ---------------------------------------------------------------------------

ACTION_DESCRIPTIONS: dict[str, dict[str, str | set[str] | bool]] = {
    "device": {
        "name": "Device actions (isolate, scan, investigate, restrict, collect package)",
        "columns": DEVICE_ACTION_COLUMNS,
        "require_all": False,
    },
    "file": {
        "name": "File actions (allow/block, quarantine)",
        "columns": FILE_ACTION_COLUMNS,
        "require_all": False,
    },
    "user_compromise": {
        "name": "Mark user as compromised",
        "columns": USER_COMPROMISE_COLUMNS,
        "require_all": False,
    },
    "user_disable": {
        "name": "Disable user / Force password reset",
        "columns": USER_DISABLE_COLUMNS,
        "require_all": False,
    },
    "email": {
        "name": "Email actions (move to folder, delete)",
        "columns": EMAIL_ACTION_REQUIRED_COLUMNS,
        "require_all": True,  # ALL columns must be present
    },
}
