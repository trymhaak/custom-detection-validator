"""Complete table classification for Microsoft Defender XDR and Sentinel.

Source: https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables
        https://learn.microsoft.com/defender-xdr/custom-detection-rules
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class TableClassification:
    category: str  # mde, alert, other_xdr, sentinel, unknown
    required_timestamp: str  # "Timestamp" or "TimeGenerated"
    required_event_id_columns: tuple[str, ...]  # additional columns beyond timestamp
    supports_nrt: bool
    supports_scheduled: bool
    notes: str = ""


# ---------------------------------------------------------------------------
# All known XDR tables (from MS Learn Advanced Hunting schema reference)
# ---------------------------------------------------------------------------

ALL_XDR_TABLES: set[str] = {
    # MDE / Device tables
    "DeviceEvents",
    "DeviceFileEvents",
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "DeviceRegistryEvents",
    "DeviceLogonEvents",
    "DeviceImageLoadEvents",
    "DeviceFileCertificateInfo",
    "DeviceInfo",
    "DeviceNetworkInfo",
    "DeviceTvmSoftwareInventory",
    "DeviceTvmSoftwareVulnerabilities",
    "DeviceTvmSoftwareVulnerabilitiesKB",
    "DeviceTvmSecureConfigurationAssessment",
    "DeviceTvmSecureConfigurationAssessmentKB",
    "DeviceTvmSoftwareEvidenceBeta",
    "DeviceTvmHardwareFirmware",
    "DeviceTvmInfoGathering",
    "DeviceTvmInfoGatheringKB",
    "DeviceTvmBrowserExtensions",
    "DeviceTvmBrowserExtensionsKB",
    "DeviceTvmCertificateInfo",
    "DeviceBaselineComplianceAssessment",
    "DeviceBaselineComplianceAssessmentKB",
    "DeviceBaselineComplianceProfiles",
    # Alert tables
    "AlertInfo",
    "AlertEvidence",
    # Email tables (MDO)
    "EmailEvents",
    "EmailAttachmentInfo",
    "EmailPostDeliveryEvents",
    "EmailUrlInfo",
    "CampaignInfo",
    "FileMaliciousContentInfo",
    # Identity tables (MDI/MCAS)
    "IdentityDirectoryEvents",
    "IdentityLogonEvents",
    "IdentityQueryEvents",
    "IdentityInfo",
    "IdentityAccountInfo",
    "IdentityEvents",
    # Cloud tables
    "CloudAppEvents",
    "CloudAuditEvents",
    "CloudProcessEvents",
    "CloudStorageAggregatedEvents",
    # AAD / Entra tables
    "AADSignInEventsBeta",
    "AADSpnSignInEventsBeta",
    "EntraIdSignInEvents",
    "EntraIdSpnSignInEvents",
    # Behavior tables
    "BehaviorInfo",
    "BehaviorEntities",
    # URL/Click tables
    "UrlClickEvents",
    # Data Security
    "DataSecurityBehaviors",
    "DataSecurityEvents",
    # Exposure Management
    "ExposureGraphEdges",
    "ExposureGraphNodes",
    # AI
    "AIAgentsInfo",
    # Disruption
    "DisruptionAndResponseEvents",
    # Message (Teams)
    "MessageEvents",
    "MessagePostDeliveryEvents",
    "MessageUrlInfo",
    # Graph / OAuth
    "GraphApiAuditEvents",
    "OAuthAppInfo",
}

# ---------------------------------------------------------------------------
# NRT-supported tables (Continuous frequency)
# Source: https://learn.microsoft.com/defender-xdr/custom-detection-rules#tables-that-support-continuous-nrt-frequency
# ---------------------------------------------------------------------------

NRT_SUPPORTED_XDR: set[str] = {
    "AlertEvidence",
    "CloudAppEvents",
    "DeviceEvents",
    "DeviceFileCertificateInfo",
    "DeviceFileEvents",
    "DeviceImageLoadEvents",
    "DeviceLogonEvents",
    "DeviceNetworkEvents",
    "DeviceNetworkInfo",
    "DeviceInfo",
    "DeviceProcessEvents",
    "DeviceRegistryEvents",
    "EmailAttachmentInfo",
    "EmailEvents",  # except LatestDeliveryLocation and LatestDeliveryAction columns
    "EmailPostDeliveryEvents",
    "EmailUrlInfo",
    "IdentityDirectoryEvents",
    "IdentityLogonEvents",
    "IdentityQueryEvents",
    "UrlClickEvents",
}

NRT_SUPPORTED_SENTINEL: set[str] = {
    "ABAPAuditLog_CL",
    "AuditLogs",
    "AWSCloudTrail",
    "AWSGuardDuty",
    "AzureActivity",
    "Cisco_Umbrella_dns_CL",
    "Cisco_Umbrella_proxy_CL",
    "CommonSecurityLog",
    "GCPAuditLogs",
    "MicrosoftGraphActivityLogs",
    "OfficeActivity",
    "Okta_CL",
    "OktaV2_CL",
    "ProofpointPOD",
    "ProofPointTAPClicksPermitted_CL",
    "ProofPointTAPMessagesDelivered_CL",
    "SecurityAlert",
    "SecurityEvent",
    "SigninLogs",
}

# ---------------------------------------------------------------------------
# Known Sentinel tables (those without _CL suffix)
# ---------------------------------------------------------------------------

KNOWN_SENTINEL_TABLES: set[str] = {
    "AuditLogs",
    "SigninLogs",
    "CommonSecurityLog",
    "SecurityEvent",
    "SecurityAlert",
    "SecurityIncident",
    "OfficeActivity",
    "AzureActivity",
    "AWSCloudTrail",
    "AWSGuardDuty",
    "GCPAuditLogs",
    "MicrosoftGraphActivityLogs",
    "ProofpointPOD",
    "Syslog",
    "WindowsEvent",
    "DnsEvents",
    "Heartbeat",
    "W3CIISLog",
    "WindowsFirewall",
    "AADManagedIdentitySignInLogs",
    "AADNonInteractiveUserSignInLogs",
    "AADProvisioningLogs",
    "AADRiskyUsers",
    "AADServicePrincipalSignInLogs",
    "AADUserRiskEvents",
    "AzureDevOpsAuditing",
    "AzureDiagnostics",
    "AzureMetrics",
    "BehaviorAnalytics",
    "ContainerInventory",
    "ContainerLog",
    "Dynamics365Activity",
    "Event",
    "InsightsMetrics",
    "IntuneAuditLogs",
    "IntuneDevices",
    "LAQueryLogs",
    "MicrosoftAzureBastionAuditLogs",
    "MicrosoftPurviewInformationProtection",
    "Perf",
    "PowerBIActivity",
    "ProtectionStatus",
    "SecurityRecommendation",
    "SqlAtpStatus",
    "StorageBlobLogs",
    "StorageFileLogs",
    "ThreatIntelligenceIndicator",
    "Update",
    "Usage",
    "UserAccessAnalytics",
    "UserPeerAnalytics",
    "VMBoundPort",
    "VMComputer",
    "VMConnection",
    "VMProcess",
    "Anomalies",
    "AppDependencies",
    "AppTraces",
}


def is_sentinel_table(table_name: str) -> bool:
    """Check if a table is a Sentinel table (custom _CL or known Sentinel table)."""
    return table_name.endswith("_CL") or table_name in KNOWN_SENTINEL_TABLES


def classify_table(table_name: str) -> TableClassification:
    """Classify a table and return its requirements for custom detection rules."""

    # 1. Sentinel tables (_CL suffix or known Sentinel table)
    if is_sentinel_table(table_name):
        return TableClassification(
            category="sentinel",
            required_timestamp="TimeGenerated",
            required_event_id_columns=(),
            supports_nrt=table_name in NRT_SUPPORTED_SENTINEL,
            supports_scheduled=True,
            notes="Sentinel table - uses TimeGenerated instead of Timestamp",
        )

    # 2. Known XDR tables
    if table_name in ALL_XDR_TABLES:
        if table_name.startswith("Alert"):
            return TableClassification(
                category="alert",
                required_timestamp="Timestamp",
                required_event_id_columns=(),  # only Timestamp needed
                supports_nrt=table_name in NRT_SUPPORTED_XDR,
                supports_scheduled=True,
            )
        elif table_name.startswith("Device"):
            return TableClassification(
                category="mde",
                required_timestamp="Timestamp",
                required_event_id_columns=("DeviceId", "ReportId"),
                supports_nrt=table_name in NRT_SUPPORTED_XDR,
                supports_scheduled=True,
            )
        else:
            # All other XDR tables: Email*, Identity*, Cloud*, etc.
            return TableClassification(
                category="other_xdr",
                required_timestamp="Timestamp",
                required_event_id_columns=("ReportId",),
                supports_nrt=table_name in NRT_SUPPORTED_XDR,
                supports_scheduled=True,
            )

    # 3. Unknown table
    return TableClassification(
        category="unknown",
        required_timestamp="Timestamp",
        required_event_id_columns=("ReportId",),
        supports_nrt=False,
        supports_scheduled=True,
        notes="Unknown table - not found in Advanced Hunting schema. May be a custom Sentinel table (use _CL suffix).",
    )


# Human-readable category names
CATEGORY_DISPLAY_NAMES: dict[str, str] = {
    "mde": "Microsoft Defender for Endpoint (Device*)",
    "alert": "Alert",
    "other_xdr": "Defender XDR",
    "sentinel": "Microsoft Sentinel",
    "unknown": "Unknown",
}
