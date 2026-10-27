"""Pydantic data contracts for phisGuard.

Strictly defines the structure for parsed emails, digital forensic features,
observed evidence, unavailable evidence, and calibrated risk assessments.
"""

from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field


class RiskCategory(str, Enum):
    LOW = "LOW"
    REVIEW = "REVIEW"
    HIGH = "HIGH"


class AuthStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SOFTFAIL = "SOFTFAIL"
    NEUTRAL = "NEUTRAL"
    NONE = "NONE"
    PERMERROR = "PERMERROR"
    TEMPERROR = "TEMPERROR"
    UNAVAILABLE = "UNAVAILABLE"


class ParsedHeader(BaseModel):
    name: str
    value: str


class AddressEntity(BaseModel):
    raw: str
    display_name: str = ""
    email_address: str = ""
    domain: str = ""


class ReceivedHop(BaseModel):
    hop_index: int
    by_host: Optional[str] = None
    from_host: Optional[str] = None
    ip: Optional[str] = None
    timestamp_raw: Optional[str] = None
    timestamp_iso: Optional[str] = None
    delay_seconds_from_prev: Optional[float] = None


class AttachmentMetadata(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    extension: str
    has_executable_extension: bool = False
    has_double_extension: bool = False


class AuthenticationResults(BaseModel):
    spf_status: AuthStatus = AuthStatus.UNAVAILABLE
    spf_domain: Optional[str] = None
    dkim_status: AuthStatus = AuthStatus.UNAVAILABLE
    dkim_domain: Optional[str] = None
    dmarc_status: AuthStatus = AuthStatus.UNAVAILABLE
    dmarc_policy: Optional[str] = None
    raw_auth_header: Optional[str] = None


class ParsedEmail(BaseModel):
    message_id: Optional[str] = None
    date_raw: Optional[str] = None
    date_iso: Optional[str] = None
    from_entity: AddressEntity
    to_entities: List[AddressEntity] = Field(default_factory=list)
    reply_to_entity: Optional[AddressEntity] = None
    return_path_entity: Optional[AddressEntity] = None
    subject: str = ""
    body_plain: str = ""
    body_html_sanitized: str = ""
    received_hops: List[ReceivedHop] = Field(default_factory=list)
    auth_results: AuthenticationResults = Field(default_factory=AuthenticationResults)
    attachments: List[AttachmentMetadata] = Field(default_factory=list)
    extracted_urls: List[str] = Field(default_factory=list)
    extracted_domains: List[str] = Field(default_factory=list)
    originating_ip: Optional[str] = None
    mime_type: str = "text/plain"
    is_multipart: bool = False
    part_count: int = 1
    raw_headers: List[ParsedHeader] = Field(default_factory=list)


class ForensicFeatureVector(BaseModel):
    # Addressing & Impersonation
    display_name_length: int
    has_display_name: int
    display_name_contains_email: int
    from_reply_to_mismatch: int
    from_return_path_mismatch: int
    from_is_free_webmail: int
    reply_to_is_free_webmail: int
    display_name_mimics_corp_domain: int

    # Authentication Signals (0=unavailable/none, 1=pass, -1=fail)
    spf_pass: int
    spf_fail: int
    spf_available: int
    dkim_pass: int
    dkim_fail: int
    dkim_available: int
    dmarc_pass: int
    dmarc_fail: int
    dmarc_available: int

    # Routing & Hop Forensics
    received_hops_count: int
    has_transit_delay_anomaly: int
    max_hop_delay_seconds: float

    # Structural & Payload Forensics
    is_multipart: int
    part_count: int
    attachment_count: int
    has_executable_attachment: int
    has_double_extension_attachment: int
    body_plain_char_count: int
    body_plain_word_count: int
    subject_char_count: int
    subject_word_count: int
    has_links_in_body: int
    link_count: int
    zero_attachment_zero_link: int  # Signature BEC characteristic (payloadless)


class ObservedSignal(BaseModel):
    category: str  # Identity, Authentication, Content, Routing, Structural
    title: str
    description: str
    severity: str  # Informational, Caution, Warning, Suspicious
    is_evidence_present: bool = True


class SafeNextStep(BaseModel):
    action: str
    channel: str  # e.g., Out-of-band Phone, Internal ERP, Standard Workflow
    description: str


class RiskAssessment(BaseModel):
    risk_category: RiskCategory
    decision_threshold: float
    calibrated_score: Optional[float] = None
    score_interpretation: str
    model_version: str
    observed_evidence: List[ObservedSignal] = Field(default_factory=list)
    unavailable_evidence: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    safe_next_steps: List[SafeNextStep] = Field(default_factory=list)


class InvestigationRecord(BaseModel):
    id: str
    timestamp_iso: str
    source_type: str  # eml_upload, visible_text, api
    subject: str
    sender: str
    risk_assessment: RiskAssessment
    parsed_email: Optional[ParsedEmail] = None
    forensic_report: Optional["ForensicInvestigationReport"] = None


# --- 5 Parallel Evidence Extraction Modules & Forensic Pipeline Schemas ---

class NLPModuleOutput(BaseModel):
    phishing_probability: float
    suspicious_text_features: List[str] = Field(default_factory=list)
    detected_intents: List[str] = Field(default_factory=list)
    urgency_score: float = 0.0
    impersonation_indicators: List[str] = Field(default_factory=list)


class HeaderAuthModuleOutput(BaseModel):
    authentication_results: Dict[str, str] = Field(default_factory=dict)
    header_anomalies: List[str] = Field(default_factory=list)
    sender_metadata: Dict[str, Any] = Field(default_factory=dict)
    spoofing_probability: float = 0.0


class OriginTraceabilityModuleOutput(BaseModel):
    origin_ip: Optional[str] = None
    routing_path: List[Dict[str, Any]] = Field(default_factory=list)
    infrastructure_indicators: List[str] = Field(default_factory=list)
    is_suspicious_origin: bool = False
    transit_delay_anomaly: bool = False


class InfrastructureReputationModuleOutput(BaseModel):
    reputation_score: float = 0.0
    threat_intelligence_matches: List[str] = Field(default_factory=list)
    flagged_urls: List[Dict[str, Any]] = Field(default_factory=list)
    infrastructure_context: Dict[str, Any] = Field(default_factory=dict)


class CampaignCorrelationModuleOutput(BaseModel):
    related_email_matches: List[Dict[str, Any]] = Field(default_factory=list)
    campaign_indicators: List[str] = Field(default_factory=list)
    potential_campaign_id: Optional[str] = None
    similarity_score: float = 0.0
    supporting_evidence: List[str] = Field(default_factory=list)


class KeyEvidenceItem(BaseModel):
    module: str
    evidence_text: str
    severity: str  # High, Warning, Informational


class DetailedReport(BaseModel):
    module_wise_analysis: Dict[str, Any] = Field(default_factory=dict)
    technical_indicators: Dict[str, Any] = Field(default_factory=dict)
    related_emails_and_campaigns: List[Dict[str, Any]] = Field(default_factory=list)
    references_and_sources: List[str] = Field(default_factory=list)


class ForensicInvestigationReport(BaseModel):
    decision: str  # "Phishing", "Legitimate", "Uncertain"
    fraud_confidence_score: float  # e.g. 0.85
    fraud_confidence_percentage: str  # e.g. "85%"
    key_evidence: List[KeyEvidenceItem] = Field(default_factory=list)
    detailed_report: DetailedReport
    module_1_nlp: NLPModuleOutput
    module_2_headers: HeaderAuthModuleOutput
    module_3_origin: OriginTraceabilityModuleOutput
    module_4_reputation: InfrastructureReputationModuleOutput
    module_5_campaign: CampaignCorrelationModuleOutput


InvestigationRecord.model_rebuild()

