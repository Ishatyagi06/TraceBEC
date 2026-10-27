"""Evidence Fusion & Risk Assessment Engine.

Fuses evidence across the 5 Parallel Evidence Extraction Modules:
1. NLP Analysis
2. Header & Authentication Analysis
3. Origin Traceability
4. Infrastructure Reputation
5. Historical Campaign Correlation

Generates:
- Weighted Fraud Confidence Score (0-100%)
- Final Decision (Phishing / Legitimate / Uncertain)
- Key Evidence items across modules
- Explainable Output & Detailed Forensic Report
"""

from typing import List, Dict, Any, Tuple
from app.schemas.email_schema import (
    ParsedEmail,
    NLPModuleOutput,
    HeaderAuthModuleOutput,
    InfrastructureReputationModuleOutput,
    CampaignCorrelationModuleOutput,
    KeyEvidenceItem,
    DetailedReport,
    ForensicInvestigationReport,
)
from app.forensics.nlp_analyzer import analyze_nlp
from app.forensics.header_analyzer import analyze_headers
from app.forensics.infrastructure_reputation import analyze_infrastructure_reputation
from app.forensics.campaign_correlator import correlate_campaigns


# Module Weight Matrix (Rebalanced across 4 core detection modules)
WEIGHT_NLP = 0.30
WEIGHT_HEADERS = 0.30
WEIGHT_REPUTATION = 0.20
WEIGHT_CAMPAIGN = 0.20


def execute_forensic_pipeline(parsed: ParsedEmail) -> ForensicInvestigationReport:
    """Executes evidence extraction modules in parallel and fuses results."""
    # 1. Run Parallel Modules
    m1_nlp: NLPModuleOutput = analyze_nlp(parsed)
    m2_headers: HeaderAuthModuleOutput = analyze_headers(parsed)
    m4_reputation: InfrastructureReputationModuleOutput = analyze_infrastructure_reputation(parsed)
    m5_campaign: CampaignCorrelationModuleOutput = correlate_campaigns(parsed)

    # 2. Derive normalized module scores [0.0, 1.0]
    score_m1 = m1_nlp.phishing_probability
    score_m2 = m2_headers.spoofing_probability
    score_m4 = m4_reputation.reputation_score
    score_m5 = m5_campaign.similarity_score

    # 3. Weighted Evidence Fusion
    raw_fused_score = (
        WEIGHT_NLP * score_m1 +
        WEIGHT_HEADERS * score_m2 +
        WEIGHT_REPUTATION * score_m4 +
        WEIGHT_CAMPAIGN * score_m5
    )

    # 4. Critical Overrides
    # Active Threat Intel Hit
    if m4_reputation.threat_intelligence_matches:
        if any("Active Phishing Registry" in t for t in m4_reputation.threat_intelligence_matches):
            raw_fused_score = max(raw_fused_score, 0.95)

    # Executive Impersonation + Webmail Divergence
    if score_m2 >= 0.70 and score_m1 >= 0.60:
        raw_fused_score = max(raw_fused_score, 0.85)

    fraud_confidence_score = min(0.99, max(0.01, round(raw_fused_score, 2)))
    fraud_confidence_percentage = f"{int(round(fraud_confidence_score * 100))}%"

    # 5. Final Classification Decision
    if fraud_confidence_score >= 0.70:
        decision = "Phishing"
    elif fraud_confidence_score >= 0.35:
        decision = "Uncertain"
    else:
        decision = "Legitimate"

    # 6. Collect Top Key Evidence Items
    key_evidence: List[KeyEvidenceItem] = []

    # Module 1 Key Evidence
    if m1_nlp.detected_intents:
        key_evidence.append(KeyEvidenceItem(
            module="NLP Analysis",
            evidence_text=f"Suspicious content detected: {', '.join(m1_nlp.detected_intents)} (Urgency: {int(m1_nlp.urgency_score * 100)}%)",
            severity="High" if m1_nlp.phishing_probability >= 0.60 else "Warning"
        ))
    elif m1_nlp.suspicious_text_features:
        key_evidence.append(KeyEvidenceItem(
            module="NLP Analysis",
            evidence_text=m1_nlp.suspicious_text_features[0],
            severity="Warning"
        ))

    # Module 2 Key Evidence
    if m2_headers.header_anomalies:
        key_evidence.append(KeyEvidenceItem(
            module="Header & Authentication",
            evidence_text=m2_headers.header_anomalies[0],
            severity="High" if m2_headers.spoofing_probability >= 0.60 else "Warning"
        ))

    # Module 4 Key Evidence
    if m4_reputation.threat_intelligence_matches:
        key_evidence.append(KeyEvidenceItem(
            module="Infrastructure Reputation",
            evidence_text=m4_reputation.threat_intelligence_matches[0],
            severity="High"
        ))
    elif m4_reputation.flagged_urls:
        key_evidence.append(KeyEvidenceItem(
            module="Infrastructure Reputation",
            evidence_text=f"Flagged URL structure: {m4_reputation.flagged_urls[0].get('url')}",
            severity="Warning"
        ))

    # Module 5 Key Evidence
    if m5_campaign.related_email_matches:
        camp = m5_campaign.related_email_matches[0]
        key_evidence.append(KeyEvidenceItem(
            module="Historical Campaign Correlation",
            evidence_text=f"Correlated with campaign '{camp['campaign_name']}' ({camp['campaign_id']}) with {int(camp['confidence']*100)}% match",
            severity="High" if camp['confidence'] >= 0.60 else "Informational"
        ))

    if not key_evidence:
        key_evidence.append(KeyEvidenceItem(
            module="Integrity Check",
            evidence_text="No anomalous security or impersonation indicators observed.",
            severity="Informational"
        ))

    # 7. Generate Detailed Report
    detailed_report = DetailedReport(
        module_wise_analysis={
            "module_1_nlp_score": score_m1,
            "module_2_header_auth_score": score_m2,
            "module_4_infrastructure_reputation_score": score_m4,
            "module_5_campaign_correlation_score": score_m5,
            "weights": {
                "nlp": WEIGHT_NLP,
                "headers": WEIGHT_HEADERS,
                "reputation": WEIGHT_REPUTATION,
                "campaign": WEIGHT_CAMPAIGN,
            }
        },
        technical_indicators={
            "originating_ip": parsed.originating_ip,
            "sender_address": m2_headers.sender_metadata.get("from_address"),
            "authentication": m2_headers.authentication_results,
            "extracted_urls_count": len(parsed.extracted_urls or []),
            "extracted_domains": parsed.extracted_domains or [],
            "hop_count": len(parsed.received_hops or [])
        },
        related_emails_and_campaigns=m5_campaign.related_email_matches,
        references_and_sources=[
            "RFC 5322 Internet Message Format & MIME RFC 2045",
            "NIST SP 800-177 Trustworthy Email Standard",
            "TraceBEC Historical Threat Campaign Database v1.0",
            "Threat Intelligence Feed Integration (Simulated Heuristic)"
        ]
    )

    return ForensicInvestigationReport(
        decision=decision,
        fraud_confidence_score=fraud_confidence_score,
        fraud_confidence_percentage=fraud_confidence_percentage,
        key_evidence=key_evidence,
        detailed_report=detailed_report,
        module_1_nlp=m1_nlp,
        module_2_headers=m2_headers,
        module_3_origin=None,
        module_4_reputation=m4_reputation,
        module_5_campaign=m5_campaign
    )
