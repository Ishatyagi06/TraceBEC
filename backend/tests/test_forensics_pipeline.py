"""Automated Tests for the 5-Module Digital Email Forensics Pipeline.

Tests:
1. Ingestion & Preprocessing (.eml parser, URL/domain extraction, originating IP)
2. Module 1: NLP Analysis Engine
3. Module 2: Header & Authentication Analysis
4. Module 3: Origin Traceability
5. Module 4: Infrastructure Reputation Engine
6. Module 5: Historical Campaign Correlation
7. Evidence Fusion & Explainable Output Generation
"""

import pytest
from app.forensics.parser import parse_eml_bytes, extract_urls_and_domains
from app.forensics.nlp_analyzer import analyze_nlp
from app.forensics.header_analyzer import analyze_headers
from app.forensics.infrastructure_reputation import analyze_infrastructure_reputation
from app.forensics.campaign_correlator import correlate_campaigns
from app.forensics.evidence_fusion import execute_forensic_pipeline


SAMPLE_PHISHING_EML = b"""From: "Chief Executive Officer" <ceo-alert@gmail.com>
To: finance-desk@corporate.com
Reply-To: bad-actor-drop@external-mail.com
Subject: Urgent & Confidential: Wire Transfer Directive for Closing Acquisition
Date: Tue, 27 Oct 2026 10:15:00 +0000
Message-ID: <threat-alpha-001@mail.com>
Authentication-Results: mx.corporate.com; spf=fail (sender IP not authorized); dkim=fail; dmarc=fail
Received: from mail-relay.anonymizer.net ([185.220.101.45]) by mx.corporate.com with ESMTP; Tue, 27 Oct 2026 10:14:30 +0000
Received: from internal-client ([10.0.0.1]) by mail-relay.anonymizer.net; Tue, 27 Oct 2026 10:00:00 +0000
Content-Type: text/html; charset=UTF-8

<html>
<body>
<p>I am currently tied up in an off-site board meeting and cannot take calls.</p>
<p>We must process an immediate wire transfer for the closing acquisition before EOD today. Keep this strictly confidential.</p>
<p>Please review the acquisition invoice at: <a href="http://185.220.101.45/invoice.pdf">Download Invoice</a></p>
<p>Also confirm your access at <a href="https://payroll-portal-update.xyz/direct-deposit">Portal Link</a></p>
</body>
</html>
"""

SAMPLE_BENIGN_EML = b"""From: "Alice Smith" <alice@corporate.com>
To: bob@corporate.com
Subject: Team Sync Agenda for Thursday
Date: Tue, 27 Oct 2026 09:00:00 +0000
Message-ID: <clean-internal-001@corporate.com>
Authentication-Results: mx.corporate.com; spf=pass; dkim=pass; dmarc=pass
Received: from mail.corporate.com ([192.0.2.1]) by mx.corporate.com with ESMTP; Tue, 27 Oct 2026 09:00:02 +0000
Content-Type: text/plain; charset=UTF-8

Hi Bob,

Here is the tentative agenda for our upcoming team sync on Thursday:
1. Project milestones review
2. Sprint retrospectives
3. Documentation updates

Let me know if you would like to add any other topics.

Best,
Alice
"""


def test_preprocessing_and_extracted_data():
    parsed = parse_eml_bytes(SAMPLE_PHISHING_EML)
    assert parsed.subject == "Urgent & Confidential: Wire Transfer Directive for Closing Acquisition"
    assert parsed.from_entity.display_name == "Chief Executive Officer"
    assert parsed.reply_to_entity.email_address == "bad-actor-drop@external-mail.com"
    
    # Verify extracted URLs & domains
    assert len(parsed.extracted_urls) >= 2
    assert "payroll-portal-update.xyz" in parsed.extracted_domains
    
    # Verify Originating IP extracted from Received hops
    assert parsed.originating_ip == "185.220.101.45"
    assert len(parsed.received_hops) == 2


def test_module_1_nlp_analysis():
    parsed = parse_eml_bytes(SAMPLE_PHISHING_EML)
    nlp_out = analyze_nlp(parsed)
    
    assert nlp_out.phishing_probability >= 0.70
    assert nlp_out.urgency_score > 0.0
    assert "Financial / Wire Redirection" in nlp_out.detected_intents
    assert len(nlp_out.suspicious_text_features) > 0


def test_module_2_header_auth_analysis():
    parsed = parse_eml_bytes(SAMPLE_PHISHING_EML)
    header_out = analyze_headers(parsed)
    
    assert header_out.spoofing_probability >= 0.70
    assert any("SPF" in a for a in header_out.header_anomalies)
    assert any("Reply-To" in a for a in header_out.header_anomalies)
    assert header_out.authentication_results["spf"] == "FAIL"


def test_module_4_infrastructure_reputation():
    parsed = parse_eml_bytes(SAMPLE_PHISHING_EML)
    rep_out = analyze_infrastructure_reputation(parsed)
    
    assert rep_out.reputation_score >= 0.50
    assert any("IPv4" in m or "Top-Level Domain" in m for m in rep_out.threat_intelligence_matches)


def test_module_5_campaign_correlation():
    parsed = parse_eml_bytes(SAMPLE_PHISHING_EML)
    camp_out = correlate_campaigns(parsed)
    
    assert len(camp_out.related_email_matches) > 0
    assert camp_out.potential_campaign_id in ("CAMP-BEC-WIRE-01", "CAMP-PAYROLL-UPD-02")
    assert camp_out.similarity_score > 0.30


def test_evidence_fusion_and_final_output_generation():
    parsed = parse_eml_bytes(SAMPLE_PHISHING_EML)
    report = execute_forensic_pipeline(parsed)
    
    # Verify final output structure matching diagram
    assert report.decision == "Phishing"
    assert report.fraud_confidence_score >= 0.75
    assert "%" in report.fraud_confidence_percentage
    assert len(report.key_evidence) >= 3
    
    # Verify detailed report
    assert "module_wise_analysis" in report.detailed_report.model_dump()
    assert report.detailed_report.technical_indicators["originating_ip"] == "185.220.101.45"
    assert len(report.detailed_report.references_and_sources) > 0


def test_benign_email_forensic_pipeline():
    parsed = parse_eml_bytes(SAMPLE_BENIGN_EML)
    report = execute_forensic_pipeline(parsed)
    
    assert report.decision == "Legitimate"
    assert report.fraud_confidence_score < 0.35
