"""Unit & Integration Tests for phisGuard Digital Forensics Pipeline."""

import os
from pathlib import Path
from app.forensics.parser import parse_eml_bytes, parse_visible_text
from app.forensics.feature_extractor import extract_forensic_features
from app.forensics.leakage import compute_exact_hash, audit_and_cluster_dataset
from app.schemas.email_schema import RiskCategory, AuthStatus


SAMPLES_DIR = Path(__file__).parent.parent.parent / "data" / "samples"


def test_benign_corporate_eml_parsing():
    eml_path = SAMPLES_DIR / "benign_corporate_01.eml"
    assert eml_path.exists(), f"Sample file not found: {eml_path}"
    
    with open(eml_path, "rb") as f:
        raw_bytes = f.read()
    
    parsed = parse_eml_bytes(raw_bytes)
    assert parsed.from_entity.email_address == "eileen.peebles@enron.com"
    assert parsed.from_entity.domain == "enron.com"
    assert "Natural Gas Logistics" in parsed.subject
    assert len(parsed.received_hops) >= 2
    assert parsed.auth_results.spf_status == AuthStatus.UNAVAILABLE
    
    feat_vec, signals, unavailable = extract_forensic_features(parsed)
    assert feat_vec.from_reply_to_mismatch == 0
    assert feat_vec.from_is_free_webmail == 0
    assert any("SPF Authentication header absent" in u for u in unavailable)


def test_bec_ceo_wire_forensic_extraction():
    eml_path = SAMPLES_DIR / "bec_ceo_wire_01.eml"
    assert eml_path.exists()
    
    with open(eml_path, "rb") as f:
        raw_bytes = f.read()
    
    parsed = parse_eml_bytes(raw_bytes)
    assert "Kenneth Lay" in parsed.from_entity.display_name
    assert parsed.from_entity.domain == "gmail.com"
    assert parsed.reply_to_entity.domain == "consultant-offshore.org"
    assert parsed.auth_results.spf_status == AuthStatus.SOFTFAIL
    assert parsed.auth_results.dmarc_status == AuthStatus.FAIL
    
    feat_vec, signals, unavailable = extract_forensic_features(parsed)
    assert feat_vec.from_reply_to_mismatch == 1
    assert feat_vec.from_is_free_webmail == 1
    assert feat_vec.display_name_mimics_corp_domain == 1
    assert feat_vec.zero_attachment_zero_link == 1
    
    # Check signal generation
    titles = [s.title for s in signals]
    assert "Reply-To Domain Mismatch" in titles
    assert "Display Name Spoofing with Free Webmail" in titles
    assert "SPF Authentication Failure" in titles
    assert "DMARC Policy Failure" in titles
    assert "Payloadless Message Structure" in titles


def test_leakage_audit_and_clustering():
    records = [
        {
            "id": "1",
            "subject": "Urgent Wire Needed",
            "body": "Please wire $50,000 to the offshore escrow account immediately.",
            "sender_domain": "attacker-vps.com",
            "label": 1
        },
        {
            "id": "2",
            "subject": "Urgent Wire Needed",
            "body": "Please wire $50,000 to the offshore escrow account immediately.",
            "sender_domain": "attacker-vps.com",
            "label": 1
        },
        {
            "id": "3",
            "subject": "Urgent Wire Needed Today",
            "body": "Please wire $50,000 to the offshore escrow account immediately.",
            "sender_domain": "attacker-vps.com",
            "label": 1
        },
        {
            "id": "4",
            "subject": "Weekly Team Meeting",
            "body": "Let's review the pipeline metrics on Monday morning at 9am.",
            "sender_domain": "enron.com",
            "label": 0
        }
    ]
    
    final_records, summary = audit_and_cluster_dataset(records, similarity_threshold=0.7)
    assert summary["exact_duplicates"] == 1
    assert summary["near_duplicates"] >= 1
    # Samples 1, 2, and 3 should share the same cluster_id
    cluster_1 = next(r["cluster_id"] for r in final_records if r["id"] == "1")
    cluster_2 = next(r["cluster_id"] for r in final_records if r["id"] == "2")
    cluster_3 = next(r["cluster_id"] for r in final_records if r["id"] == "3")
    assert cluster_1 == cluster_2 == cluster_3
    
    cluster_4 = next(r["cluster_id"] for r in final_records if r["id"] == "4")
    assert cluster_4 != cluster_1
