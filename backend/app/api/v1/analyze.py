"""Analysis API Endpoints (EML & Visible Text).

Implements:
- POST /analyze/eml: Full RFC 5322 MIME & header forensics + Multimodal assessment
- POST /analyze/text: Tier-1 visible text analysis with explicit unavailable-evidence disclosures
"""

import uuid
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, UploadFile, File, HTTPException, status
from pydantic import BaseModel

from app.schemas.email_schema import (
    InvestigationRecord,
    RiskAssessment,
    RiskCategory,
    SafeNextStep,
)
from app.forensics.parser import parse_eml_bytes, parse_visible_text
from app.forensics.feature_extractor import extract_forensic_features
from app.forensics.evidence_fusion import execute_forensic_pipeline
from app.models.calibrator import categorize_risk
from app.api.v1.investigations import save_investigation


router = APIRouter(prefix="/analyze", tags=["analyze"])


class TextAnalysisRequest(BaseModel):
    subject: str
    body: str
    sender: Optional[str] = ""


def _build_safe_next_steps(risk_cat: RiskCategory, has_financial_cues: bool) -> list[SafeNextStep]:
    """Generates defensive, actionable guidance without alarmism."""
    steps = []
    if risk_cat in (RiskCategory.HIGH, RiskCategory.REVIEW):
        steps.append(SafeNextStep(
            action="Out-of-Band Verbal Verification",
            channel="Known Phone / Pre-established Internal Directory",
            description="Contact the purported sender using a previously verified corporate number or internal desk extension. Never use contact details provided inside the email itself."
        ))
        if has_financial_cues:
            steps.append(SafeNextStep(
                action="Secondary Accounting Approval",
                channel="Enterprise ERP / Dual-Signoff Protocol",
                description="Require secondary dual-authorization before updating banking routing coordinates or remitting wires over corporate thresholds."
            ))
        steps.append(SafeNextStep(
            action="Preserve Transport Evidence",
            channel="Security Operations / SOC Triage",
            description="Export the raw RFC 5322 (.eml) file to your security team for transit relay header analysis and domain authentication verification."
        ))
    else:
        steps.append(SafeNextStep(
            action="Standard Operational Handling",
            channel="Normal Business Workflow",
            description="No anomalous BEC signals detected. Standard operational hygiene and vigilance apply."
        ))
    return steps


@router.post("/eml", response_model=InvestigationRecord)
async def analyze_eml_file(file: UploadFile = File(...)):
    """Accepts a validated .eml upload and returns parsed evidence plus model assessment."""
    if not file.filename.lower().endswith((".eml", ".msg", ".txt")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must have a .eml or supported email format extension."
        )

    raw_bytes = await file.read()
    if len(raw_bytes) > 10 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File size exceeds maximum safe upload limit of 10 MB."
        )

    parsed = parse_eml_bytes(raw_bytes)
    feat_vec, signals, unavailable = extract_forensic_features(parsed)

    # Calculate calibrated risk score
    # High risk signals: Display name spoofing + Reply-to mismatch + Auth failures + Urgency
    risk_score = 0.05  # Base benign prior
    if feat_vec.display_name_mimics_corp_domain:
        risk_score += 0.40
    if feat_vec.from_reply_to_mismatch:
        risk_score += 0.30
    if feat_vec.spf_fail or feat_vec.dmarc_fail:
        risk_score += 0.20
    if feat_vec.zero_attachment_zero_link and feat_vec.body_plain_word_count > 15:
        # Check financial/urgency keywords in text
        body_lower = (parsed.body_plain or "").lower()
        if any(w in body_lower for w in ["wire", "banking", "deposit", "confidential", "urgent", "payroll", "invoice"]):
            risk_score += 0.25

    calibrated_prob = min(0.99, max(0.01, round(risk_score, 3)))
    category, rationale = categorize_risk(calibrated_prob)
    has_finance = any(w in (parsed.body_plain or "").lower() for w in ["wire", "invoice", "payroll", "deposit", "bank"])

    assessment = RiskAssessment(
        risk_category=category,
        decision_threshold=0.35 if category == RiskCategory.REVIEW else 0.70,
        calibrated_score=calibrated_prob,
        score_interpretation=rationale,
        model_version="phisGuard-Multimodal-v1.0",
        observed_evidence=signals,
        unavailable_evidence=unavailable,
        limitations=[
            "This model provides investigative triage support and does not constitute definitive proof of fraud or sender identity.",
            "A Reply-To divergence may occur legitimately in ticketing systems or discussion lists.",
            "Missing authentication headers reflect receiver reporting, not necessarily authentication failure."
        ],
        safe_next_steps=_build_safe_next_steps(category, has_finance)
    )

    forensic_report = execute_forensic_pipeline(parsed)

    record_id = f"inv_{uuid.uuid4().hex[:12]}"
    record = InvestigationRecord(
        id=record_id,
        timestamp_iso=datetime.utcnow().isoformat() + "Z",
        source_type="eml_upload",
        subject=parsed.subject or "(No Subject)",
        sender=parsed.from_entity.raw or "Unknown",
        risk_assessment=assessment,
        parsed_email=parsed,
        forensic_report=forensic_report
    )

    save_investigation(record)
    return record


@router.post("/text", response_model=InvestigationRecord)
def analyze_visible_text(req: TextAnalysisRequest):
    """Analyzes visible message text (Tier 1 Gmail integration / text paste)."""
    parsed = parse_visible_text(subject=req.subject, body=req.body, sender=req.sender)
    feat_vec, signals, unavailable = extract_forensic_features(parsed)

    # Linguistic BEC heuristic evaluation
    body_lower = (req.body or "").lower()
    subj_lower = (req.subject or "").lower()
    combined_text = f"{subj_lower} {body_lower}"

    risk_score = 0.05
    if any(w in combined_text for w in ["wire", "immediate", "urgent", "confidential", "payroll", "bank account", "invoice"]):
        risk_score += 0.35
    if any(w in combined_text for w in ["ceo", "executive", "board meeting", "do not discuss", "nd a"]):
        risk_score += 0.25
    if feat_vec.display_name_mimics_corp_domain or feat_vec.from_is_free_webmail:
        risk_score += 0.25

    calibrated_prob = min(0.99, max(0.01, round(risk_score, 3)))
    category, rationale = categorize_risk(calibrated_prob)
    has_finance = any(w in combined_text for w in ["wire", "invoice", "payroll", "bank"])

    # Disclose unavailable evidence explicitly
    unavailable.extend([
        "RFC 5322 transit headers ('Received' relay hops) unavailable from visible text.",
        "Cryptographic DKIM public key signature unverified.",
        "Receiving server SPF and DMARC authentication verdicts absent."
    ])

    assessment = RiskAssessment(
        risk_category=category,
        decision_threshold=0.35 if category == RiskCategory.REVIEW else 0.70,
        calibrated_score=calibrated_prob,
        score_interpretation=rationale,
        model_version="phisGuard-Linguistic-v1.0",
        observed_evidence=signals,
        unavailable_evidence=unavailable,
        limitations=[
            "Tier-1 Visible Text Mode evaluates contextual language patterns only; transport headers are absent.",
            "For full forensic header validation, export the raw .eml file and analyze through the phisGuard Dashboard."
        ],
        safe_next_steps=_build_safe_next_steps(category, has_finance)
    )

    forensic_report = execute_forensic_pipeline(parsed)

    record_id = f"inv_{uuid.uuid4().hex[:12]}"
    record = InvestigationRecord(
        id=record_id,
        timestamp_iso=datetime.utcnow().isoformat() + "Z",
        source_type="visible_text",
        subject=req.subject or "(No Subject)",
        sender=req.sender or "Unknown",
        risk_assessment=assessment,
        parsed_email=parsed,
        forensic_report=forensic_report
    )

    save_investigation(record)
    return record
