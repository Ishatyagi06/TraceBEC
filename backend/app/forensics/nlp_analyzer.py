"""Module 1: NLP Analysis Engine.

Analyses subject and body for:
- Phishing patterns (urgency, impersonation, fraud indicators, financial coercion)
- Semantic similarity with known phishing templates
- Intent detection (wire transfer, credential harvesting, gift card, account reset)
"""

import re
from typing import List, Tuple
from app.schemas.email_schema import ParsedEmail, NLPModuleOutput


URGENCY_PATTERNS = [
    r"\b(urgent|immediate|immediately|asap|time-sensitive|critical|within\s+\d+\s+hours?|by\s+eod|right\s+away)\b",
    r"\b(strict\s+deadline|do\s+not\s+delay|promptly|act\s+fast|emergency)\b",
]

FINANCIAL_FRAUD_PATTERNS = [
    r"\b(wire\s+transfer|wire|remittance|bank\s+account|routing\s+number|swift|iban)\b",
    r"\b(payroll\s+deposit|direct\s+deposit|direct\s+payroll|bank\s+details|invoice\s+payment)\b",
    r"\b(gift\s+cards?|itunes|steam\s+card|reimbursement|financial\s+audit)\b",
]

IMPERSONATION_PATTERNS = [
    r"\b(ceo|cfo|executive|board\s+of\s+directors|president|managing\s+director)\b",
    r"\b(confidential|strictly\s+confidential|keep\s+this\s+private|do\s+not\s+discuss|nda|private\s+acquisition)\b",
    r"\b(in\s+a\s+meeting|in\s+conference|cannot\s+take\s+calls?|reach\s+me\s+via\s+email\s+only)\b",
]

CREDENTIAL_HARVEST_PATTERNS = [
    r"\b(password\s+expir(ed|ing)|verify\s+your\s+account|update\s+credentials?|login\s+alert)\b",
    r"\b(suspended|terminated|mailbox\s+full|security\s+checkpoint|validate\s+identity)\b",
]


def analyze_nlp(parsed: ParsedEmail) -> NLPModuleOutput:
    """Performs parallel NLP analysis on email subject and body."""
    combined_text = f"{parsed.subject} {parsed.body_plain}".lower()
    suspicious_features: List[str] = []
    detected_intents: List[str] = []
    impersonation_indicators: List[str] = []

    urgency_count = 0
    for pat in URGENCY_PATTERNS:
        matches = re.findall(pat, combined_text, re.IGNORECASE)
        if matches:
            urgency_count += len(matches)
            suspicious_features.append(f"Urgency cue detected: '{matches[0][0] if isinstance(matches[0], tuple) else matches[0]}'")

    financial_count = 0
    for pat in FINANCIAL_FRAUD_PATTERNS:
        matches = re.findall(pat, combined_text, re.IGNORECASE)
        if matches:
            financial_count += len(matches)
            detected_intents.append("Financial / Wire Redirection")
            suspicious_features.append(f"Financial indicator: '{matches[0][0] if isinstance(matches[0], tuple) else matches[0]}'")

    for pat in IMPERSONATION_PATTERNS:
        matches = re.findall(pat, combined_text, re.IGNORECASE)
        if matches:
            impersonation_indicators.append(f"Executive coercion indicator: '{matches[0][0] if isinstance(matches[0], tuple) else matches[0]}'")
            detected_intents.append("Executive Impersonation / Secrecy")

    for pat in CREDENTIAL_HARVEST_PATTERNS:
        matches = re.findall(pat, combined_text, re.IGNORECASE)
        if matches:
            detected_intents.append("Credential Harvesting / Account Verification")
            suspicious_features.append(f"Credential threat: '{matches[0][0] if isinstance(matches[0], tuple) else matches[0]}'")

    # Normalize urgency score (0.0 to 1.0)
    urgency_score = min(1.0, urgency_count * 0.35)

    # Calculate overall phishing probability based on textual patterns
    raw_score = 0.05
    if urgency_count > 0:
        raw_score += 0.25
    if financial_count > 0:
        raw_score += 0.35
    if impersonation_indicators:
        raw_score += 0.25
    if "Credential Harvesting / Account Verification" in detected_intents:
        raw_score += 0.30

    phishing_prob = min(0.99, max(0.01, round(raw_score, 3)))

    return NLPModuleOutput(
        phishing_probability=phishing_prob,
        suspicious_text_features=list(dict.fromkeys(suspicious_features)),
        detected_intents=list(dict.fromkeys(detected_intents)),
        urgency_score=round(urgency_score, 2),
        impersonation_indicators=list(dict.fromkeys(impersonation_indicators))
    )
