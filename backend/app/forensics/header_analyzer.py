"""Module 2: Header & Authentication Analysis Engine.

Analyses email headers for:
- SPF, DKIM, DMARC authentication verdicts
- Display name impersonation & corporate domain mimicry
- From vs. Reply-To & Return-Path divergences
- Header routing anomalies (unusual Received hops, free webmail abuse)
"""

from typing import Dict, List, Any
from app.schemas.email_schema import ParsedEmail, AuthStatus, HeaderAuthModuleOutput
from app.forensics.parser import FREE_WEBMAIL_DOMAINS


def analyze_headers(parsed: ParsedEmail) -> HeaderAuthModuleOutput:
    """Performs parallel Header & Authentication analysis."""
    anomalies: List[str] = []
    auth_results: Dict[str, str] = {
        "spf": parsed.auth_results.spf_status.value,
        "dkim": parsed.auth_results.dkim_status.value,
        "dmarc": parsed.auth_results.dmarc_status.value,
    }

    sender_metadata: Dict[str, Any] = {
        "from_address": parsed.from_entity.email_address,
        "from_domain": parsed.from_entity.domain,
        "from_display_name": parsed.from_entity.display_name,
        "reply_to": parsed.reply_to_entity.email_address if parsed.reply_to_entity else None,
        "return_path": parsed.return_path_entity.email_address if parsed.return_path_entity else None,
        "is_free_webmail": parsed.from_entity.domain in FREE_WEBMAIL_DOMAINS,
    }

    spoofing_score = 0.05

    # 1. Cryptographic Authentication Failures
    if parsed.auth_results.spf_status in (AuthStatus.FAIL, AuthStatus.SOFTFAIL):
        anomalies.append(f"SPF authentication verdict: {parsed.auth_results.spf_status.value} (sending server unauthorized)")
        spoofing_score += 0.30
    elif parsed.auth_results.spf_status == AuthStatus.PASS:
        spoofing_score = max(0.0, spoofing_score - 0.15)

    if parsed.auth_results.dkim_status == AuthStatus.FAIL:
        anomalies.append("DKIM signature validation failed (cryptographic body hash mismatch or invalid selector)")
        spoofing_score += 0.30
    elif parsed.auth_results.dkim_status == AuthStatus.PASS:
        spoofing_score = max(0.0, spoofing_score - 0.15)

    if parsed.auth_results.dmarc_status == AuthStatus.FAIL:
        anomalies.append("DMARC alignment failed (domain policy violation)")
        spoofing_score += 0.35

    # 2. Display Name Spoofing & Domain Mimicry
    disp_name = parsed.from_entity.display_name.lower()
    from_dom = parsed.from_entity.domain.lower()

    if disp_name and "@" in disp_name:
        anomalies.append(f"Display name contains embedded email address '{parsed.from_entity.display_name}'")
        spoofing_score += 0.25

    if disp_name and any(tag in disp_name for tag in ["admin", "security", "it support", "ceo", "cfo", "office of", "billing"]):
        if from_dom in FREE_WEBMAIL_DOMAINS:
            anomalies.append(f"Corporate/Executive display name '{parsed.from_entity.display_name}' originating from public webmail ({from_dom})")
            spoofing_score += 0.40

    # 3. Routing Divergences
    if parsed.reply_to_entity and parsed.reply_to_entity.domain:
        if parsed.reply_to_entity.domain.lower() != from_dom:
            anomalies.append(f"From domain ({from_dom}) differs from Reply-To domain ({parsed.reply_to_entity.domain})")
            spoofing_score += 0.30

    if parsed.return_path_entity and parsed.return_path_entity.domain:
        if parsed.return_path_entity.domain.lower() != from_dom:
            anomalies.append(f"From domain ({from_dom}) differs from Return-Path domain ({parsed.return_path_entity.domain})")
            spoofing_score += 0.15

    # 4. Missing / Unavailable authentication warning
    if parsed.auth_results.spf_status == AuthStatus.UNAVAILABLE and parsed.auth_results.dkim_status == AuthStatus.UNAVAILABLE:
        anomalies.append("Authentication headers (SPF/DKIM/DMARC) unavailable or stripped in transport")

    spoofing_prob = min(0.99, max(0.01, round(spoofing_score, 3)))

    return HeaderAuthModuleOutput(
        authentication_results=auth_results,
        header_anomalies=anomalies,
        sender_metadata=sender_metadata,
        spoofing_probability=spoofing_prob
    )
