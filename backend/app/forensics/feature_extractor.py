"""Forensic Feature Extractor & Interpretable Signal Generator.

Extracts defensible, structured technical features from ParsedEmail objects:
- Tabular numeric vector for XGBoost (E3) and Multimodal Fusion (E4)
- Human-interpretable observed signals with contextual safeguards
- Explicit tracking of unavailable evidence
"""

import re
from typing import Tuple, List, Dict, Any

from app.schemas.email_schema import (
    ParsedEmail,
    ForensicFeatureVector,
    ObservedSignal,
    AuthStatus,
)
from app.forensics.parser import FREE_WEBMAIL_DOMAINS


COMMON_CORP_KEYWORDS = {
    "ceo", "cfo", "coo", "president", "director", "executive", "payroll",
    "accounting", "finance", "billing", "treasury", "admin", "hr"
}


def extract_forensic_features(parsed: ParsedEmail) -> Tuple[ForensicFeatureVector, List[ObservedSignal], List[str]]:
    """Converts a ParsedEmail into:
    1. A numeric ForensicFeatureVector (for ML tabular models)
    2. A list of human-readable ObservedSignals (for explainability)
    3. A list of unavailable evidence statements
    """
    signals: List[ObservedSignal] = []
    unavailable: List[str] = []

    # 1. Addressing & Identity Forensics
    from_ent = parsed.from_entity
    reply_to = parsed.reply_to_entity
    return_path = parsed.return_path_entity

    display_name = from_ent.display_name
    from_addr = from_ent.email_address
    from_dom = from_ent.domain

    has_display_name = 1 if display_name else 0
    display_name_len = len(display_name)
    
    # Check if display name has an embedded email or corporate keyword
    display_name_contains_email = 1 if ("@" in display_name or ".com" in display_name.lower()) else 0
    display_name_lower = display_name.lower()
    mimics_corp = 1 if any(kw in display_name_lower for kw in COMMON_CORP_KEYWORDS) and (from_dom in FREE_WEBMAIL_DOMAINS) else 0

    from_is_free = 1 if from_dom in FREE_WEBMAIL_DOMAINS else 0
    reply_is_free = 1 if (reply_to and reply_to.domain in FREE_WEBMAIL_DOMAINS) else 0

    from_reply_mismatch = 0
    if reply_to and reply_to.email_address:
        if reply_to.domain != from_dom:
            from_reply_mismatch = 1
            signals.append(ObservedSignal(
                category="Identity & Addressing",
                title="Reply-To Domain Mismatch",
                description=f"Sender domain '{from_dom}' directs replies to a different domain '{reply_to.domain}'. Note: while common in automated ticket systems, in financial/executive emails this can indicate reply diversion.",
                severity="Warning"
            ))

    from_return_mismatch = 0
    if return_path and return_path.domain and from_dom:
        if return_path.domain != from_dom:
            from_return_mismatch = 1
            signals.append(ObservedSignal(
                category="Identity & Addressing",
                title="Return-Path Domain Divergence",
                description=f"The delivery bounce path ('{return_path.domain}') does not match the sender header domain ('{from_dom}').",
                severity="Caution"
            ))

    if mimics_corp:
        signals.append(ObservedSignal(
            category="Identity & Addressing",
            title="Display Name Spoofing with Free Webmail",
            description=f"Display name '{display_name}' presents executive or organizational authority but is sent from a public freemail service ('{from_dom}').",
            severity="Suspicious"
        ))

    if display_name_contains_email:
        signals.append(ObservedSignal(
            category="Identity & Addressing",
            title="Email Address Disguised in Display Name",
            description=f"The display name contains an embedded email string ({display_name}), a known tactic to confuse mobile email clients.",
            severity="Caution"
        ))

    # 2. Authentication Forensics
    auth = parsed.auth_results
    spf_avail = 1 if auth.spf_status != AuthStatus.UNAVAILABLE else 0
    spf_pass = 1 if auth.spf_status == AuthStatus.PASS else 0
    spf_fail = 1 if auth.spf_status in (AuthStatus.FAIL, AuthStatus.SOFTFAIL) else 0

    dkim_avail = 1 if auth.dkim_status != AuthStatus.UNAVAILABLE else 0
    dkim_pass = 1 if auth.dkim_status == AuthStatus.PASS else 0
    dkim_fail = 1 if auth.dkim_status == AuthStatus.FAIL else 0

    dmarc_avail = 1 if auth.dmarc_status != AuthStatus.UNAVAILABLE else 0
    dmarc_pass = 1 if auth.dmarc_status == AuthStatus.PASS else 0
    dmarc_fail = 1 if auth.dmarc_status == AuthStatus.FAIL else 0

    if not spf_avail:
        unavailable.append("SPF Authentication header absent or not reported by receiving relay.")
    elif spf_fail:
        signals.append(ObservedSignal(
            category="Authentication",
            title="SPF Authentication Failure",
            description=f"Sending IP is not authorized to send on behalf of '{from_dom}' under published SPF policy.",
            severity="Warning"
        ))
    elif spf_pass:
        signals.append(ObservedSignal(
            category="Authentication",
            title="SPF Validated",
            description=f"Sending relay is verified under domain '{from_dom}' SPF records.",
            severity="Informational"
        ))

    if not dkim_avail:
        unavailable.append("DKIM cryptographic signature header absent or unverified.")
    elif dkim_fail:
        signals.append(ObservedSignal(
            category="Authentication",
            title="DKIM Signature Verification Failed",
            description="The cryptographic signature does not validate the email body/headers against the public key.",
            severity="Warning"
        ))
    elif dkim_pass:
        signals.append(ObservedSignal(
            category="Authentication",
            title="DKIM Signature Validated",
            description="Cryptographic signature verified against sending domain records.",
            severity="Informational"
        ))

    if not dmarc_avail:
        unavailable.append("DMARC alignment policy result unrecorded.")
    elif dmarc_fail:
        signals.append(ObservedSignal(
            category="Authentication",
            title="DMARC Policy Failure",
            description="Message failed combined SPF/DKIM alignment under domain policy.",
            severity="Suspicious"
        ))

    # 3. Routing & Hop Forensics
    hops_count = len(parsed.received_hops)
    max_delay = 0.0
    has_delay_anomaly = 0
    
    if hops_count > 0:
        delays = [h.delay_seconds_from_prev for h in parsed.received_hops if h.delay_seconds_from_prev is not None]
        if delays:
            max_delay = max(delays)
            if max_delay > 86400:  # Transit gap > 24 hours
                has_delay_anomaly = 1
                signals.append(ObservedSignal(
                    category="Routing & Transport",
                    title="Abnormal Relay Transit Delay",
                    description=f"Relay hop timestamp analysis indicates a {max_delay/3600:.1f} hour transit gap. May reflect manual queuing, time-zone forgery, or relay latency.",
                    severity="Caution"
                ))
    else:
        unavailable.append("Transit 'Received' headers unavailable (e.g., stripped or plain text submission).")

    # 4. Structural & Payload Forensics
    is_multi = 1 if parsed.is_multipart else 0
    part_count = parsed.part_count
    att_count = len(parsed.attachments)
    
    has_exec = 1 if any(a.has_executable_extension for a in parsed.attachments) else 0
    has_double_ext = 1 if any(a.has_double_extension for a in parsed.attachments) else 0

    if has_exec:
        signals.append(ObservedSignal(
            category="Structure & Payloads",
            title="Potentially Dangerous Attachment Extension",
            description="Attachment contains an executable, script, or disk image format.",
            severity="Suspicious"
        ))

    if has_double_ext:
        signals.append(ObservedSignal(
            category="Structure & Payloads",
            title="Double File Extension Detected",
            description="Attachment uses multiple extensions (e.g., .pdf.exe) to obscure its true executable file type.",
            severity="Suspicious"
        ))

    body = parsed.body_plain or ""
    body_chars = len(body)
    body_words = len(body.split())
    subj_chars = len(parsed.subject)
    subj_words = len(parsed.subject.split())

    # Link extraction via regex
    urls = re.findall(r"https?://[^\s<>\"']+", body)
    link_count = len(urls)
    has_links = 1 if link_count > 0 else 0

    # Signature BEC characteristic: Zero attachments AND Zero links (pure conversational manipulation)
    zero_att_zero_link = 1 if (att_count == 0 and link_count == 0) else 0
    if zero_att_zero_link and body_words > 10:
        signals.append(ObservedSignal(
            category="Structure & Payloads",
            title="Payloadless Message Structure",
            description="Message contains no URLs and no attachments. Common in Business Email Compromise relying purely on social engineering and out-of-band wire requests.",
            severity="Informational"
        ))

    feature_vector = ForensicFeatureVector(
        display_name_length=display_name_len,
        has_display_name=has_display_name,
        display_name_contains_email=display_name_contains_email,
        from_reply_to_mismatch=from_reply_mismatch,
        from_return_path_mismatch=from_return_mismatch,
        from_is_free_webmail=from_is_free,
        reply_to_is_free_webmail=reply_is_free,
        display_name_mimics_corp_domain=mimics_corp,
        spf_pass=spf_pass,
        spf_fail=spf_fail,
        spf_available=spf_avail,
        dkim_pass=dkim_pass,
        dkim_fail=dkim_fail,
        dkim_available=dkim_avail,
        dmarc_pass=dmarc_pass,
        dmarc_fail=dmarc_fail,
        dmarc_available=dmarc_avail,
        received_hops_count=hops_count,
        has_transit_delay_anomaly=has_delay_anomaly,
        max_hop_delay_seconds=float(max_delay),
        is_multipart=is_multi,
        part_count=part_count,
        attachment_count=att_count,
        has_executable_attachment=has_exec,
        has_double_extension_attachment=has_double_ext,
        body_plain_char_count=body_chars,
        body_plain_word_count=body_words,
        subject_char_count=subj_chars,
        subject_word_count=subj_words,
        has_links_in_body=has_links,
        link_count=link_count,
        zero_attachment_zero_link=zero_att_zero_link,
    )

    return feature_vector, signals, unavailable
