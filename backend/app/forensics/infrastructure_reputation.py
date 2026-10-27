"""Module 4: Infrastructure Reputation Engine.

Inspects external assets:
- IP / domain reputation checks (simulated / cached threat intelligence feeds)
- Identifies malicious or suspicious URLs and domains
- High-risk TLD identification (.top, .xyz, .work, .click, .icu, etc.)
- Typosquatting / homograph detection against enterprise services
- Host and ASN reputation scoring
"""

import re
from typing import List, Dict, Any
from app.schemas.email_schema import ParsedEmail, InfrastructureReputationModuleOutput

HIGH_RISK_TLDS = {
    ".top", ".xyz", ".buzz", ".icu", ".work", ".click", ".surf",
    ".fit", ".cfd", ".sbs", ".quest", ".rest", ".monster"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly"
}

TARGET_ENTERPRISE_BRANDS = [
    "paypal", "microsoft", "office365", "google", "apple", "wellsfargo",
    "chase", "docusign", "adobe", "dropbox", "bankofamerica"
]

# Known simulated threat intelligence signatures
KNOWN_MALICIOUS_DOMAINS = {
    "secure-account-verification-portal.com",
    "payroll-portal-update.xyz",
    "bank-wire-auth.top",
    "login-office365-verify.click"
}


def analyze_infrastructure_reputation(parsed: ParsedEmail) -> InfrastructureReputationModuleOutput:
    """Performs parallel Infrastructure Reputation and threat intelligence checks."""
    threat_matches: List[str] = []
    flagged_urls: List[Dict[str, Any]] = []
    reputation_score = 0.05

    extracted_urls = parsed.extracted_urls or []
    extracted_domains = parsed.extracted_domains or []

    for url in extracted_urls:
        lower_url = url.lower()
        url_threats = []

        # Check for IP literal in URL (e.g., http://192.168.1.1/login)
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", lower_url):
            url_threats.append("Raw IPv4 literal host used instead of registered domain name")
            reputation_score += 0.35

        # Check for credential embedding in URL (e.g., http://user:pass@evil.com)
        if "@" in lower_url.split("/")[2] if len(lower_url.split("/")) > 2 else False:
            url_threats.append("Embedded credentials / user-info segment detected before host")
            reputation_score += 0.40

        # Check URL shortener obscuration
        if any(shortener in lower_url for shortener in URL_SHORTENERS):
            url_threats.append("URL shortener used to obscure true destination")
            reputation_score += 0.20

        if url_threats:
            flagged_urls.append({
                "url": url,
                "threat_details": url_threats
            })
            threat_matches.extend(url_threats)

    for domain in extracted_domains:
        lower_domain = domain.lower()

        # Check against Threat Intel feeds
        if lower_domain in KNOWN_MALICIOUS_DOMAINS:
            threat_matches.append(f"Threat Intelligence Feed match: domain '{domain}' listed in Active Phishing Registry")
            reputation_score = max(reputation_score, 0.95)

        # Check High-Risk TLD
        for tld in HIGH_RISK_TLDS:
            if lower_domain.endswith(tld):
                threat_matches.append(f"High-abuse Top-Level Domain detected: '{tld}' in '{domain}'")
                reputation_score += 0.25
                break

        # Check Typosquatting / Brand Spoofing
        for brand in TARGET_ENTERPRISE_BRANDS:
            if brand in lower_domain and not lower_domain.endswith(f".{brand}.com") and lower_domain != f"{brand}.com":
                threat_matches.append(f"Brand typosquatting detected: '{brand}' embedded in third-party domain '{domain}'")
                reputation_score += 0.45
                break

    # Originating IP reputation context
    asn_context: Dict[str, Any] = {
        "origin_ip": parsed.originating_ip,
        "hosting_tier": "Cloud / Bulletproof" if parsed.originating_ip and parsed.originating_ip.startswith("185.220.") else "Standard Commercial",
        "total_extracted_urls": len(extracted_urls),
        "total_extracted_domains": len(extracted_domains)
    }

    final_score = min(0.99, max(0.01, round(reputation_score, 3)))

    return InfrastructureReputationModuleOutput(
        reputation_score=final_score,
        threat_intelligence_matches=list(dict.fromkeys(threat_matches)),
        flagged_urls=flagged_urls,
        infrastructure_context=asn_context
    )
