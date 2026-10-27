"""Module 5: Historical Campaign Correlation Engine.

Correlates current email indicators against the Historical Evidence Database:
- Matches shared URLs, domains, originating IPs, or textual templates
- Builds similarity graph linkages
- Identifies associated active threat campaigns
- Outputs matching incidents and supporting campaign evidence
"""

from typing import List, Dict, Any
from app.schemas.email_schema import ParsedEmail, CampaignCorrelationModuleOutput
from app.forensics.historical_db import get_all_campaigns


def correlate_campaigns(parsed: ParsedEmail) -> CampaignCorrelationModuleOutput:
    """Performs parallel Historical Campaign Correlation against the evidence database."""
    campaigns = get_all_campaigns()
    best_campaign_id = None
    highest_similarity = 0.0
    matched_campaign_name = None
    related_matches: List[Dict[str, Any]] = []
    campaign_indicators: List[str] = []
    supporting_evidence: List[str] = []

    combined_text = f"{parsed.subject} {parsed.body_plain}".lower()
    from_dom = parsed.from_entity.domain.lower() if parsed.from_entity.domain else ""
    from_disp = parsed.from_entity.display_name.lower() if parsed.from_entity.display_name else ""
    origin_ip = parsed.originating_ip or ""
    extracted_urls = [u.lower() for u in (parsed.extracted_urls or [])]
    extracted_domains = [d.lower() for d in (parsed.extracted_domains or [])]

    for camp in campaigns:
        overlap_score = 0.0
        shared_iocs = []
        c_ind = camp["indicators"]

        # 1. IP Address Match
        if origin_ip and origin_ip in c_ind.get("ips", []):
            overlap_score += 0.40
            shared_iocs.append(f"Originating IP {origin_ip} matches campaign relay history")

        # 2. Sending Domain Match
        if from_dom and from_dom in c_ind.get("sending_domains", []):
            overlap_score += 0.35
            shared_iocs.append(f"Sender domain {from_dom} matches recorded campaign infrastructure")

        # 3. URL / Domain overlap
        for d in extracted_domains:
            if any(d in recorded_url for recorded_url in c_ind.get("urls", [])):
                overlap_score += 0.45
                shared_iocs.append(f"Target URL domain {d} matches verified campaign payload")

        # 4. Display Name Pattern
        for disp in c_ind.get("from_display_names", []):
            if disp.lower() in from_disp:
                overlap_score += 0.20
                shared_iocs.append(f"Display name pattern '{disp}' matches campaign impersonation profile")
                break

        # 5. Semantic / Keyword similarity
        keyword_hits = sum(1 for kw in c_ind.get("keywords", []) if kw in combined_text)
        if keyword_hits >= 2:
            overlap_score += 0.25
            shared_iocs.append(f"Matched {keyword_hits} specific campaign lexical markers")

        if overlap_score > 0.20:
            related_matches.append({
                "campaign_id": camp["campaign_id"],
                "campaign_name": camp["campaign_name"],
                "actor": camp["actor_signature"],
                "confidence": round(min(1.0, overlap_score), 2),
                "shared_iocs": shared_iocs,
                "historical_incidents_recorded": camp["total_incidents_recorded"]
            })

            if overlap_score > highest_similarity:
                highest_similarity = overlap_score
                best_campaign_id = camp["campaign_id"]
                matched_campaign_name = camp["campaign_name"]
                campaign_indicators = shared_iocs

    if matched_campaign_name:
        supporting_evidence.append(
            f"Strong campaign correlation with '{matched_campaign_name}' ({best_campaign_id})"
        )
        supporting_evidence.append(
            f"Linked to {len(related_matches)} known threat cluster(s) in Historical Evidence Database"
        )
    else:
        supporting_evidence.append("No direct campaign correlation identified in historical evidence repository.")

    return CampaignCorrelationModuleOutput(
        related_email_matches=related_matches,
        campaign_indicators=campaign_indicators,
        potential_campaign_id=best_campaign_id,
        similarity_score=round(min(1.0, highest_similarity), 2),
        supporting_evidence=supporting_evidence
    )
