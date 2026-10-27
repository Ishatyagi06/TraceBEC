"""Digital Forensics & Evidence Extraction Package."""

from app.forensics.parser import parse_eml_bytes, parse_visible_text, extract_urls_and_domains
from app.forensics.feature_extractor import extract_forensic_features
from app.forensics.nlp_analyzer import analyze_nlp
from app.forensics.header_analyzer import analyze_headers
from app.forensics.origin_tracer import trace_origin
from app.forensics.infrastructure_reputation import analyze_infrastructure_reputation
from app.forensics.historical_db import get_all_campaigns
from app.forensics.campaign_correlator import correlate_campaigns
from app.forensics.evidence_fusion import execute_forensic_pipeline

__all__ = [
    "parse_eml_bytes",
    "parse_visible_text",
    "extract_urls_and_domains",
    "extract_forensic_features",
    "analyze_nlp",
    "analyze_headers",
    "trace_origin",
    "analyze_infrastructure_reputation",
    "get_all_campaigns",
    "correlate_campaigns",
    "execute_forensic_pipeline",
]
