"""Module 3: Origin Traceability Engine.

Traces message routing path across Received relay hops:
- Analyzes sending IP
- Traces chronological hop trajectory
- Identifies sending servers and infrastructure context
- Detects suspicious patterns (Tor, VPN/proxies, transit delays, untrusted relays)
"""

from typing import List, Dict, Any
from app.schemas.email_schema import ParsedEmail, OriginTraceabilityModuleOutput
from app.forensics.parser import is_public_ip

# Well-known Tor / anonymizer / bulletproof hosting IP ranges / indicators for defensive analysis
ANONYMIZER_IP_PREFIXES = [
    "185.220.",  # Common Tor exit node cluster
    "198.98.",   # Known proxy/vpn pool
    "192.42.116.", # Tor exit
    "104.244.72.",
]


def trace_origin(parsed: ParsedEmail) -> OriginTraceabilityModuleOutput:
    """Performs parallel Origin Traceability and hop trajectory analysis."""
    routing_path: List[Dict[str, Any]] = []
    indicators: List[str] = []
    is_suspicious = False
    transit_delay_anomaly = False

    hops = parsed.received_hops or []
    
    # Trace hop-by-hop path
    for idx, hop in enumerate(hops):
        hop_info = {
            "hop": hop.hop_index,
            "by_host": hop.by_host,
            "from_host": hop.from_host,
            "ip": hop.ip,
            "is_public_ip": is_public_ip(hop.ip),
            "timestamp": hop.timestamp_iso or hop.timestamp_raw,
            "delay_seconds": hop.delay_seconds_from_prev,
        }
        routing_path.append(hop_info)

        # Detect abnormal relay delays (> 300 seconds between legitimate MX hops)
        if hop.delay_seconds_from_prev and hop.delay_seconds_from_prev > 300.0:
            transit_delay_anomaly = True
            indicators.append(f"Transit latency anomaly at Hop {hop.hop_index}: {int(hop.delay_seconds_from_prev)}s delay")

    origin_ip = parsed.originating_ip
    if origin_ip:
        indicators.append(f"Originating client relay IP identified: {origin_ip}")
        # Check anonymizer/Tor prefixes
        if any(origin_ip.startswith(prefix) for prefix in ANONYMIZER_IP_PREFIXES):
            is_suspicious = True
            indicators.append(f"Originating IP {origin_ip} matches known Tor Exit Node / Anonymizer pool (obfuscation factor; does not alone confirm fraud)")

        # Check loopback or private origin
        if not is_public_ip(origin_ip):
            indicators.append(f"Originating IP {origin_ip} is an internal/RFC1918 private address")
    else:
        if not hops:
            indicators.append("No 'Received' transport hops present in message headers")
        else:
            indicators.append("Unable to isolate public originating client IP from available hops")

    if len(hops) > 8:
        indicators.append(f"Excessive relay traversal depth ({len(hops)} hops), potential multi-proxy chain")
        is_suspicious = True

    return OriginTraceabilityModuleOutput(
        origin_ip=origin_ip,
        routing_path=routing_path,
        infrastructure_indicators=indicators,
        is_suspicious_origin=is_suspicious,
        transit_delay_anomaly=transit_delay_anomaly
    )
