"""Safe Digital Email Forensics Parser (RFC 5322 & MIME).

Designed for defensive inspection of untrusted emails:
- Strict header decoding
- Cautious routing/timestamp interpretation
- Explicit tracking of unavailable vs failed authentication
- Script-free, sanitized body extraction
- Zero-execution attachment metadata inspection
"""

import re
import email
import urllib.parse
import ipaddress
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
from typing import List, Optional, Tuple
from bs4 import BeautifulSoup

from app.schemas.email_schema import (
    ParsedEmail,
    AddressEntity,
    ReceivedHop,
    AttachmentMetadata,
    AuthenticationResults,
    AuthStatus,
    ParsedHeader,
)


def is_public_ip(ip_str: Optional[str]) -> bool:
    """Checks if an IP string is a valid public IP."""
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
    except Exception:
        return False


def extract_urls_and_domains(text: str, html: str = "") -> Tuple[List[str], List[str]]:
    """Extracts all HTTP/HTTPS URLs and distinct host domains from text and HTML bodies."""
    urls = set()
    url_pattern = re.compile(r'https?://[^\s<>"\'{}|\\^`]+', re.IGNORECASE)
    for match in url_pattern.finditer(text or ""):
        urls.add(match.group(0).rstrip(".,;)"))
    
    if html:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href.startswith(("http://", "https://")):
                    urls.add(href)
        except Exception:
            pass

    domains = set()
    for u in urls:
        try:
            parsed = urllib.parse.urlparse(u)
            if parsed.netloc:
                clean_host = parsed.netloc.lower().split(":")[0].strip()
                if clean_host:
                    domains.add(clean_host)
        except Exception:
            pass

    return sorted(list(urls)), sorted(list(domains))


FREE_WEBMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "ymail.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "msn.com",
    "aol.com",
    "icloud.com",
    "mail.com",
    "protonmail.com",
    "proton.me",
    "zoho.com",
    "yandex.com",
    "gmx.com",
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".wsf",
    ".cpl", ".msi", ".jar", ".ps1", ".hta", ".iso", ".img"
}


def parse_address_entity(header_val: Optional[str]) -> AddressEntity:
    """Safely parses an email header into display name, email, and domain."""
    if not header_val:
        return AddressEntity(raw="", display_name="", email_address="", domain="")
    
    clean_val = str(header_val).strip()
    name, addr = parseaddr(clean_val)
    domain = ""
    if "@" in addr:
        domain = addr.split("@")[-1].lower().strip()
    
    return AddressEntity(
        raw=clean_val,
        display_name=name.strip(),
        email_address=addr.lower().strip(),
        domain=domain
    )


def parse_authentication_results(msg: email.message.EmailMessage) -> AuthenticationResults:
    """Parses Authentication-Results and Received-SPF headers with strict UNAVAILABLE tracking."""
    auth_header = msg.get("Authentication-Results") or msg.get("X-Authentication-Results")
    received_spf = msg.get("Received-SPF")
    
    res = AuthenticationResults()
    if not auth_header and not received_spf:
        return res

    raw_combined = f"{auth_header or ''} ; {received_spf or ''}".strip(" ;")
    res.raw_auth_header = raw_combined
    lower = raw_combined.lower()

    # SPF Evaluation
    if "spf=" in lower or "received-spf:" in lower:
        spf_match = re.search(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", lower)
        if spf_match:
            val = spf_match.group(1).upper()
            res.spf_status = AuthStatus(val) if val in AuthStatus.__members__ else AuthStatus.NEUTRAL
        elif "pass" in lower and "spf" in lower:
            res.spf_status = AuthStatus.PASS
        elif "fail" in lower and "spf" in lower:
            res.spf_status = AuthStatus.FAIL

    # DKIM Evaluation
    if "dkim=" in lower:
        dkim_match = re.search(r"dkim=(pass|fail|neutral|none|temperror|permerror)", lower)
        if dkim_match:
            val = dkim_match.group(1).upper()
            res.dkim_status = AuthStatus(val) if val in AuthStatus.__members__ else AuthStatus.NEUTRAL
        elif "header.i=" in lower or "header.d=" in lower:
            if "pass" in lower:
                res.dkim_status = AuthStatus.PASS

    # DMARC Evaluation
    if "dmarc=" in lower:
        dmarc_match = re.search(r"dmarc=(pass|fail|temperror|permerror|none)", lower)
        if dmarc_match:
            val = dmarc_match.group(1).upper()
            res.dmarc_status = AuthStatus(val) if val in AuthStatus.__members__ else AuthStatus.NEUTRAL

    return res


def parse_received_hops(msg: email.message.EmailMessage) -> List[ReceivedHop]:
    """Extracts and safely chronologizes 'Received' transit headers."""
    received_headers = msg.get_all("Received") or []
    hops: List[ReceivedHop] = []
    
    prev_dt = None
    # Received headers are prepended by each relay; top is the last hop
    for idx, raw_hop in enumerate(reversed(received_headers)):
        clean_hop = " ".join(str(raw_hop).split())
        
        # Extract IP address pattern
        ip_match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", clean_hop)
        ip = ip_match.group(1) if ip_match else None
        
        # Extract By / From patterns
        by_match = re.search(r"\bby\s+([^\s;]+)", clean_hop, re.IGNORECASE)
        from_match = re.search(r"\bfrom\s+([^\s;]+)", clean_hop, re.IGNORECASE)
        
        # Extract timestamp after semicolon
        dt = None
        iso_str = None
        delay = None
        if ";" in clean_hop:
            raw_ts = clean_hop.split(";")[-1].strip()
            try:
                dt = parsedate_to_datetime(raw_ts)
                iso_str = dt.isoformat()
                if prev_dt and dt:
                    delay = max(0.0, (dt - prev_dt).total_seconds())
                prev_dt = dt
            except Exception:
                pass

        hops.append(ReceivedHop(
            hop_index=idx + 1,
            by_host=by_match.group(1) if by_match else None,
            from_host=from_match.group(1) if from_match else None,
            ip=ip,
            timestamp_raw=clean_hop.split(";")[-1].strip() if ";" in clean_hop else None,
            timestamp_iso=iso_str,
            delay_seconds_from_prev=delay
        ))

    return hops


def sanitize_html(html_content: str) -> str:
    """Strips dangerous executable tags and returns sanitized plain text."""
    if not html_content:
        return ""
    soup = BeautifulSoup(html_content, "html.parser")
    for elem in soup(["script", "style", "iframe", "object", "embed", "svg"]):
        elem.decompose()
    return soup.get_text(separator="\n").strip()


def parse_eml_bytes(raw_bytes: bytes) -> ParsedEmail:
    """Parses raw .eml bytes into our comprehensive, strongly-typed ParsedEmail model."""
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    
    # Basic Headers
    message_id = msg.get("Message-ID", "")
    date_raw = msg.get("Date", "")
    date_iso = None
    if date_raw:
        try:
            date_iso = parsedate_to_datetime(date_raw).isoformat()
        except Exception:
            pass

    from_entity = parse_address_entity(msg.get("From"))
    reply_to_entity = parse_address_entity(msg.get("Reply-To")) if msg.get("Reply-To") else None
    return_path_entity = parse_address_entity(msg.get("Return-Path")) if msg.get("Return-Path") else None
    
    to_entities = []
    to_header = msg.get("To", "")
    if to_header:
        for addr_str in str(to_header).split(","):
            if addr_str.strip():
                to_entities.append(parse_address_entity(addr_str))

    subject = str(msg.get("Subject", "")).strip()

    # Body and MIME Walk
    body_plain_parts = []
    body_html_parts = []
    attachments = []
    part_count = 0

    if msg.is_multipart():
        for part in msg.walk():
            part_count += 1
            content_disposition = str(part.get("Content-Disposition", ""))
            content_type = part.get_content_type()

            if "attachment" in content_disposition.lower() or part.get_filename():
                filename = part.get_filename() or f"part_{part_count}.bin"
                payload = part.get_payload(decode=True) or b""
                size_bytes = len(payload)
                ext = f".{filename.split('.')[-1].lower()}" if "." in filename else ""
                
                # Check for double extension (e.g., invoice.pdf.exe)
                has_double_ext = len(filename.split(".")) > 2 and ext in EXECUTABLE_EXTENSIONS
                has_exec = ext in EXECUTABLE_EXTENSIONS

                attachments.append(AttachmentMetadata(
                    filename=filename,
                    content_type=content_type,
                    size_bytes=size_bytes,
                    extension=ext,
                    has_executable_extension=has_exec,
                    has_double_extension=has_double_ext
                ))
            else:
                try:
                    payload = part.get_content()
                    if isinstance(payload, str):
                        if content_type == "text/plain":
                            body_plain_parts.append(payload)
                        elif content_type == "text/html":
                            body_html_parts.append(payload)
                except Exception:
                    pass
    else:
        part_count = 1
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
            if isinstance(content, str):
                if content_type == "text/plain":
                    body_plain_parts.append(content)
                elif content_type == "text/html":
                    body_html_parts.append(content)
        except Exception:
            pass

    body_plain = "\n".join(body_plain_parts).strip()
    body_html = "\n".join(body_html_parts).strip()
    sanitized_html_text = sanitize_html(body_html)

    # If plain text was missing but HTML existed, fall back to sanitized HTML text
    if not body_plain and sanitized_html_text:
        body_plain = sanitized_html_text

    raw_headers = [
        ParsedHeader(name=str(k), value=str(v))
        for k, v in msg.items()
    ]

    # Extract URLs and domains across both plain text and raw HTML
    urls, domains = extract_urls_and_domains(body_plain, body_html)

    # Determine originating IP: first public IP in chronological hops (or first found IP)
    hops = parse_received_hops(msg)
    origin_ip = None
    for hop in hops:
        if hop.ip and is_public_ip(hop.ip):
            origin_ip = hop.ip
            break
    if not origin_ip and hops:
        # Fall back to first hop IP if all are local/gateway
        for hop in hops:
            if hop.ip:
                origin_ip = hop.ip
                break

    return ParsedEmail(
        message_id=message_id,
        date_raw=date_raw,
        date_iso=date_iso,
        from_entity=from_entity,
        to_entities=to_entities,
        reply_to_entity=reply_to_entity,
        return_path_entity=return_path_entity,
        subject=subject,
        body_plain=body_plain,
        body_html_sanitized=sanitized_html_text,
        received_hops=hops,
        auth_results=parse_authentication_results(msg),
        attachments=attachments,
        extracted_urls=urls,
        extracted_domains=domains,
        originating_ip=origin_ip,
        mime_type=msg.get_content_type(),
        is_multipart=msg.is_multipart(),
        part_count=part_count,
        raw_headers=raw_headers
    )


def parse_visible_text(subject: str, body: str, sender: str = "") -> ParsedEmail:
    """Lightweight parser for Tier-1 Gmail visible text and CSV inputs (headers marked unavailable)."""
    from_entity = parse_address_entity(sender) if sender else AddressEntity(raw="Unavailable")
    urls, domains = extract_urls_and_domains(body)

    return ParsedEmail(
        message_id=None,
        date_raw=None,
        date_iso=None,
        from_entity=from_entity,
        to_entities=[],
        reply_to_entity=None,
        return_path_entity=None,
        subject=subject or "",
        body_plain=body or "",
        body_html_sanitized="",
        received_hops=[],
        auth_results=AuthenticationResults(),
        attachments=[],
        extracted_urls=urls,
        extracted_domains=domains,
        originating_ip=None,
        mime_type="text/plain",
        is_multipart=False,
        part_count=1,
        raw_headers=[]
    )
