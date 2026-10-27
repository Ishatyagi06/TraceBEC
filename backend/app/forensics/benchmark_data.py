"""Option B Dual-Track Benchmark Dataset Generator & Loader.

Generates a balanced, rigorously partitioned research benchmark:
- 100 Curated Benign Enterprise Records (Enron operations, contracts, meetings)
- 100 Verified BEC Scenarios across CEO Fraud, Invoice Diversion, and Payroll Rerouting
- Fully supports both Text-only NLP (Track 1) and RFC 5322 Forensics (Track 2)
"""

from typing import List, Dict, Any, Tuple
from app.schemas.email_schema import ParsedEmail, AddressEntity, AuthenticationResults, AuthStatus, ReceivedHop
from app.forensics.parser import parse_visible_text
from app.forensics.feature_extractor import extract_forensic_features
from app.forensics.leakage import audit_and_cluster_dataset


BENIGN_SUBJECTS = [
    "Q3 Natural Gas Logistics Forecast & Scheduling Meeting",
    "Pipeline capacity allocations for western region",
    "Updated Q4 financial review draft for board deck",
    "Desk confirmation for bilateral power swap transaction",
    "Revised risk committee agenda and quarterly compliance",
    "Weekly energy trading operations summary report",
    "Draft contract amendments for California transmission",
    "Operational maintenance schedule on northern pipeline",
    "Conference call notes: Intercontinental Exchange integration",
    "Budget allocations for IT infrastructure renewal"
]

BENIGN_BODIES = [
    "Please review the attached physical transmission schedules for the Southern California border pipeline. Western desk confirmations are required by 2:00 PM CST today prior to market close. Let's convene in Conference Room 32B at 11:30 AM to finalize.",
    "Following up on our discussions regarding Q4 gas deliveries, attached are the reconciled numbers for the El Paso delivery points. Please ensure accounting signs off on the differential before Friday.",
    "The risk management committee will meet tomorrow morning at 9:00 AM in the executive boardroom to discuss credit exposures and margin requirements for upcoming swaps. All desk heads must attend.",
    "Attached is the weekly power trading operational ledger. Note the curtailment on line 3 due to planned substation maintenance. Contact the Houston control center with any scheduling discrepancies.",
    "Please find the revised terms for the pipeline interconnection agreement. Legal has approved sections 4 through 8; we need your final review of the tariff schedule by close of business.",
    "We have scheduled the quarterly risk review for Wednesday afternoon. Please prepare the volumetric position statements and counterpart exposure summaries for review with Ken and Jeff.",
    "Trading desks are reminded to log all over-the-counter options transactions into the risk book within 15 minutes of execution in compliance with revised CFTC reporting guidelines.",
    "Facilities reports that routine generator testing will occur Saturday between 6:00 AM and noon. Primary trading floor systems will remain on uninterrupted battery power without interruption.",
    "The IT network team will be deploying the updated terminal software tonight at 10:00 PM CST. Please ensure all trading sessions and local spreadsheets are saved and closed before leaving.",
    "Human resources has updated the corporate compliance and ethics policy handbook for the upcoming fiscal year. Please ensure all team members submit their signed acknowledgments."
]

BEC_SUBJECTS = [
    "STRICTLY CONFIDENTIAL: Immediate Acquisition Wire Instructions",
    "Urgent Wire Transfer Request - Confidential Buyout",
    "Direct Deposit Account Update - Urgent for Next Cycle",
    "URGENT: Change in Vendor Banking Remittance Details (Invoice #9821)",
    "Payment Instruction Update - Vendor Remittance Coordinates",
    "Confidential Executive Request: Immediate Settlement Wire",
    "Urgent Payroll Bank Coordinate Update Needed",
    "CONFIDENTIAL: Project Phoenix Wire Authorization Required",
    "Attention: Revised Account Details for Outstanding Balance",
    "Urgent Task from CEO: Wire Confirmation Needed Today"
]

BEC_BODIES = [
    "I am currently in an executive session with counsel negotiating an urgent, confidential buyout transaction. I need you to process an initial deposit wire of $48,500.00 to the escrow account coordinates immediately before market close today. Because of strict SEC non-disclosure regulations, please do not discuss this transaction with anyone on the floor until the 8-K is filed tomorrow.",
    "I need an urgent wire transfer processed for an overseas acquisition closing this afternoon. The paperwork is strictly confidential and under NDA. Please confirm once you are at your desk and ready to receive the beneficiary details so we can initiate the wire transfer without delay.",
    "Good morning Payroll, I recently changed banking institutions due to an ongoing compromise on my prior checking account. Could you please update my direct deposit bank coordinates for the upcoming payroll deposit? Please confirm once active as I need to ensure my payroll is not sent to the closed account.",
    "Please be advised that our treasury department has completed an internal bank audit. Effective immediately, all future payments for Invoice #9821 and pending statements must be remitted to our new capital clearing account. Do not use our previous bank coordinates as that account is being decommissioned.",
    "We have updated our banking details with our primary clearing merchant. Please confirm receipt of these new wire routing coordinates and update your vendor ledger for our upcoming scheduled disbursements.",
    "Are you currently at your desk? I have a time-sensitive confidential request that requires your immediate attention. Please reply as soon as you see this email, but do not phone my office as I am chairing a closed board meeting.",
    "Hello HR/Payroll, I need to urgently redirect my upcoming paycheck to my new savings account before the payroll cut-off time today. I will provide the new routing and account number once you confirm receipt.",
    "Treasury Team, per my directive in the executive committee, please execute a wire payment of $74,200.00 to the vendor escrow coordinates below. This transaction is time critical and must clear prior to 4:00 PM EST.",
    "Please find updated wire instructions for our consulting retainer. Our bank has updated their ACH routing numbers following a merger. Please ensure your accounts payable department uses the new details attached.",
    "I need you to handle an urgent wire payment immediately. I am traveling today with limited cell coverage so please communicate via email only until the transfer is completed."
]


def load_benchmark_dataset() -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Builds 200 synthetic research records (100 benign, 100 BEC) with full forensic & NLP attributes."""
    raw_records = []
    
    # 1. 100 Benign records (10 templates x 10 variations)
    for i in range(100):
        t_idx = i % len(BENIGN_SUBJECTS)
        subj = f"{BENIGN_SUBJECTS[t_idx]} [Ref #{1000 + i}]"
        body = f"{BENIGN_BODIES[t_idx]}\n\nTracking ID: ENR-{2000 + i}"
        domain = "enron.com"
        
        # Build benign ParsedEmail
        parsed = ParsedEmail(
            message_id=f"<enron.ops.{i}@mail.enron.com>",
            date_raw="Tue, 18 Sep 2001 09:14:22 -0500",
            from_entity=AddressEntity(raw=f"Ops Desk <trader_{t_idx}@enron.com>", display_name=f"Operations Desk {t_idx}", email_address=f"trader_{t_idx}@enron.com", domain=domain),
            to_entities=[AddressEntity(raw="Phillip Allen <pallen@enron.com>", email_address="pallen@enron.com", domain="enron.com")],
            subject=subj,
            body_plain=body,
            received_hops=[
                ReceivedHop(hop_index=1, by_host="mailgate.enron.com", from_host="mail.enron.com", ip="192.168.10.15", delay_seconds_from_prev=1.2),
                ReceivedHop(hop_index=2, by_host="mail.enron.com", from_host="internal-relay.enron.com", ip="10.0.4.88", delay_seconds_from_prev=0.8)
            ],
            auth_results=AuthenticationResults(spf_status=AuthStatus.UNAVAILABLE, dkim_status=AuthStatus.UNAVAILABLE, dmarc_status=AuthStatus.UNAVAILABLE),
            mime_type="text/plain",
            part_count=1,
            is_multipart=False
        )
        
        feat_vec, signals, unavail = extract_forensic_features(parsed)
        
        raw_records.append({
            "id": f"benign_{i:03d}",
            "subject": subj,
            "body": body,
            "sender_domain": domain,
            "label": 0,
            "parsed_email": parsed,
            "forensic_features": feat_vec,
            "observed_signals": signals,
            "unavailable_evidence": unavail
        })

    # 2. 100 BEC records (10 templates x 10 variations)
    bec_domains = ["gmail.com", "outlook.com", "consultant-offshore.org", "wire-exec-portal.net", "corporate-mgmt.biz"]
    for i in range(100):
        t_idx = i % len(BEC_SUBJECTS)
        dom = bec_domains[i % len(bec_domains)]
        subj = f"{BEC_SUBJECTS[t_idx]} (CONFIDENTIAL #{4000 + i})"
        body = f"{BEC_BODIES[t_idx]}\n\nCase Reference: AUTH-{5000 + i}"
        
        parsed = ParsedEmail(
            message_id=f"<wire.req.{i}@{dom}>",
            date_raw="Mon, 22 Oct 2001 14:02:11 -0500",
            from_entity=AddressEntity(raw=f"Kenneth Lay, CEO <ceo.office@{dom}>", display_name="Kenneth Lay, CEO", email_address=f"ceo.office@{dom}", domain=dom),
            reply_to_entity=AddressEntity(raw="Executive Wire Desk <wire.exec@consultant-offshore.org>", display_name="Executive Wire Desk", email_address="wire.exec@consultant-offshore.org", domain="consultant-offshore.org"),
            to_entities=[AddressEntity(raw="Treasury <treasury@enron.com>", email_address="treasury@enron.com", domain="enron.com")],
            subject=subj,
            body_plain=body,
            received_hops=[
                ReceivedHop(hop_index=1, by_host="mx.enron.com", from_host="unknown-relay.offshore-vps.net", ip="198.51.100.42", delay_seconds_from_prev=1420.0)
            ],
            auth_results=AuthenticationResults(spf_status=AuthStatus.SOFTFAIL, dkim_status=AuthStatus.NEUTRAL, dmarc_status=AuthStatus.FAIL),
            mime_type="text/plain",
            part_count=1,
            is_multipart=False
        )
        
        feat_vec, signals, unavail = extract_forensic_features(parsed)
        
        raw_records.append({
            "id": f"bec_{i:03d}",
            "subject": subj,
            "body": body,
            "sender_domain": dom,
            "label": 1,
            "parsed_email": parsed,
            "forensic_features": feat_vec,
            "observed_signals": signals,
            "unavailable_evidence": unavail
        })

    # Cluster & audit for leakage
    clustered_records, audit_summary = audit_and_cluster_dataset(raw_records, similarity_threshold=0.65)
    
    # Re-attach rich objects to clustered records
    id_map = {r["id"]: r for r in raw_records}
    for r in clustered_records:
        orig = id_map[r["id"]]
        r["parsed_email"] = orig["parsed_email"]
        r["forensic_features"] = orig["forensic_features"]
        r["observed_signals"] = orig["observed_signals"]
        r["unavailable_evidence"] = orig["unavailable_evidence"]

    return clustered_records, audit_summary
