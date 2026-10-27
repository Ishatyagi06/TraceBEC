"""Historical Evidence Database.

Maintains repository of:
- Previously analysed phishing emails & incident records
- Known malicious URLs and domains
- IP and infrastructure history
- Campaign groupings (e.g. Campaign #BEC-WIRE-2026, Campaign #PAYROLL-SPOOF)
- External threat intelligence feed snapshots
"""

from typing import List, Dict, Any

HISTORICAL_CAMPAIGNS: List[Dict[str, Any]] = [
    {
        "campaign_id": "CAMP-BEC-WIRE-01",
        "campaign_name": "Executive Wire Fraud & Acquisition Secrecy Campaign",
        "actor_signature": "BEC-FinActor-Apex",
        "indicators": {
            "keywords": ["wire", "confidential", "acquisition", "board of directors", "strictly confidential"],
            "from_display_names": ["CEO", "Chief Executive Officer", "Executive Vice President"],
            "sending_domains": ["gmail.com", "outlook.com", "corporate-exec-mail.com"],
            "ips": ["185.220.101.45", "185.220.101.46", "198.98.54.12"],
            "urls": ["http://185.220.101.45/invoice.pdf"]
        },
        "sample_subject": "Urgent & Confidential: Wire Transfer Directive for Closing Acquisition",
        "first_seen": "2026-08-14T09:20:00Z",
        "total_incidents_recorded": 14
    },
    {
        "campaign_id": "CAMP-PAYROLL-UPD-02",
        "campaign_name": "Direct Deposit / Payroll Routing Diversion",
        "actor_signature": "PayrollPhish-Syndicate",
        "indicators": {
            "keywords": ["payroll", "direct deposit", "routing number", "bank change", "update my bank details"],
            "from_display_names": ["HR Payroll", "Human Resources Support", "Benefits Coordinator"],
            "sending_domains": ["hr-portal-benefits.xyz", "payroll-support.top"],
            "ips": ["104.244.72.115", "192.42.116.14"],
            "urls": ["https://payroll-portal-update.xyz/direct-deposit"]
        },
        "sample_subject": "Quick Request: Update my payroll banking coordinates before Friday",
        "first_seen": "2026-09-02T14:15:00Z",
        "total_incidents_recorded": 28
    },
    {
        "campaign_id": "CAMP-O365-CREDHVEST-03",
        "campaign_name": "Office365 / Corporate SSO Credential Harvester",
        "actor_signature": "CloudHarvester-Storm",
        "indicators": {
            "keywords": ["password expired", "mailbox full", "verify your account", "re-authenticate"],
            "from_display_names": ["IT Administrator", "Microsoft 365 Alert", "Security Operations"],
            "sending_domains": ["microsoft-support-team.net", "login-office365-verify.click"],
            "ips": ["45.142.166.12", "194.26.29.88"],
            "urls": ["https://login-office365-verify.click/auth"]
        },
        "sample_subject": "Action Required: Your Microsoft 365 password expires in 2 hours",
        "first_seen": "2026-10-10T11:00:00Z",
        "total_incidents_recorded": 62
    }
]


def get_all_campaigns() -> List[Dict[str, Any]]:
    """Returns all active campaign records in the Historical Evidence Database."""
    return HISTORICAL_CAMPAIGNS
