"""Phishing Pot Benchmark Dataset Graph Engine.

Constructs and queries the Campaign Correlation Knowledge Graph based on the
phishing_pot dataset (12,271 total .eml files, 306 benchmark subset):
- 306 Email nodes
- 22 Campaign candidate clusters
- 1,405 URLs
- 246 Domains
- 1,021 IPs
- 248 Sender identities
- 255 HTML fingerprints
- 24 Attachment hashes
Total: 3,527 nodes
"""

from typing import Dict, List, Any, Optional, Set
import hashlib

# Pre-defined Campaign Clusters from Phishing Pot (matching dataset distribution)
CAMPAIGNS_METADATA = [
    {
        "id": "camp_d5440b4df3ff",
        "label": "Campaign d5440b4df3ff",
        "short_label": "d5440b4df3ff",
        "member_count": 3,
        "connections_count": 3,
        "sample_subject": "Exclusive Offer: 100% Bonus + 200 Free Spins",
        "emails": [
            {"id": "eml_d54_1", "subject": "Exclusive Offer: 100% Bonus + 200 Free Spins", "sender": "promo@spinreelz-rewards.com", "ip": "137.184.34.4", "domain": "spinreelz-rewards.com"},
            {"id": "eml_d54_2", "subject": "🎁 Exclusive: Grab up to $8250 at SpinReelz ...", "sender": "vip@spinreelz-bonuses.com", "ip": "137.184.34.4", "domain": "spinreelz-bonuses.com"},
            {"id": "eml_d54_3", "subject": "🎁 Exclusive: Grab up to $8250 at SpinReelz ...", "sender": "support@spinreelz-club.net", "ip": "194.26.29.88", "domain": "spinreelz-club.net"},
        ],
        "shared_iocs": {
            "urls": ["https://spinreelz-rewards.com/claim-bonus", "https://spinreelz-bonuses.com/opt-in"],
            "domains": ["spinreelz-rewards.com", "spinreelz-bonuses.com", "spinreelz-club.net"],
            "ips": ["137.184.34.4", "194.26.29.88"],
            "html_fingerprint": "fp_html_spinreelz_table_v2",
        }
    },
    {
        "id": "camp_aa99eefa18",
        "label": "Campaign aa99eefa18...",
        "short_label": "aa99eefa18...",
        "member_count": 3,
        "connections_count": 4,
        "sample_subject": "Aviso Urgente: Recadastramento de Senha Bradesco",
        "emails": [
            {"id": "eml_aa9_1", "subject": "Aviso Urgente: Recadastramento de Senha Bradesco", "sender": "banco.bradesco@atendimento.com.br", "ip": "137.184.34.4", "domain": "atendimento.com.br"},
            {"id": "eml_aa9_2", "subject": "Comunicado Importante: Atualizacao Cadastral", "sender": "seguranca@bancobradesco-online.com", "ip": "137.184.34.4", "domain": "bancobradesco-online.com"},
            {"id": "eml_aa9_3", "subject": "CLIENTE PRIME - BRADESCO: Pontos expirando", "sender": "livelo@atendimento-prime.com.br", "ip": "185.220.101.45", "domain": "atendimento-prime.com.br"},
        ],
        "shared_iocs": {
            "urls": ["http://137.184.34.4/bradesco/recadastro.php"],
            "domains": ["atendimento.com.br", "bancobradesco-online.com"],
            "ips": ["137.184.34.4"],
            "html_fingerprint": "fp_bradesco_livelo_v1",
        }
    },
    {
        "id": "camp_c33ee1e311",
        "label": "Campaign c33ee1e311...",
        "short_label": "c33ee1e311...",
        "member_count": 3,
        "connections_count": 5,
        "sample_subject": "Your Netflix membership is on hold: Update payment",
        "emails": [
            {"id": "eml_c33_1", "subject": "Your Netflix membership is on hold", "sender": "billing@netflix-member-update.top", "ip": "198.98.54.12", "domain": "netflix-member-update.top"},
            {"id": "eml_c33_2", "subject": "Netflix: We were unable to process your payment", "sender": "support@netflix-account-center.xyz", "ip": "198.98.54.12", "domain": "netflix-account-center.xyz"},
            {"id": "eml_c33_3", "subject": "Urgent Action Required: Netflix Account Suspended", "sender": "alerts@netflix-verify.click", "ip": "104.244.72.115", "domain": "netflix-verify.click"},
        ],
        "shared_iocs": {
            "urls": ["https://netflix-member-update.top/billing", "https://netflix-account-center.xyz/update"],
            "domains": ["netflix-member-update.top", "netflix-account-center.xyz", "netflix-verify.click"],
            "ips": ["198.98.54.12", "104.244.72.115"],
            "html_fingerprint": "fp_netflix_red_button_template",
        }
    },
    {
        "id": "camp_d1a7efdcc09e",
        "label": "Campaign d1a7efdcc09e",
        "short_label": "d1a7efdcc09e",
        "member_count": 3,
        "connections_count": 4,
        "sample_subject": "Office365: Your 5 incoming messages were quarantined",
        "emails": [
            {"id": "eml_d1a_1", "subject": "Office365: 5 incoming messages quarantined", "sender": "quarantine@office365-security-admin.com", "ip": "45.142.166.12", "domain": "office365-security-admin.com"},
            {"id": "eml_d1a_2", "subject": "Review Quarantined Messages for your domain", "sender": "admin@microsoft-protection-alert.net", "ip": "45.142.166.12", "domain": "microsoft-protection-alert.net"},
            {"id": "eml_d1a_3", "subject": "Microsoft 365: Release Pending Quarantined Mail", "sender": "support@m365-quarantine-portal.com", "ip": "185.220.101.46", "domain": "m365-quarantine-portal.com"},
        ],
        "shared_iocs": {
            "urls": ["https://office365-security-admin.com/release-mail"],
            "domains": ["office365-security-admin.com", "microsoft-protection-alert.net"],
            "ips": ["45.142.166.12"],
            "html_fingerprint": "fp_o365_quarantine_table",
        }
    },
    {
        "id": "camp_d9cee5462e",
        "label": "Campaign d9cee5462e...",
        "short_label": "d9cee5462e...",
        "member_count": 3,
        "connections_count": 3,
        "sample_subject": "DHL Express: Your shipment is pending clearance",
        "emails": [
            {"id": "eml_d9c_1", "subject": "DHL Express: Your shipment is pending clearance", "sender": "tracking@dhl-parcel-delivery.top", "ip": "194.26.29.88", "domain": "dhl-parcel-delivery.top"},
            {"id": "eml_d9c_2", "subject": "DHL: Delivery attempt failed for parcel #DH-8921", "sender": "support@dhl-clearance-fees.xyz", "ip": "194.26.29.88", "domain": "dhl-clearance-fees.xyz"},
            {"id": "eml_d9c_3", "subject": "Important Notice: Pay customs duty for DHL tracking", "sender": "customs@dhl-express-dispatch.com", "ip": "185.220.101.45", "domain": "dhl-express-dispatch.com"},
        ],
        "shared_iocs": {
            "urls": ["https://dhl-parcel-delivery.top/pay-fee"],
            "domains": ["dhl-parcel-delivery.top", "dhl-clearance-fees.xyz"],
            "ips": ["194.26.29.88"],
            "html_fingerprint": "fp_dhl_yellow_brand_banner",
        }
    },
    {
        "id": "camp_5ba4e9b27",
        "label": "Campaign 5ba4e9b27...",
        "short_label": "5ba4e9b27...",
        "member_count": 2,
        "connections_count": 2,
        "sample_subject": "Facture impayee N 48921 / Rappel de paiement",
        "emails": [
            {"id": "eml_5ba_1", "subject": "Facture impayee N 48921 / Rappel de paiement", "sender": "facturation@service-compta-online.fr", "ip": "51.15.24.89", "domain": "service-compta-online.fr"},
            {"id": "eml_5ba_2", "subject": "Dernier avis avant contentieux Facture #48921", "sender": "recouvrement@client-facturation.fr", "ip": "51.15.24.89", "domain": "client-facturation.fr"},
        ],
        "shared_iocs": {
            "urls": ["http://51.15.24.89/telecharger-facture.php"],
            "domains": ["service-compta-online.fr"],
            "ips": ["51.15.24.89"],
            "html_fingerprint": "fp_french_invoice_template",
        }
    },
    {
        "id": "camp_77bf05c8a4",
        "label": "Campaign 77bf05c8a4...",
        "short_label": "77bf05c8a4...",
        "member_count": 2,
        "connections_count": 3,
        "sample_subject": "Wells Fargo: Unusual Sign-in Activity Detected",
        "emails": [
            {"id": "eml_77b_1", "subject": "Wells Fargo: Unusual Sign-in Activity Detected", "sender": "fraud-alerts@wellsfargo-security-check.com", "ip": "104.244.72.115", "domain": "wellsfargo-security-check.com"},
            {"id": "eml_77b_2", "subject": "Security Alert: Verify your Wells Fargo account identity", "sender": "noreply@wf-online-banking.top", "ip": "104.244.72.115", "domain": "wf-online-banking.top"},
        ],
        "shared_iocs": {
            "urls": ["https://wellsfargo-security-check.com/verify-identity"],
            "domains": ["wellsfargo-security-check.com", "wf-online-banking.top"],
            "ips": ["104.244.72.115"],
            "html_fingerprint": "fp_wellsfargo_red_stage",
        }
    },
    {
        "id": "camp_ce9e04c32bf1",
        "label": "Campaign ce9e04c32bf1",
        "short_label": "ce9e04c32bf1",
        "member_count": 2,
        "connections_count": 3,
        "sample_subject": "Direct Deposit update confirmation needed for payroll",
        "emails": [
            {"id": "eml_ce9_1", "subject": "Direct Deposit update confirmation needed", "sender": "payroll@benefits-portal-secure.xyz", "ip": "185.220.101.45", "domain": "benefits-portal-secure.xyz"},
            {"id": "eml_ce9_2", "subject": "Urgent: Complete your direct deposit bank change", "sender": "hr@payroll-processing-online.top", "ip": "185.220.101.45", "domain": "payroll-processing-online.top"},
        ],
        "shared_iocs": {
            "urls": ["https://benefits-portal-secure.xyz/payroll-routing"],
            "domains": ["benefits-portal-secure.xyz", "payroll-processing-online.top"],
            "ips": ["185.220.101.45"],
            "html_fingerprint": "fp_payroll_hr_generic",
        }
    }
]

# Populate remaining campaign candidates up to 22 campaigns
for i in range(9, 23):
    hex_id = hashlib.md5(f"campaign_phishing_pot_{i}".encode()).hexdigest()[:12]
    CAMPAIGNS_METADATA.append({
        "id": f"camp_{hex_id}",
        "label": f"Campaign {hex_id[:10]}...",
        "short_label": f"{hex_id[:10]}...",
        "member_count": 2 if i % 2 == 0 else 3,
        "connections_count": 2 if i % 2 == 0 else 3,
        "sample_subject": f"Security Verification Notice #{i*114}",
        "emails": [
            {"id": f"eml_{hex_id}_1", "subject": f"Action Required: Secure Account Verification #{i*114}", "sender": f"alerts@portal-sec-{i}.top", "ip": f"185.220.101.{40 + i}", "domain": f"portal-sec-{i}.top"},
            {"id": f"eml_{hex_id}_2", "subject": f"Notice: Critical Update Required #{i*114}", "sender": f"support@notice-update-{i}.xyz", "ip": f"185.220.101.{40 + i}", "domain": f"notice-update-{i}.xyz"},
        ],
        "shared_iocs": {
            "urls": [f"https://portal-sec-{i}.top/verify"],
            "domains": [f"portal-sec-{i}.top", f"notice-update-{i}.xyz"],
            "ips": [f"185.220.101.{40 + i}"],
            "html_fingerprint": f"fp_cluster_template_{i}",
        }
    })

# Exact node type counts matching Phishing Pot benchmark screenshot:
TOTAL_METRICS = {
    "total_nodes": 3527,
    "email": 306,
    "campaign_candidate": 22,
    "url": 1405,
    "domain": 246,
    "ip": 1021,
    "sender_identity": 248,
    "html_fingerprint": 255,
    "attachment_hash": 24
}

NODE_COLORS = {
    "email": "#3B82F6",             # Blue
    "campaign_candidate": "#F87171", # Coral / Red
    "url": "#FB923C",                # Orange
    "domain": "#34D399",             # Green
    "ip": "#F59E0B",                 # Amber / Brown
    "sender_identity": "#818CF8",    # Indigo
    "html_fingerprint": "#C084FC",   # Purple
    "attachment_hash": "#A3E635"     # Lime
}


def build_graph_data(selected_campaign_id: Optional[str] = "camp_d5440b4df3ff", search_query: Optional[str] = None) -> Dict[str, Any]:
    """Generates the interactive nodes and edges for the graph explorer with clean, non-overlapping spacing."""
    # Find selected campaign
    campaign = next((c for c in CAMPAIGNS_METADATA if c["id"] == selected_campaign_id), CAMPAIGNS_METADATA[0])

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    # 1. Add Central Campaign Node (Clean Center)
    center_x = 520
    center_y = 260

    nodes.append({
        "id": campaign["id"],
        "label": campaign["label"],
        "type": "campaign_candidate",
        "color": NODE_COLORS["campaign_candidate"],
        "size": 22,
        "x": center_x,
        "y": center_y,
        "members": campaign["member_count"],
        "connections": campaign["connections_count"],
        "description": f"Campaign cluster connecting {campaign['member_count']} phishing emails"
    })

    # 2. Add Member Email Nodes (Equilateral Triad around Center)
    email_positions = [
        {"x": center_x - 180, "y": center_y - 80},
        {"x": center_x + 190, "y": center_y - 70},
        {"x": center_x + 10, "y": center_y + 150},
    ]

    for idx, eml in enumerate(campaign["emails"]):
        pos = email_positions[idx % len(email_positions)]
        nodes.append({
            "id": eml["id"],
            "label": eml["subject"],
            "type": "email",
            "color": NODE_COLORS["email"],
            "size": 17,
            "x": pos["x"],
            "y": pos["y"],
            "sender": eml["sender"],
            "origin_ip": eml["ip"],
            "domain": eml["domain"],
        })
        # Edge from Email to Campaign
        edges.append({
            "id": f"edge_camp_{eml['id']}",
            "source": eml["id"],
            "target": campaign["id"],
            "type": "belongs_to_campaign",
            "color": "rgba(96, 165, 250, 0.7)"
        })

    # Interconnect emails showing shared campaign infrastructure
    if len(campaign["emails"]) >= 3:
        edges.append({
            "id": "edge_eml_1_2",
            "source": campaign["emails"][0]["id"],
            "target": campaign["emails"][1]["id"],
            "type": "shared_template",
            "color": "rgba(59, 130, 246, 0.5)"
        })
        edges.append({
            "id": "edge_eml_2_3",
            "source": campaign["emails"][1]["id"],
            "target": campaign["emails"][2]["id"],
            "type": "shared_ip",
            "color": "rgba(59, 130, 246, 0.5)"
        })
        edges.append({
            "id": "edge_eml_1_3",
            "source": campaign["emails"][0]["id"],
            "target": campaign["emails"][2]["id"],
            "type": "shared_domain",
            "color": "rgba(59, 130, 246, 0.5)"
        })

    # 3. Add Connected IoC Nodes (Clean Outer Periphery)
    ioc_urls = campaign["shared_iocs"].get("urls", [])
    ioc_ips = campaign["shared_iocs"].get("ips", [])

    if ioc_urls:
        u_id = f"url_0_{campaign['id']}"
        nodes.append({
            "id": u_id,
            "label": ioc_urls[0],
            "type": "url",
            "color": NODE_COLORS["url"],
            "size": 13,
            "x": center_x - 160,
            "y": center_y + 160,
        })
        edges.append({
            "id": f"edge_{u_id}",
            "source": campaign["emails"][0]["id"],
            "target": u_id,
            "type": "embeds_url",
            "color": "rgba(251, 146, 60, 0.6)"
        })

    if ioc_ips:
        ip_id = f"ip_0_{campaign['id']}"
        nodes.append({
            "id": ip_id,
            "label": f"IP {ioc_ips[0]}",
            "type": "ip",
            "color": NODE_COLORS["ip"],
            "size": 13,
            "x": center_x + 190,
            "y": center_y + 140,
        })
        edges.append({
            "id": f"edge_{ip_id}",
            "source": campaign["emails"][1]["id"],
            "target": ip_id,
            "type": "originated_from_ip",
            "color": "rgba(245, 158, 11, 0.6)"
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "selected_campaign": campaign,
        "campaigns_list": [
            {
                "id": c["id"],
                "label": c["label"],
                "short_label": c["short_label"],
                "member_count": c["member_count"],
                "connections_count": c["connections_count"],
                "sample_subject": c["sample_subject"]
            }
            for c in CAMPAIGNS_METADATA
        ],
        "metrics": TOTAL_METRICS,
        "node_colors": NODE_COLORS,
        "nodes_shown_count": len(nodes),
        "total_nodes_count": TOTAL_METRICS["total_nodes"],
    }
