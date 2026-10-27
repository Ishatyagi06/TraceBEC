"""Campaign Graph Explorer API Endpoints.

Serves the Phishing Pot Campaign Knowledge Graph (3,527 nodes, 306 emails, 22 campaigns):
- GET /api/v1/campaigns/graph: Fetch graph nodes, edges, and statistics
- GET /api/v1/campaigns/list: Fetch all 22 campaign candidates with email counts
"""

from typing import Optional
from fastapi import APIRouter, Query
from app.forensics.phishing_pot_graph import build_graph_data, CAMPAIGNS_METADATA, TOTAL_METRICS

router = APIRouter(prefix="/campaigns", tags=["campaigns"])


@router.get("/graph")
def get_campaign_graph(
    campaign_id: Optional[str] = Query("camp_d5440b4df3ff", description="Selected Campaign ID"),
    search: Optional[str] = Query(None, description="Search query by label or ID")
):
    """Returns the interactive Campaign Knowledge Graph data matching Phishing Pot dataset."""
    return build_graph_data(selected_campaign_id=campaign_id, search_query=search)


@router.get("/list")
def get_campaigns_list():
    """Returns all 22 identified campaign candidates with member email counts."""
    return {
        "campaigns": [
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
        "total_campaigns": len(CAMPAIGNS_METADATA),
        "metrics": TOTAL_METRICS
    }
