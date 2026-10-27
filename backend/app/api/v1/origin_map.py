"""Origin Traceability Map API Endpoints.

Serves geographic and routing hop trajectory data for origin inspection:
- GET /api/v1/origin-map/trace: Trace geographical origin and relay hops for an IP
"""

from typing import Optional
from fastapi import APIRouter, Query
from app.forensics.origin_map import get_origin_trace_trajectory, resolve_ip_geo

router = APIRouter(prefix="/origin-map", tags=["origin-map"])


@router.get("/trace")
def trace_origin_map(
    ip: Optional[str] = Query("185.220.101.45", description="Target IP to trace")
):
    """Returns geographical coordinates, hops, and transit trajectory for the Origin Map."""
    return get_origin_trace_trajectory(origin_ip=ip)


@router.get("/geo/{ip}")
def resolve_ip(ip: str):
    """Resolves single IP to geolocation and ASN context."""
    return resolve_ip_geo(ip)
