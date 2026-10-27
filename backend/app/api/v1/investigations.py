"""Investigation Management API.

Supports retrieval and permanent deletion under user privacy and retention controls.
"""

from typing import Dict, List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, status
from app.schemas.email_schema import InvestigationRecord
from app.core.config import settings


router = APIRouter(prefix="/investigations", tags=["investigations"])

# In-memory investigation storage with thread-safe dictionary semantics
INVESTIGATION_STORE: Dict[str, InvestigationRecord] = {}


def save_investigation(record: InvestigationRecord):
    """Saves an investigation record if retention policy permits."""
    if settings.retention_mode != "ephemeral":
        INVESTIGATION_STORE[record.id] = record


@router.get("", response_model=List[InvestigationRecord])
def list_investigations():
    """Lists all stored investigations."""
    return list(INVESTIGATION_STORE.values())


@router.get("/{investigation_id}", response_model=InvestigationRecord)
def get_investigation(investigation_id: str):
    """Retrieves an authorized investigation record."""
    if investigation_id not in INVESTIGATION_STORE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' not found."
        )
    return INVESTIGATION_STORE[investigation_id]


@router.delete("/{investigation_id}", status_code=status.HTTP_200_OK)
def delete_investigation(investigation_id: str):
    """Permanently deletes an investigation record under user privacy policy."""
    if investigation_id not in INVESTIGATION_STORE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' not found."
        )
    del INVESTIGATION_STORE[investigation_id]
    return {"status": "deleted", "investigation_id": investigation_id}
