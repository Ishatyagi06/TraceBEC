"""Datasets Profiling & Validation API.

Implements POST /datasets/profile for auditing uploaded datasets:
- Schema detection
- Class balance
- Missing field proportions
- Token length distribution
- Template leakage and near-duplicate audit
"""

from typing import List, Dict, Any, Optional
import io
import pandas as pd
from fastapi import APIRouter, UploadFile, File, HTTPException, status
from pydantic import BaseModel
import os
from pathlib import Path

from app.forensics.parser import parse_eml_bytes
from app.forensics.profiler import profile_dataset_records


router = APIRouter(prefix="/datasets", tags=["datasets"])


def get_phishing_pot_dir() -> Path:
    candidates = [
        Path(os.getcwd()) / "data" / "phishing_pot",
        Path(__file__).resolve().parents[4] / "data" / "phishing_pot",
        Path("c:/Users/ISHA TYAGI/OneDrive/Desktop/phisGuard/data/phishing_pot"),
    ]
    for p in candidates:
        if p.exists() and p.is_dir():
            return p
    return candidates[0]


class DatasetProfileRequest(BaseModel):
    records: List[Dict[str, Any]]


@router.get("/profile_phishing_pot")
def profile_phishing_pot_dataset():
    """Profiles the real PhishingPot honeypot dataset (.eml files) located on disk."""
    phishing_dir = get_phishing_pot_dir()
    if not phishing_dir.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"PhishingPot dataset directory not found at {phishing_dir}"
        )
    
    eml_files = sorted(list(phishing_dir.glob("*.eml")))
    if not eml_files:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No .eml files found in {phishing_dir}"
        )

    records: List[Dict[str, Any]] = []
    file_metadata = []

    for fpath in eml_files:
        try:
            with open(fpath, "rb") as fp:
                raw_bytes = fp.read()
            parsed = parse_eml_bytes(raw_bytes)
            
            body_text = parsed.body_plain or parsed.body_html_sanitized or ""
            sender = parsed.from_entity.email_address or parsed.from_entity.raw or "unknown"
            sender_domain = parsed.from_entity.domain or "unknown"
            
            rec = {
                "id": fpath.name,
                "subject": parsed.subject or "(No Subject)",
                "body": body_text,
                "sender_domain": sender_domain,
                "from": sender,
                "date": parsed.date_iso or parsed.date_raw or "",
                "received_hops": len(parsed.received_hops) if parsed.received_hops else None,
                "auth_results": parsed.auth_results.model_dump() if parsed.auth_results else None,
                "label": 1
            }
            records.append(rec)
            file_metadata.append({
                "filename": fpath.name,
                "subject": parsed.subject or "(No Subject)",
                "sender": sender,
                "size_bytes": len(raw_bytes),
                "hops_count": len(parsed.received_hops),
                "originating_ip": parsed.originating_ip
            })
        except Exception:
            continue

    if not records:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to parse any .eml records from dataset."
        )

    profile = profile_dataset_records(records)
    profile["dataset_name"] = "PhishingPot Honeypot Dataset"
    profile["dataset_path"] = str(phishing_dir)
    profile["sample_files"] = file_metadata
    return profile


@router.post("/profile")
def profile_dataset_json(payload: DatasetProfileRequest):
    """Profiles a JSON list of dataset records."""
    if not payload.records:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must contain non-empty 'records' list."
        )
    return profile_dataset_records(payload.records)


@router.post("/profile/upload")
async def profile_dataset_file(file: UploadFile = File(...)):
    """Profiles an uploaded .csv or .json dataset file."""
    filename = file.filename.lower()
    content = await file.read()
    records: List[Dict[str, Any]] = []

    if filename.endswith(".csv"):
        try:
            df = pd.read_csv(io.BytesIO(content))
            records = df.to_dict(orient="records")
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to parse CSV file: {str(e)}"
            )
    elif filename.endswith(".json"):
        import json
        try:
            records = json.loads(content.decode("utf-8"))
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to parse JSON file: {str(e)}"
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Supported dataset formats are .csv and .json"
        )

    return profile_dataset_records(records)
