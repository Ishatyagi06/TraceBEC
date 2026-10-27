"""Dataset Profiler & Schema Validation Engine.

Profiles datasets for research readiness:
- Class balance & label integrity
- Missing field proportions (e.g. headers vs text-only)
- Text token length distributions
- Duplicate and template leakage quantification
"""

import pandas as pd
import numpy as np
from typing import Dict, Any, List
from app.forensics.leakage import audit_and_cluster_dataset


def profile_dataset_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generates a comprehensive research profile of a dataset."""
    if not records:
        return {"error": "Dataset is empty"}

    df = pd.DataFrame(records)
    total_count = len(df)

    # Label distribution
    label_counts = {}
    if "label" in df.columns:
        raw_counts = df["label"].value_counts().to_dict()
        label_counts = {str(k): int(v) for k, v in raw_counts.items()}
    
    # Missing fields
    missing_fields = {}
    for col in ["subject", "body", "from", "date", "received_hops", "auth_results"]:
        if col in df.columns:
            null_count = int(df[col].isna().sum() + (df[col] == "").sum())
            missing_fields[col] = {
                "missing_count": null_count,
                "missing_pct": round((null_count / total_count) * 100, 2)
            }
        else:
            missing_fields[col] = {
                "missing_count": total_count,
                "missing_pct": 100.0,
                "note": "Column absent from dataset"
            }

    # Text length statistics
    lengths = df["body"].astype(str).apply(lambda x: len(x.split()))
    length_stats = {
        "min_words": int(lengths.min()),
        "max_words": int(lengths.max()),
        "mean_words": round(float(lengths.mean()), 1),
        "median_words": int(lengths.median()),
        "p95_words": int(np.percentile(lengths, 95))
    }

    # Run leakage and cluster audit
    cleaned_records = []
    for idx, row in df.iterrows():
        cleaned_records.append({
            "id": row.get("id", str(idx)),
            "subject": str(row.get("subject", "")),
            "body": str(row.get("body", "")),
            "sender_domain": str(row.get("sender_domain", "unknown")),
            "label": row.get("label", 0)
        })

    _, leakage_summary = audit_and_cluster_dataset(cleaned_records)

    return {
        "total_samples": total_count,
        "class_distribution": label_counts,
        "missing_field_analysis": missing_fields,
        "length_distribution": length_stats,
        "leakage_audit": leakage_summary,
        "forensic_readiness": "FULL" if missing_fields.get("received_hops", {}).get("missing_pct", 100) < 50 else "TEXT_ONLY_RESTRICTED"
    }
