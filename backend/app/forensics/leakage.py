"""Leakage Auditing & Exploratory Cluster-Disjoint Splitting.

Implements rigorous evaluation hygiene:
1. Exact de-duplication (SHA-256)
2. Near-duplicate grouping via MinHash-style shingles
3. Cluster-disjoint group generation to prevent template leakage across folds
4. Side-by-side comparison with standard random splitting
"""

import hashlib
import re
from typing import List, Dict, Set, Tuple, Any
import numpy as np
import pandas as pd


def normalize_text(text: str) -> str:
    """Normalizes whitespace and casing for reliable deduplication."""
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r"\s+", " ", text).strip()
    return text


def compute_exact_hash(subject: str, body: str) -> str:
    """Calculates SHA-256 of normalized subject and body."""
    combined = f"{normalize_text(subject)}||{normalize_text(body)}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def get_k_shingles(text: str, k: int = 4) -> Set[str]:
    """Extracts k-word shingles for near-duplicate Jaccard estimation."""
    words = normalize_text(text).split()
    if len(words) < k:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i:i+k]) for i in range(len(words) - k + 1)}


def jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    """Computes Jaccard similarity between two sets of shingles."""
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return float(intersection) / float(union) if union > 0 else 0.0


def audit_and_cluster_dataset(
    records: List[Dict[str, Any]],
    similarity_threshold: float = 0.70
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Audits input records for exact/near duplicates and assigns cluster IDs.
    
    Each record must have: 'id', 'subject', 'body', 'sender_domain', 'label'.
    Returns:
    - enriched records with 'cluster_id' and 'is_duplicate' flag
    - summary audit metrics
    """
    exact_hashes: Dict[str, str] = {}
    enriched = []
    shingle_cache: Dict[str, Set[str]] = {}
    cluster_map: Dict[str, int] = {}
    next_cluster_id = 0

    exact_dup_count = 0
    near_dup_count = 0

    # Pass 1: Exact Hash & Shingle caching
    for r in records:
        rec_id = str(r["id"])
        subj = r.get("subject", "")
        body = r.get("body", "")
        domain = r.get("sender_domain", "unknown")
        
        h = compute_exact_hash(subj, body)
        shingles = get_k_shingles(f"{subj} {body}", k=2)
        shingle_cache[rec_id] = shingles
        
        is_exact_dup = False
        exact_dup_of = None
        if h in exact_hashes:
            is_exact_dup = True
            exact_dup_count += 1
            exact_dup_of = exact_hashes[h]
        else:
            exact_hashes[h] = rec_id

        enriched.append({
            **r,
            "hash": h,
            "is_exact_duplicate": is_exact_dup,
            "exact_dup_of": exact_dup_of,
            "temp_cluster": None
        })

    # Pass 2: Near-Duplicate Clustering
    for i, r_i in enumerate(enriched):
        id_i = str(r_i["id"])
        
        # If this is an exact duplicate of an earlier record, inherit its cluster
        if r_i["exact_dup_of"] is not None and r_i["exact_dup_of"] in cluster_map:
            r_i["temp_cluster"] = cluster_map[r_i["exact_dup_of"]]
            cluster_map[id_i] = r_i["temp_cluster"]
            continue

        if r_i["temp_cluster"] is not None:
            continue
        
        # New cluster leader
        cluster_id = next_cluster_id
        next_cluster_id += 1
        r_i["temp_cluster"] = cluster_id
        cluster_map[id_i] = cluster_id
        shingles_i = shingle_cache[id_i]
        dom_i = r_i.get("sender_domain", "").lower()

        for j in range(i + 1, len(enriched)):
            r_j = enriched[j]
            id_j = str(r_j["id"])
            
            if r_j["exact_dup_of"] == id_i:
                r_j["temp_cluster"] = cluster_id
                cluster_map[id_j] = cluster_id
                continue

            if r_j["temp_cluster"] is not None:
                continue
            
            shingles_j = shingle_cache[id_j]
            sim = jaccard_similarity(shingles_i, shingles_j)
            
            # Cluster if text shares template similarity
            if sim >= similarity_threshold:
                r_j["temp_cluster"] = cluster_id
                cluster_map[id_j] = cluster_id
                near_dup_count += 1

    # Finalize cluster assignment
    final_records = []
    for r in enriched:
        cid = r["temp_cluster"] if r["temp_cluster"] is not None else next_cluster_id
        final_records.append({
            "id": r["id"],
            "subject": r.get("subject", ""),
            "body": r.get("body", ""),
            "sender_domain": r.get("sender_domain", "unknown"),
            "label": r.get("label", 0),
            "cluster_id": f"cluster_{cid:04d}",
            "is_duplicate": r["is_exact_duplicate"]
        })

    unique_clusters = len(set(r["cluster_id"] for r in final_records))
    summary = {
        "total_records": len(records),
        "exact_duplicates": exact_dup_count,
        "near_duplicates": near_dup_count,
        "unique_clusters": unique_clusters,
        "leakage_risk_rating": "HIGH" if (exact_dup_count + near_dup_count) / max(1, len(records)) > 0.2 else "MODERATE"
    }

    return final_records, summary
