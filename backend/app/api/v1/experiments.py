"""Research Lab Experiments API.

Implements:
- GET /experiments: Retrieve all experiment configurations and metrics
- GET /experiments/{id}: Retrieve detailed results for a specific experiment (E1 - E4)
- POST /experiments: Trigger a documented experiment run
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel


router = APIRouter(prefix="/experiments", tags=["experiments"])

RESEARCH_DIR = Path(__file__).parent.parent.parent.parent.parent / "research"


class ExperimentCreateRequest(BaseModel):
    experiment_id: str
    description: Optional[str] = ""
    n_splits: int = 5


def _load_benchmark_results() -> Dict[str, Any]:
    """Loads the benchmark results JSON artifact."""
    res_file = RESEARCH_DIR / "full_benchmark_results.json"
    if not res_file.exists():
        res_file = RESEARCH_DIR / "baseline_results.json"
    if res_file.exists():
        try:
            with open(res_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "experiments": [],
        "comparative_analysis": {"cluster_disjoint_ranking": [], "latency_profile_ms": {}}
    }


@router.get("")
def list_experiments():
    """Retrieves all experiment statuses, metrics, and rankings."""
    data = _load_benchmark_results()
    return data


@router.get("/nlp-benchmarks")
def get_nlp_benchmarks():
    """Returns the actual notebook NLP text-classification benchmark results."""
    from app.models.baseline_tfidf import get_actual_notebook_benchmark_results
    return get_actual_notebook_benchmark_results()


@router.get("/{experiment_id}")
def get_experiment_details(experiment_id: str):
    """Retrieves details and fold metrics for a specific experiment."""
    if experiment_id.lower() == "nlp-benchmarks":
        from app.models.baseline_tfidf import get_actual_notebook_benchmark_results
        return get_actual_notebook_benchmark_results()

    data = _load_benchmark_results()
    experiments = data.get("experiments", [])
    for exp in experiments:
        if exp.get("experiment_id", "").lower() == experiment_id.lower():
            return exp
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Experiment '{experiment_id}' not found in research benchmark records."
    )

