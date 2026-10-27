"""Benchmark Execution Engine & CPU Resource Profiler.

Executes and benchmarks:
- Dataset profiling (schema, lengths, leakage audit)
- E1: TF-IDF + Logistic Regression (Linguistic Baseline)
- E3: Tabular Forensics + XGBoost (Digital Evidence Baseline)
- Latency & CPU compute requirements profiling
- Emits reproducible research artifact: research/baseline_results.json
"""

import os
import json
import time
from pathlib import Path

from app.forensics.benchmark_data import load_benchmark_dataset
from app.forensics.profiler import profile_dataset_records
from app.models.baseline_tfidf import evaluate_e1_baseline
from app.models.forensic_xgboost import evaluate_e3_baseline


def run_full_baseline_benchmark() -> str:
    """Executes dataset profiling, E1, E3, and records results."""
    print("=== Step 1: Loading Option B Benchmark Dataset ===")
    records, audit_summary = load_benchmark_dataset()
    print(f"Loaded {len(records)} records. Unique clusters: {audit_summary['unique_clusters']}")

    print("\n=== Step 2: Profiling Dataset Schema & Forensic Completeness ===")
    profile = profile_dataset_records(records)
    print(f"Total samples: {profile['total_samples']}")
    print(f"Class distribution: {profile['class_distribution']}")
    print(f"Leakage audit summary: {profile['leakage_audit']}")

    # Prepare inputs for E1 and E3
    texts = [f"{r['subject']} {r['body']}" for r in records]
    labels = [r["label"] for r in records]
    cluster_ids = [r["cluster_id"] for r in records]
    features = [r["forensic_features"] for r in records]

    print("\n=== Step 3: Training & Evaluating E1 (TF-IDF + Logistic Regression) ===")
    t0 = time.perf_counter()
    e1_results = evaluate_e1_baseline(texts, labels, cluster_ids, n_splits=5)
    e1_total_time = time.perf_counter() - t0
    print(f"E1 Completed in {e1_total_time:.2f}s")
    print(f"  Random Split F1: {e1_results['random_split']['f1_mean']} | PR-AUC: {e1_results['random_split']['pr_auc_mean']}")
    print(f"  Cluster-Disjoint F1: {e1_results['cluster_disjoint_split']['f1_mean']} | PR-AUC: {e1_results['cluster_disjoint_split']['pr_auc_mean']}")
    print(f"  Leakage Delta F1: {e1_results['leakage_delta_f1']}")

    print("\n=== Step 4: Training & Evaluating E3 (Tabular Forensics + XGBoost) ===")
    t1 = time.perf_counter()
    e3_results = evaluate_e3_baseline(features, labels, cluster_ids, n_splits=5)
    e3_total_time = time.perf_counter() - t1
    print(f"E3 Completed in {e3_total_time:.2f}s")
    print(f"  Random Split F1: {e3_results['random_split']['f1_mean']} | PR-AUC: {e3_results['random_split']['pr_auc_mean']}")
    print(f"  Cluster-Disjoint F1: {e3_results['cluster_disjoint_split']['f1_mean']} | PR-AUC: {e3_results['cluster_disjoint_split']['pr_auc_mean']}")
    print(f"  Leakage Delta F1: {e3_results['leakage_delta_f1']}")

    print("\n=== Step 5: Evaluating E2 (DistilRoBERTa Contextual NLP) ===")
    from app.models.transformer_nlp import evaluate_e2_transformer
    t2 = time.perf_counter()
    e2_results = evaluate_e2_transformer(texts, labels, cluster_ids, n_splits=5)
    e2_total_time = time.perf_counter() - t2
    print(f"E2 Completed in {e2_total_time:.2f}s")
    print(f"  Random Split F1: {e2_results['random_split']['f1_mean']} | PR-AUC: {e2_results['random_split']['pr_auc_mean']}")
    print(f"  Cluster-Disjoint F1: {e2_results['cluster_disjoint_split']['f1_mean']} | PR-AUC: {e2_results['cluster_disjoint_split']['pr_auc_mean']}")
    print(f"  Leakage Delta F1: {e2_results['leakage_delta_f1']}")

    print("\n=== Step 6: Evaluating E4 (Multimodal Text-Forensic Fusion) ===")
    from app.models.fusion_classifier import evaluate_e4_fusion
    t3 = time.perf_counter()
    e4_results = evaluate_e4_fusion(texts, features, labels, cluster_ids, n_splits=5)
    e4_total_time = time.perf_counter() - t3
    print(f"E4 Completed in {e4_total_time:.2f}s")
    print(f"  Random Split F1: {e4_results['random_split']['f1_mean']} | PR-AUC: {e4_results['random_split']['pr_auc_mean']}")
    print(f"  Cluster-Disjoint F1: {e4_results['cluster_disjoint_split']['f1_mean']} | PR-AUC: {e4_results['cluster_disjoint_split']['pr_auc_mean']}")
    print(f"  Leakage Delta F1: {e4_results['leakage_delta_f1']}")

    # Compile comprehensive research artifact
    all_experiments = [e1_results, e2_results, e3_results, e4_results]
    
    # Sort models by Cluster-Disjoint F1, then Brier score
    ranked_cluster = sorted(
        all_experiments,
        key=lambda x: (x["cluster_disjoint_split"]["f1_mean"], -x["cluster_disjoint_split"]["brier_score_mean"]),
        reverse=True
    )

    research_artifact = {
        "benchmark_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host_environment": {
            "os": "Windows",
            "cpu_mode": True,
            "python_version": "3.11.9"
        },
        "dataset_profile": profile,
        "experiments": all_experiments,
        "comparative_analysis": {
            "cluster_disjoint_ranking": [
                {
                    "rank": idx + 1,
                    "experiment_id": exp["experiment_id"],
                    "model_name": exp["model_name"],
                    "f1": exp["cluster_disjoint_split"]["f1_mean"],
                    "pr_auc": exp["cluster_disjoint_split"]["pr_auc_mean"],
                    "brier_score": exp["cluster_disjoint_split"]["brier_score_mean"],
                    "infer_latency_ms": exp["cluster_disjoint_split"]["avg_infer_latency_ms"]
                }
                for idx, exp in enumerate(ranked_cluster)
            ],
            "latency_profile_ms": {
                exp["experiment_id"]: exp["cluster_disjoint_split"]["avg_infer_latency_ms"]
                for exp in all_experiments
            }
        }
    }

    research_dir = Path(__file__).parent.parent.parent.parent / "research"
    research_dir.mkdir(exist_ok=True)
    out_file = research_dir / "full_benchmark_results.json"
    
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(research_artifact, f, indent=2)

    print(f"\n[OK] Full 4-Experiment benchmark results written to: {out_file}")
    return str(out_file)


if __name__ == "__main__":
    run_full_baseline_benchmark()
