"""Experiment 3 (E3): Structured Forensic Baseline.

Architecture: 30+ Tabular Forensic Features + XGBoost Classifier.
Evaluates technical indicators alone (addressing, routing, authentication, MIME).
Tests both Random and Exploratory Cluster-Disjoint splits.
"""

import time
from typing import Dict, Any, List
import numpy as np
import xgboost as xgb
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
)
from sklearn.model_selection import StratifiedKFold, StratifiedGroupKFold

from app.schemas.email_schema import ForensicFeatureVector


def vector_to_numpy(features: List[ForensicFeatureVector]) -> np.ndarray:
    """Converts a list of Pydantic ForensicFeatureVectors into a 2D float32 numpy array."""
    rows = []
    for f in features:
        row = [
            float(f.display_name_length),
            float(f.has_display_name),
            float(f.display_name_contains_email),
            float(f.from_reply_to_mismatch),
            float(f.from_return_path_mismatch),
            float(f.from_is_free_webmail),
            float(f.reply_to_is_free_webmail),
            float(f.display_name_mimics_corp_domain),
            float(f.spf_pass),
            float(f.spf_fail),
            float(f.spf_available),
            float(f.dkim_pass),
            float(f.dkim_fail),
            float(f.dkim_available),
            float(f.dmarc_pass),
            float(f.dmarc_fail),
            float(f.dmarc_available),
            float(f.received_hops_count),
            float(f.has_transit_delay_anomaly),
            float(f.max_hop_delay_seconds),
            float(f.is_multipart),
            float(f.part_count),
            float(f.attachment_count),
            float(f.has_executable_attachment),
            float(f.has_double_extension_attachment),
            float(f.body_plain_char_count),
            float(f.body_plain_word_count),
            float(f.subject_char_count),
            float(f.subject_word_count),
            float(f.has_links_in_body),
            float(f.link_count),
            float(f.zero_attachment_zero_link),
        ]
        rows.append(row)
    return np.array(rows, dtype=np.float32)


def evaluate_e3_baseline(
    features: List[ForensicFeatureVector],
    labels: List[int],
    cluster_ids: List[str],
    n_splits: int = 5
) -> Dict[str, Any]:
    """Runs 5-fold evaluation for E3 under both Random and Cluster-Disjoint splits."""
    X = vector_to_numpy(features)
    y = np.array(labels, dtype=np.int32)
    groups = np.array(cluster_ids)

    def _run_cv(cv_splitter, split_name: str) -> Dict[str, Any]:
        precisions, recalls, f1s, roc_aucs, pr_aucs, brier_scores = [], [], [], [], [], []
        train_times, infer_times = [], []
        conf_matrices = []

        splits = cv_splitter.split(X, y, groups=groups) if isinstance(cv_splitter, StratifiedGroupKFold) else cv_splitter.split(X, y)
        
        for fold_idx, (train_idx, test_idx) in enumerate(splits):
            X_train, X_test = X[train_idx], X[test_idx]
            y_train, y_test = y[train_idx], y[test_idx]

            model = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=4,
                learning_rate=0.05,
                subsample=0.8,
                colsample_bytree=0.8,
                eval_metric="logloss",
                random_state=42,
                n_jobs=2
            )
            
            t0 = time.perf_counter()
            model.fit(X_train, y_train)
            t_train = time.perf_counter() - t0
            train_times.append(t_train)

            t1 = time.perf_counter()
            probs = model.predict_proba(X_test)[:, 1]
            t_infer = (time.perf_counter() - t1) / max(1, len(X_test))
            infer_times.append(t_infer * 1000.0)

            preds = (probs >= 0.5).astype(int)

            precisions.append(precision_score(y_test, preds, zero_division=0))
            recalls.append(recall_score(y_test, preds, zero_division=0))
            f1s.append(f1_score(y_test, preds, zero_division=0))
            roc_aucs.append(roc_auc_score(y_test, probs) if len(set(y_test)) > 1 else 0.5)
            pr_aucs.append(average_precision_score(y_test, probs) if len(set(y_test)) > 1 else 0.5)
            brier_scores.append(brier_score_loss(y_test, probs))
            conf_matrices.append(confusion_matrix(y_test, preds, labels=[0, 1]))

        total_cm = np.sum(conf_matrices, axis=0).tolist()
        return {
            "split_type": split_name,
            "precision_mean": round(float(np.mean(precisions)), 4),
            "recall_mean": round(float(np.mean(recalls)), 4),
            "f1_mean": round(float(np.mean(f1s)), 4),
            "roc_auc_mean": round(float(np.mean(roc_aucs)), 4),
            "pr_auc_mean": round(float(np.mean(pr_aucs)), 4),
            "brier_score_mean": round(float(np.mean(brier_scores)), 4),
            "avg_train_time_sec": round(float(np.mean(train_times)), 4),
            "avg_infer_latency_ms": round(float(np.mean(infer_times)), 3),
            "confusion_matrix": total_cm,
        }

    random_results = _run_cv(StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42), "Random Split (Stratified K-Fold)")
    cluster_results = _run_cv(StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=42), "Exploratory Cluster-Disjoint (Stratified Group K-Fold)")

    leakage_delta_f1 = round(random_results["f1_mean"] - cluster_results["f1_mean"], 4)

    return {
        "experiment_id": "E3_Forensic_XGBoost",
        "model_name": "Tabular Forensics + XGBoost (Digital Evidence Baseline)",
        "random_split": random_results,
        "cluster_disjoint_split": cluster_results,
        "leakage_delta_f1": leakage_delta_f1,
        "note": f"Template leakage delta: F1 drops by {leakage_delta_f1 * 100:.2f}% under cluster-disjoint holdout."
    }
