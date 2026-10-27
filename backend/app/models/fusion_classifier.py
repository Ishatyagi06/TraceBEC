"""Experiment 4 (E4): Multimodal Text-Forensic Fusion Classifier.

Core Research Experiment:
Fuses deep contextual text representations (DistilRoBERTa 768-dim) with
defensible digital forensic features (32-dim) into a joint calibrated classification head.
Evaluates Random Split vs Exploratory Cluster-Disjoint Split and compares against E1, E2, E3.
"""

import time
from typing import Dict, Any, List, Tuple
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
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
from app.models.forensic_xgboost import vector_to_numpy
from app.models.transformer_nlp import TransformerFeatureExtractor
from app.models.calibrator import ProbabilityCalibrator, categorize_risk


class MultimodalFusionModel:
    """Combines text embeddings and standardized forensic features with Platt calibration."""

    def __init__(self):
        self.scaler = StandardScaler()
        self.classifier = LogisticRegression(class_weight="balanced", C=0.5, max_iter=1000, random_state=42)
        self.calibrator = ProbabilityCalibrator()
        self.is_fitted = False

    def fit(self, X_text_embed: np.ndarray, X_forensic: np.ndarray, y: np.ndarray):
        """Fits scaler strictly on training split, then fits classifier and calibrator."""
        X_forensic_scaled = self.scaler.fit_transform(X_forensic)
        X_fused = np.hstack([X_text_embed, X_forensic_scaled])
        
        self.classifier.fit(X_fused, y)
        train_logits = self.classifier.decision_function(X_fused)
        self.calibrator.fit(train_logits, y)
        self.is_fitted = True

    def predict_proba(self, X_text_embed: np.ndarray, X_forensic: np.ndarray) -> np.ndarray:
        """Emits calibrated probabilities for fused representations."""
        if not self.is_fitted:
            raise ValueError("Model is not fitted.")
        X_forensic_scaled = self.scaler.transform(X_forensic)
        X_fused = np.hstack([X_text_embed, X_forensic_scaled])
        raw_logits = self.classifier.decision_function(X_fused)
        return self.calibrator.predict_calibrated_prob(raw_logits)


def evaluate_e4_fusion(
    texts: List[str],
    features: List[ForensicFeatureVector],
    labels: List[int],
    cluster_ids: List[str],
    n_splits: int = 5
) -> Dict[str, Any]:
    """Runs 5-fold evaluation for E4 Multimodal Fusion under both splits."""
    extractor = TransformerFeatureExtractor()
    t_feat_start = time.perf_counter()
    X_embed = extractor.extract_pooled_embeddings(texts)
    X_forensic = vector_to_numpy(features)
    y = np.array(labels, dtype=np.int32)
    groups = np.array(cluster_ids)
    feat_time = time.perf_counter() - t_feat_start

    def _run_cv(cv_splitter, split_name: str) -> Dict[str, Any]:
        precisions, recalls, f1s, roc_aucs, pr_aucs, brier_scores, eces = [], [], [], [], [], [], []
        train_times, infer_times = [], []
        conf_matrices = []

        splits = cv_splitter.split(X_embed, y, groups=groups) if isinstance(cv_splitter, StratifiedGroupKFold) else cv_splitter.split(X_embed, y)

        for fold_idx, (train_idx, test_idx) in enumerate(splits):
            X_emb_train, X_emb_test = X_embed[train_idx], X_embed[test_idx]
            X_for_train, X_for_test = X_forensic[train_idx], X_forensic[test_idx]
            y_train, y_test = y[train_idx], y[test_idx]

            fusion_model = MultimodalFusionModel()
            
            t0 = time.perf_counter()
            fusion_model.fit(X_emb_train, X_for_train, y_train)
            t_train = time.perf_counter() - t0
            train_times.append(t_train)

            t1 = time.perf_counter()
            probs = fusion_model.predict_proba(X_emb_test, X_for_test)
            t_infer = (time.perf_counter() - t1) / max(1, len(test_idx))
            infer_times.append(t_infer * 1000.0)

            preds = (probs >= 0.5).astype(int)

            precisions.append(precision_score(y_test, preds, zero_division=0))
            recalls.append(recall_score(y_test, preds, zero_division=0))
            f1s.append(f1_score(y_test, preds, zero_division=0))
            roc_aucs.append(roc_auc_score(y_test, probs) if len(set(y_test)) > 1 else 0.5)
            pr_aucs.append(average_precision_score(y_test, probs) if len(set(y_test)) > 1 else 0.5)
            brier_scores.append(brier_score_loss(y_test, probs))
            eces.append(fusion_model.calibrator.compute_ece(probs, y_test))
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
            "ece_mean": round(float(np.mean(eces)), 4),
            "avg_train_time_sec": round(float(np.mean(train_times)), 4),
            "avg_infer_latency_ms": round(float(np.mean(infer_times)), 3),
            "confusion_matrix": total_cm,
        }

    random_results = _run_cv(StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42), "Random Split (Stratified K-Fold)")
    cluster_results = _run_cv(StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=42), "Exploratory Cluster-Disjoint (Stratified Group K-Fold)")

    leakage_delta_f1 = round(random_results["f1_mean"] - cluster_results["f1_mean"], 4)

    return {
        "experiment_id": "E4_Multimodal_Fusion",
        "model_name": "Multimodal Fusion (DistilRoBERTa + Tabular Forensics + Calibrator)",
        "random_split": random_results,
        "cluster_disjoint_split": cluster_results,
        "leakage_delta_f1": leakage_delta_f1,
        "feature_extraction_time_sec": round(feat_time, 2),
        "note": f"Template leakage delta: F1 drops by {leakage_delta_f1 * 100:.2f}% under cluster-disjoint holdout."
    }
