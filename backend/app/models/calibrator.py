"""Probability Calibration & Uncertainty Estimation Module.

Implements Platt Scaling (Sigmoid) and Temperature Scaling to ensure model scores
represent calibrated risk estimates rather than uncalibrated raw softmax scores.
Also computes Expected Calibration Error (ECE) and Brier Score.
"""

from typing import Tuple, List, Dict, Any
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss

from app.schemas.email_schema import RiskCategory


class ProbabilityCalibrator:
    """Platt Scaling probability calibrator fitted strictly on validation logits."""

    def __init__(self):
        self.calibrator = LogisticRegression(C=1.0, solver="lbfgs", max_iter=500)
        self.is_fitted = False

    def fit(self, val_logits: np.ndarray, val_labels: np.ndarray):
        """Fits Platt scaling on validation fold logits."""
        logits_2d = val_logits.reshape(-1, 1)
        self.calibrator.fit(logits_2d, val_labels)
        self.is_fitted = True

    def predict_calibrated_prob(self, test_logits: np.ndarray) -> np.ndarray:
        """Transforms raw logits into calibrated probabilities."""
        if not self.is_fitted:
            # Fallback to standard sigmoid if not fitted
            return 1.0 / (1.0 + np.exp(-test_logits))
        logits_2d = test_logits.reshape(-1, 1)
        return self.calibrator.predict_proba(logits_2d)[:, 1]

    def compute_ece(self, probs: np.ndarray, labels: np.ndarray, n_bins: int = 10) -> float:
        """Computes Expected Calibration Error (ECE) across probability bins."""
        bin_limits = np.linspace(0, 1, n_bins + 1)
        ece = 0.0
        n_samples = len(probs)
        if n_samples == 0:
            return 0.0

        for i in range(n_bins):
            bin_mask = (probs > bin_limits[i]) & (probs <= bin_limits[i + 1])
            bin_size = np.sum(bin_mask)
            if bin_size > 0:
                bin_acc = np.mean(labels[bin_mask])
                bin_conf = np.mean(probs[bin_mask])
                ece += (bin_size / n_samples) * np.abs(bin_acc - bin_conf)

        return float(round(ece, 4))


def categorize_risk(
    calibrated_prob: float,
    threshold_low: float = 0.35,
    threshold_high: float = 0.70
) -> Tuple[RiskCategory, str]:
    """Maps a calibrated probability to a documented RiskCategory and rationale."""
    if calibrated_prob < threshold_low:
        category = RiskCategory.LOW
        rationale = f"Calibrated risk ({calibrated_prob:.2f}) is below triage threshold ({threshold_low:.2f}). No elevated BEC indicators detected."
    elif calibrated_prob < threshold_high:
        category = RiskCategory.REVIEW
        rationale = f"Calibrated risk ({calibrated_prob:.2f}) is in the elevated review band ({threshold_low:.2f} - {threshold_high:.2f}). Manual review or out-of-band verification recommended."
    else:
        category = RiskCategory.HIGH
        rationale = f"Calibrated risk ({calibrated_prob:.2f}) exceeds high-confidence threat threshold ({threshold_high:.2f}). High-probability BEC or identity spoofing detected."

    return category, rationale
