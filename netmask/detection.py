"""Validated model inference and risk scoring."""

from __future__ import annotations

import hashlib
import json
import pickle
import platform
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import sklearn

from .features import FEATURE_COUNT, FEATURE_NAMES, validate_feature_vector


@dataclass(frozen=True)
class RiskPolicy:
    """Explicit thresholds for the total probability of any non-benign class."""

    low: float = 0.20
    medium: float = 0.40
    high: float = 0.60
    very_high: float = 0.80

    def __post_init__(self) -> None:
        values = (self.low, self.medium, self.high, self.very_high)
        if any(value < 0 or value > 1 for value in values):
            raise ValueError("Risk thresholds must be between 0 and 1")
        if list(values) != sorted(values) or len(set(values)) != len(values):
            raise ValueError("Risk thresholds must be strictly increasing")

    def level_for(self, attack_probability: float) -> str:
        if attack_probability >= self.very_high:
            return "very_high"
        if attack_probability >= self.high:
            return "high"
        if attack_probability >= self.medium:
            return "medium"
        if attack_probability >= self.low:
            return "low"
        return "minimal"


@dataclass(frozen=True)
class DetectionResult:
    classification: str
    confidence: float
    attack_probability: float
    risk_level: str
    probabilities: dict[str, float]
    should_alert: bool
    inference_ms: float
    model_version: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DetectionEngine:
    """Thread-safe inference wrapper enforcing the model's feature contract."""

    def __init__(
        self,
        classifier: Any,
        *,
        risk_policy: RiskPolicy | None = None,
        model_path: str | Path | None = None,
        model_version: str = "legacy-rf-1",
    ) -> None:
        self.classifier = classifier
        self.risk_policy = risk_policy or RiskPolicy()
        self.model_path = Path(model_path).resolve() if model_path else None
        self.model_version = model_version
        self._lock = threading.Lock()
        self.classes = tuple(str(value) for value in classifier.classes_)
        if "Benign" not in self.classes:
            raise ValueError("Classifier must expose a Benign class")
        if getattr(classifier, "n_features_in_", FEATURE_COUNT) != FEATURE_COUNT:
            raise ValueError(
                f"Classifier expects {classifier.n_features_in_} features, not {FEATURE_COUNT}"
            )
        self._validate_probability_contract()

    @classmethod
    def from_pickle(
        cls,
        model_path: str | Path,
        *,
        risk_policy: RiskPolicy | None = None,
        model_version: str = "legacy-rf-1",
    ) -> "DetectionEngine":
        path = Path(model_path)
        with path.open("rb") as model_file:
            classifier = pickle.load(model_file)
        return cls(
            classifier,
            risk_policy=risk_policy,
            model_path=path,
            model_version=model_version,
        )

    def _predict_probabilities(self, matrix: np.ndarray) -> np.ndarray:
        with self._lock:
            probabilities = np.asarray(self.classifier.predict_proba(matrix), dtype=float)
        if probabilities.ndim != 2 or probabilities.shape[1] != len(self.classes):
            raise RuntimeError(f"Invalid probability shape: {probabilities.shape}")
        if not np.isfinite(probabilities).all():
            raise RuntimeError("Model returned non-finite probabilities")
        if (probabilities < -1e-9).any() or (probabilities > 1 + 1e-9).any():
            raise RuntimeError("Model returned probabilities outside [0, 1]")
        sums = probabilities.sum(axis=1)
        if not np.allclose(sums, 1.0, atol=1e-6):
            raise RuntimeError(f"Model probabilities do not sum to 1: {sums.tolist()}")
        return probabilities

    def _validate_probability_contract(self) -> None:
        self._predict_probabilities(np.zeros((1, FEATURE_COUNT), dtype=np.float64))

    def detect(self, values: list[object] | tuple[object, ...] | np.ndarray) -> DetectionResult:
        features = validate_feature_vector(values)
        started = time.perf_counter()
        row = self._predict_probabilities(features.reshape(1, -1))[0]
        inference_ms = (time.perf_counter() - started) * 1000
        probability_map = {
            class_name: float(probability)
            for class_name, probability in zip(self.classes, row, strict=True)
        }
        classification = self.classes[int(np.argmax(row))]
        confidence = float(np.max(row))
        attack_probability = float(1.0 - probability_map["Benign"])
        risk_level = self.risk_policy.level_for(attack_probability)
        should_alert = classification != "Benign" or risk_level in {"high", "very_high"}
        return DetectionResult(
            classification=classification,
            confidence=confidence,
            attack_probability=attack_probability,
            risk_level=risk_level,
            probabilities=probability_map,
            should_alert=should_alert,
            inference_ms=round(inference_ms, 3),
            model_version=self.model_version,
        )

    def detect_many(self, matrix: np.ndarray) -> list[DetectionResult]:
        rows = [validate_feature_vector(row) for row in matrix]
        return [self.detect(row) for row in rows]

    def metadata(self) -> dict[str, Any]:
        digest = None
        if self.model_path and self.model_path.is_file():
            digest = hashlib.sha256(self.model_path.read_bytes()).hexdigest()
        return {
            "model_version": self.model_version,
            "model_sha256": digest,
            "model_path": str(self.model_path) if self.model_path else None,
            "classes": list(self.classes),
            "feature_count": FEATURE_COUNT,
            "feature_names": list(FEATURE_NAMES),
            "risk_policy": asdict(self.risk_policy),
            "probability_calibrated": False,
            "calibration_note": "Legacy model; thresholds require labeled validation data.",
            "scikit_learn_version": sklearn.__version__,
            "python_version": platform.python_version(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def write_metadata(self, destination: str | Path) -> Path:
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.metadata(), indent=2), encoding="utf-8")
        return path