"""Offline labeled-dataset evaluation for NetMask Sentinel."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
)

from netmask.detection import DetectionEngine
from netmask.features import FEATURE_NAMES


def _normalized(name: object) -> str:
    return "".join(character.lower() for character in str(name) if character.isalnum())


def _resolve_columns(frame: pd.DataFrame, label_column: str) -> tuple[list[str], str]:
    available = {_normalized(column): str(column) for column in frame.columns}
    resolved_features: list[str] = []
    missing: list[str] = []
    for feature in FEATURE_NAMES:
        match = available.get(_normalized(feature))
        if match is None:
            missing.append(feature)
        else:
            resolved_features.append(match)
    if missing:
        raise ValueError(f"Dataset is missing feature columns: {missing}")

    label = available.get(_normalized(label_column))
    if label is None:
        for candidate in ("label", "classification", "class", "target"):
            label = available.get(candidate)
            if label:
                break
    if label is None:
        raise ValueError(
            f"Label column '{label_column}' was not found. Available columns: {list(frame.columns)}"
        )
    return resolved_features, label


def evaluate(
    dataset: Path,
    engine: DetectionEngine,
    *,
    label_column: str,
) -> dict[str, object]:
    frame = pd.read_csv(dataset)
    feature_columns, resolved_label = _resolve_columns(frame, label_column)
    numeric = frame[feature_columns].apply(pd.to_numeric, errors="coerce")
    finite_mask = np.isfinite(numeric.to_numpy(dtype=float)).all(axis=1)
    labels = frame[resolved_label].astype(str).str.strip()
    known_mask = labels.isin(engine.classes)
    valid_mask = finite_mask & known_mask.to_numpy()

    if not valid_mask.any():
        raise ValueError("No valid labeled rows remain after validation")

    valid_features = numeric.loc[valid_mask].to_numpy(dtype=float)
    y_true = labels.loc[valid_mask].tolist()
    detections = engine.detect_many(valid_features)
    y_pred = [item.classification for item in detections]
    attack_scores = np.asarray([item.attack_probability for item in detections])
    y_attack = np.asarray([label != "Benign" for label in y_true], dtype=int)

    report = classification_report(
        y_true,
        y_pred,
        labels=list(engine.classes),
        output_dict=True,
        zero_division=0,
    )
    result: dict[str, object] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": str(dataset.resolve()),
        "rows": {
            "total": int(len(frame)),
            "evaluated": int(valid_mask.sum()),
            "invalid_features": int((~finite_mask).sum()),
            "unknown_labels": int((~known_mask).sum()),
        },
        "model": engine.metadata(),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "classification_report": report,
        "labels": list(engine.classes),
        "confusion_matrix": confusion_matrix(
            y_true, y_pred, labels=list(engine.classes)
        ).tolist(),
        "risk_distribution": dict(Counter(item.risk_level for item in detections)),
        "attack_average_precision": (
            float(average_precision_score(y_attack, attack_scores))
            if len(set(y_attack.tolist())) > 1
            else None
        ),
        "warning": (
            "Metrics describe this dataset only. The legacy model probabilities are not calibrated."
        ),
    }
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate the NetMask Sentinel classifier on a labeled CSV with the canonical 39 features."
    )
    parser.add_argument("dataset", nargs="?", type=Path, help="Labeled CSV dataset")
    parser.add_argument("--model", type=Path, default=Path("models/model.pkl"))
    parser.add_argument("--label-column", default="Label")
    parser.add_argument("--output", type=Path, default=Path("reports/evaluation.json"))
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Validate the model contract and write metadata without a dataset",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        engine = DetectionEngine.from_pickle(args.model)
        if args.smoke:
            payload = {
                "status": "ok",
                "model": engine.metadata(),
                "zero_vector_detection": engine.detect(np.zeros(len(FEATURE_NAMES))).to_dict(),
            }
        else:
            if args.dataset is None:
                raise ValueError("A dataset is required unless --smoke is used")
            payload = evaluate(args.dataset, engine, label_column=args.label_column)

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        print(f"\nReport written to {args.output.resolve()}")
        return 0
    except Exception as exc:
        print(f"Evaluation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())