"""Canonical feature contract shared by live inference and offline evaluation."""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np

FEATURE_NAMES: tuple[str, ...] = (
    "FlowDuration",
    "BwdPacketLengthMax",
    "BwdPacketLengthMin",
    "BwdPacketLengthMean",
    "BwdPacketLengthStd",
    "FlowIATMean",
    "FlowIATStd",
    "FlowIATMax",
    "FlowIATMin",
    "FwdIATTotal",
    "FwdIATMean",
    "FwdIATStd",
    "FwdIATMax",
    "FwdIATMin",
    "BwdIATTotal",
    "BwdIATMean",
    "BwdIATStd",
    "BwdIATMax",
    "BwdIATMin",
    "FwdPSHFlags",
    "FwdPackets/s",
    "PacketLengthMax",
    "PacketLengthMean",
    "PacketLengthStd",
    "PacketLengthVariance",
    "FINFlagCount",
    "SYNFlagCount",
    "PSHFlagCount",
    "ACKFlagCount",
    "URGFlagCount",
    "AveragePacketSize",
    "BwdSegmentSizeAvg",
    "FWDInitWinBytes",
    "BwdInitWinBytes",
    "ActiveMin",
    "IdleMean",
    "IdleStd",
    "IdleMax",
    "IdleMin",
)

METADATA_NAMES: tuple[str, ...] = (
    "Src",
    "SrcPort",
    "Dest",
    "DestPort",
    "Protocol",
    "FlowStartTime",
    "FlowLastSeen",
    "PName",
    "PID",
)

FEATURE_COUNT = len(FEATURE_NAMES)
METADATA_COUNT = len(METADATA_NAMES)
FLOW_RECORD_COUNT = FEATURE_COUNT + METADATA_COUNT


class FeatureValidationError(ValueError):
    """Raised when a flow cannot safely be passed to the trained model."""


def validate_feature_vector(values: Sequence[object]) -> np.ndarray:
    """Return one finite float64 feature row with the canonical 39-column shape."""
    if len(values) != FEATURE_COUNT:
        raise FeatureValidationError(
            f"Expected {FEATURE_COUNT} features, received {len(values)}"
        )

    try:
        row = np.asarray(values, dtype=np.float64)
    except (TypeError, ValueError) as exc:
        raise FeatureValidationError("Features must all be numeric") from exc

    if row.shape != (FEATURE_COUNT,):
        raise FeatureValidationError(f"Unexpected feature shape: {row.shape}")
    if not np.isfinite(row).all():
        invalid = np.flatnonzero(~np.isfinite(row)).tolist()
        names = [FEATURE_NAMES[index] for index in invalid]
        raise FeatureValidationError(f"Non-finite feature values: {names}")
    return row


def split_flow_record(record: Sequence[object]) -> tuple[np.ndarray, dict[str, object]]:
    """Validate a live Flow.terminated() record and split features from metadata."""
    if len(record) != FLOW_RECORD_COUNT:
        raise FeatureValidationError(
            f"Expected {FLOW_RECORD_COUNT} flow values, received {len(record)}"
        )
    features = validate_feature_vector(record[:FEATURE_COUNT])
    metadata = dict(zip(METADATA_NAMES, record[FEATURE_COUNT:], strict=True))
    return features, metadata