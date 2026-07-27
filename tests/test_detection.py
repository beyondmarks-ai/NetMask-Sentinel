import unittest

import numpy as np

from netmask.detection import DetectionEngine, RiskPolicy
from netmask.features import FEATURE_COUNT, FeatureValidationError, validate_feature_vector


class FakeClassifier:
    classes_ = np.array(["Benign", "Attack"])
    n_features_in_ = FEATURE_COUNT

    def __init__(self, probabilities=(0.9, 0.1)):
        self.probabilities = probabilities

    def predict_proba(self, matrix):
        return np.tile(np.asarray(self.probabilities, dtype=float), (len(matrix), 1))


class DetectionTests(unittest.TestCase):
    def test_attack_probability_and_risk_use_non_benign_total(self):
        result = DetectionEngine(FakeClassifier((0.15, 0.85))).detect([0] * FEATURE_COUNT)
        self.assertEqual(result.classification, "Attack")
        self.assertEqual(result.risk_level, "very_high")
        self.assertAlmostEqual(result.attack_probability, 0.85)
        self.assertTrue(result.should_alert)

    def test_benign_result_does_not_alert(self):
        result = DetectionEngine(FakeClassifier()).detect([0] * FEATURE_COUNT)
        self.assertEqual(result.classification, "Benign")
        self.assertEqual(result.risk_level, "minimal")
        self.assertFalse(result.should_alert)

    def test_feature_contract_rejects_wrong_size_and_non_finite(self):
        with self.assertRaises(FeatureValidationError):
            validate_feature_vector([0] * (FEATURE_COUNT - 1))
        values = [0] * FEATURE_COUNT
        values[4] = float("nan")
        with self.assertRaises(FeatureValidationError):
            validate_feature_vector(values)

    def test_invalid_probability_contract_is_rejected(self):
        with self.assertRaises(RuntimeError):
            DetectionEngine(FakeClassifier((0.8, 0.8)))

    def test_risk_thresholds_must_be_strict(self):
        with self.assertRaises(ValueError):
            RiskPolicy(low=0.2, medium=0.2)


if __name__ == "__main__":
    unittest.main()