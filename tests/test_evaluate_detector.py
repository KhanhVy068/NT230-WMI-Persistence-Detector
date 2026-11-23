"""Kiểm thử metric evaluation tách khỏi logic Detector."""

import copy
import unittest

from tools.evaluate_detector import _metrics, evaluate


class TestEvaluationMetrics(unittest.TestCase):
    def test_metrics_and_zero_denominators_are_explicit(self):
        metrics = _metrics([
            {"expected": True, "predicted": True},
            {"expected": False, "predicted": True},
            {"expected": True, "predicted": False},
            {"expected": False, "predicted": False},
        ])
        self.assertEqual(
            {key: metrics[key] for key in ("tp", "fp", "tn", "fn")},
            {"tp": 1, "fp": 1, "tn": 1, "fn": 1},
        )
        self.assertEqual(metrics["precision"], 0.5)
        self.assertEqual(metrics["recall"], 0.5)
        self.assertEqual(metrics["f1"], 0.5)
        self.assertEqual(metrics["fpr"], 0.5)

        no_positive_predictions = _metrics([{"expected": False, "predicted": False}])
        self.assertIsNone(no_positive_predictions["precision"])
        self.assertIsNone(no_positive_predictions["recall"])
        self.assertIsNone(no_positive_predictions["f1"])
        self.assertEqual(no_positive_predictions["fpr"], 0.0)

    def test_evaluate_rejects_invalid_label_before_reading_sample(self):
        labels = {
            "S-INVALID": {
                "split": "evaluation",
                "label": "suspicious",
                "file": "not-read.json",
                "expected_rule_ids": ["R99"],
            }
        }
        with self.assertRaises(ValueError):
            evaluate(copy.deepcopy(labels), dataset_root=None, split="evaluation", baseline="BASE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
