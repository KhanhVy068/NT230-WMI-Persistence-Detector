"""Kiểm thử metric evaluation tách khỏi logic Detector."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import uuid

from tools.evaluate_detector import _metrics, evaluate


PROJECT_ROOT = Path(__file__).resolve().parents[1]


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

    def test_direct_cli_imports_project_modules_and_writes_result(self):
        token = uuid.uuid4().hex
        directory = PROJECT_ROOT / "tests"
        labels_path = directory / f".evaluation_{token}_labels.json"
        sample_path = directory / f".evaluation_{token}_sample.json"
        output_path = directory / f".evaluation_{token}_output.json"
        for path in (labels_path, sample_path, output_path):
            self.addCleanup(path.unlink, missing_ok=True)
        sample_path.write_text(json.dumps({
            "subscription_id": "S-CLI",
            "computer": "EVAL-VM",
            "namespace": "root\\subscription",
            "filter": {"name": "F", "query": "SELECT * FROM Win32_ProcessStartTrace"},
            "consumer": {
                "name": "C",
                "type": "CommandLineEventConsumer",
                "command_line": "powershell.exe -EncodedCommand VwByAGkAdABlAA==",
            },
            "binding": {"filter": "F", "consumer": "C"},
        }), encoding="utf-8")
        labels_path.write_text(json.dumps({
            "S-CLI": {
                "split": "evaluation",
                "label": "suspicious",
                "file": sample_path.name,
                "expected_rule_ids": ["R01"],
            }
        }), encoding="utf-8")
        environment = os.environ.copy()
        environment["PYTHONUTF8"] = "1"
        process = subprocess.run(
            [
                sys.executable, "-X", "utf8", "tools/evaluate_detector.py",
                "--labels", str(labels_path), "--dataset-root", str(directory),
                "--baseline", "TEST-BASELINE", "--output", str(output_path),
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            timeout=15,
            env=environment,
        )
        self.assertEqual(process.returncode, 0, process.stderr.decode("utf-8"))
        result = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(result["subscription_metrics"]["tp"], 1)
        self.assertEqual(result["results"][0]["predicted_rule_ids"], ["R01"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
