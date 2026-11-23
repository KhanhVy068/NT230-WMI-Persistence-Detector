"""Đánh giá Detector TV3 theo labels dataset, tách khỏi logic phát hiện.

Detector không gọi module này và không đọc labels.json. Script chỉ dùng labels
sau khi Detector đã tạo report để tổng hợp metric tái hiện được.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import os
import platform
import sys
import tempfile
from typing import Any, Dict, Iterable, List

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from collector.normalizer import load_json, normalize_data
from detector.engine import analyze_normalized
from detector.rules import ENABLED_RULE_IDS


def _ratio(numerator: int, denominator: int):
    return None if denominator == 0 else numerator / denominator


def _metric_counts(items: Iterable[Dict[str, bool]]) -> Dict[str, int]:
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for item in items:
        expected = item["expected"]
        predicted = item["predicted"]
        if expected and predicted:
            counts["tp"] += 1
        elif predicted:
            counts["fp"] += 1
        elif expected:
            counts["fn"] += 1
        else:
            counts["tn"] += 1
    return counts


def _metrics(items: Iterable[Dict[str, bool]]) -> Dict[str, Any]:
    counts = _metric_counts(items)
    precision = _ratio(counts["tp"], counts["tp"] + counts["fp"])
    recall = _ratio(counts["tp"], counts["tp"] + counts["fn"])
    # Do not derive F1 from precision/recall: either individual denominator
    # can be zero even though the F1 denominator is non-zero.
    f1 = _ratio(
        2 * counts["tp"],
        2 * counts["tp"] + counts["fp"] + counts["fn"],
    )
    return {
        **counts,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": _ratio(counts["fp"], counts["fp"] + counts["tn"]),
    }


def _validate_label(subscription_id: str, metadata: Dict[str, Any]) -> None:
    if metadata.get("label") not in {"suspicious", "benign"}:
        raise ValueError(f"{subscription_id}: label phải là suspicious hoặc benign")
    if not isinstance(metadata.get("file"), str) or not metadata["file"]:
        raise ValueError(f"{subscription_id}: thiếu file")
    expected = metadata.get("expected_rule_ids")
    if not isinstance(expected, list) or any(rule_id not in ENABLED_RULE_IDS for rule_id in expected):
        raise ValueError(f"{subscription_id}: expected_rule_ids không hợp lệ cho TV3")


def evaluate(labels: Dict[str, Any], dataset_root: Path, split: str, baseline: str) -> Dict[str, Any]:
    """Chạy Detector trên split đã chọn rồi đối chiếu labels bên ngoài Detector."""
    selected = []
    for subscription_id, metadata in sorted(labels.items()):
        if not isinstance(metadata, dict) or metadata.get("split") != split:
            continue
        _validate_label(subscription_id, metadata)
        selected.append((subscription_id, metadata))
    if not selected:
        raise ValueError(f"Không có label nào thuộc split {split!r}")

    subscriptions = []
    subscription_pairs = []
    rule_pairs = {rule_id: [] for rule_id in ENABLED_RULE_IDS}
    results = []
    for subscription_id, metadata in selected:
        raw_path = dataset_root / metadata["file"]
        raw = load_json(raw_path)
        normalized = normalize_data(wmi_data=raw)
        report = analyze_normalized(normalized)
        if len(report["analyses"]) != 1:
            raise ValueError(f"{subscription_id}: mẫu phải tạo đúng một analysis")
        analysis = report["analyses"][0]
        if analysis["subscription_id"] != subscription_id:
            raise ValueError(
                f"{subscription_id}: Subscription ID từ mẫu là {analysis['subscription_id']!r}"
            )
        predicted_rule_ids = analysis["matched_rule_ids"]
        expected_rule_ids = metadata["expected_rule_ids"]
        expected_subscription = metadata["label"] == "suspicious"
        predicted_subscription = bool(predicted_rule_ids)
        subscription_pairs.append({
            "expected": expected_subscription,
            "predicted": predicted_subscription,
        })
        for rule_id in ENABLED_RULE_IDS:
            rule_pairs[rule_id].append({
                "expected": rule_id in expected_rule_ids,
                "predicted": rule_id in predicted_rule_ids,
            })
        results.append({
            "subscription_id": subscription_id,
            "file": metadata["file"],
            "label": metadata["label"],
            "data_quality": metadata.get("data_quality"),
            "expected_rule_ids": expected_rule_ids,
            "predicted_rule_ids": predicted_rule_ids,
            "predicted_alert": predicted_subscription,
            "data_status": analysis["data_status"],
            "unavailable_fields": analysis["unavailable_fields"],
            "unanalysed_forms": analysis["unanalysed_forms"],
            "normalization_status": normalized["normalization_status"],
            "detector_status": report["detector_status"],
            "analysis": analysis,
            "alerts": report["alerts"],
        })
        subscriptions.append(subscription_id)

    all_rule_pairs = [pair for pairs in rule_pairs.values() for pair in pairs]
    incomplete = [item["subscription_id"] for item in results if item["data_status"] == "incomplete"]
    with_unanalysed = [item["subscription_id"] for item in results if item["unanalysed_forms"]]
    return {
        "evaluation_format_version": "1.0",
        "baseline": baseline,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python_version": platform.python_version(),
        "split": split,
        "enabled_rule_ids": list(ENABLED_RULE_IDS),
        "metrics_policy": {
            "subscription_positive": "Một subscription là predicted positive khi matched_rule_ids không rỗng.",
            "rule_positive": "Mỗi cặp subscription/rule được so sánh với expected_rule_ids của label.",
            "zero_denominator": "Precision, recall và FPR là null khi mẫu số riêng bằng 0. F1 dùng 2*TP/(2*TP+FP+FN) và chỉ là null khi mẫu số F1 bằng 0; không thay bằng 0 hoặc 1.",
            "incomplete_data": "Không loại mẫu incomplete khỏi metric; coverage báo riêng IDs bị incomplete.",
            "unanalysed_forms": "Không loại mẫu có unanalysed_forms; coverage báo riêng để diễn giải giới hạn.",
        },
        "coverage": {
            "subscriptions": len(results),
            "complete_subscriptions": len(results) - len(incomplete),
            "incomplete_subscription_ids": incomplete,
            "subscriptions_with_unanalysed_forms": with_unanalysed,
        },
        "subscription_metrics": _metrics(subscription_pairs),
        "rule_metrics": {
            rule_id: _metrics(rule_pairs[rule_id]) for rule_id in ENABLED_RULE_IDS
        },
        "rule_metrics_micro": _metrics(all_rule_pairs),
        "results": results,
        "subscription_ids": subscriptions,
    }


def write_json_atomic(path: Path, payload: Dict[str, Any]) -> None:
    """Ghi result JSON UTF-8 atomically để không hỏng kết quả cũ."""
    temporary_path = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as output:
            temporary_path = Path(output.name)
            json.dump(payload, output, ensure_ascii=False, indent=2, allow_nan=False)
            output.write("\n")
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", type=Path, default=Path("dataset/labels.json"))
    parser.add_argument("--dataset-root", type=Path, default=Path("dataset"))
    parser.add_argument("--split", default="evaluation")
    parser.add_argument("--baseline", required=True, help="Commit SHA hoặc baseline ID đã chốt")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.labels.resolve() == args.output.resolve():
            raise ValueError("--output phải khác --labels")
        labels = load_json(args.labels)
        if not isinstance(labels, dict):
            raise ValueError("labels.json phải là object ánh xạ subscription ID")
        result = evaluate(labels, args.dataset_root, args.split, args.baseline)
        write_json_atomic(args.output, result)
        print(
            f"Đã đánh giá {result['coverage']['subscriptions']} Subscription: {args.output}",
            file=sys.stderr,
        )
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"Evaluation thất bại: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
