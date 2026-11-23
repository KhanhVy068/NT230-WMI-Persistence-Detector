"""Tạo Alert xác định được từ rule match của TV3."""

import hashlib
import json
from typing import Any, Dict


def _alert_identity(subscription: Dict[str, Any], rule_id: str) -> str:
    """Sinh ID ổn định, phân biệt Subscription cùng ID ở host/scope khác nhau."""
    context = {
        "computer": subscription.get("computer"),
        "namespace": subscription.get("namespace"),
        "rule_id": rule_id,
        "subscription_id": subscription.get("subscription_id"),
    }
    serialized = json.dumps(
        context, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False,
    )
    return "ALR-" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def generate_alert(
    subscription: Dict[str, Any], rule_result: Dict[str, Any], data_status: str,
) -> Dict[str, Any]:
    """Tạo một Alert cho một rule đã có trạng thái matched."""
    if rule_result.get("status") != "matched":
        raise ValueError("Chỉ có thể tạo Alert cho rule đã matched")
    rule_id = rule_result["rule_id"]
    return {
        "alert_id": _alert_identity(subscription, rule_id),
        "rule_id": rule_id,
        "subscription_id": subscription.get("subscription_id"),
        "computer": subscription.get("computer"),
        "namespace": subscription.get("namespace"),
        "severity": "medium",
        "reason": rule_result["reason"],
        "evidence": rule_result["evidence"],
        "data_status": data_status,
    }
