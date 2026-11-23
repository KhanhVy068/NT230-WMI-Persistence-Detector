"""Engine TV3 Mốc 4: nhận bundle Normalizer và tạo report R01-R04."""

import argparse
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Dict, List

from collector.normalizer import load_json

from .alert_generator import generate_alert
from .rules import ENABLED_RULE_IDS, NOT_IMPLEMENTED_RULE_IDS, evaluate_subscription


REPORT_FORMAT_VERSION = "1.0"

RULE_SCOPE = {
    "R01": {
        "supported_execution_form": "PowerShell được gọi trực tiếp ở consumer.command_line với tham số đầy đủ -EncodedCommand trước -Command, -File hoặc --%.",
        "not_analyzed_execution_forms": [
            "PowerShell được gọi gián tiếp qua cmd.exe /c, shell wrapper hoặc process trung gian.",
            "PowerShell nằm trong consumer.script_text hoặc script_file_name.",
            "Tham số hoặc executable được dựng động, obfuscate, hay không thể tách token an toàn.",
        ],
        "safety": "Detector chỉ phân tích văn bản; không chạy hoặc giải mã command/script.",
    },
    "R02": {
        "supported_execution_form": "PowerShell được gọi trực tiếp ở consumer.command_line với tham số đầy đủ -WindowStyle và giá trị Hidden trước -Command, -File hoặc --%.",
        "not_analyzed_execution_forms": [
            "PowerShell được gọi gián tiếp qua cmd.exe /c, shell wrapper hoặc process trung gian.",
            "PowerShell nằm trong consumer.script_text hoặc script_file_name.",
            "Tham số hoặc executable được dựng động, obfuscate, hay không thể tách token an toàn.",
        ],
        "safety": "Detector chỉ phân tích văn bản; không chạy command/script.",
    },
    "R03": {
        "supported_execution_sources": [
            "consumer.executable_path của CommandLineEventConsumer.",
            "Executable trực tiếp tĩnh trong consumer.command_line.",
            "Script path sau PowerShell -File.",
            "File chương trình/batch tĩnh ngay sau cmd.exe /c.",
            "Script path tĩnh truyền cho cscript.exe hoặc wscript.exe.",
            "consumer.script_file_name của ActiveScriptEventConsumer.",
        ],
        "recognized_path_groups": {
            "Temp": "Thành phần thư mục Temp chính xác, hoặc %TEMP% / %TMP%.",
            "AppData": "Thành phần AppData chính xác, hoặc %APPDATA% / %LOCALAPPDATA%.",
            "Downloads": "Thành phần Downloads chính xác, hoặc %USERPROFILE%\\Downloads.",
            "Users\\Public": "Cặp thành phần Users\\Public chính xác, hoặc %PUBLIC%.",
        },
        "not_analyzed_execution_forms": [
            "PowerShell -Command, consumer.script_text, command wrapper và chuỗi dựng động.",
            "Path tương đối/bare, biến môi trường chưa biết, hoặc command line không tách token an toàn.",
            "Cú pháp cmd.exe /c hoặc cscript/wscript phức tạp không có script/file tĩnh xác định được.",
        ],
        "conclusion_limit": "Match chỉ nói đích thực thi được cấu hình nằm trong nhóm path lab; không xác minh file tồn tại, quyền ghi hoặc việc thực thi thực tế.",
        "safety": "Detector chỉ phân tích văn bản theo ngữ nghĩa Windows và không dùng filesystem/môi trường của máy chạy Detector.",
    },
    "R04": {
        "supported_vbscript_forms": [
            "Gán tĩnh Set <biến> = CreateObject(\"WScript.Shell\").",
            "Lời gọi <cùng biến>.Run hoặc <cùng biến>.Exec với đối số lệnh đầu tiên là string literal tĩnh.",
            "Shell đích tĩnh: cmd/cmd.exe, powershell/powershell.exe hoặc pwsh/pwsh.exe.",
        ],
        "not_analyzed_execution_forms": [
            "JScript hoặc scripting_engine không phải VBScript.",
            "CreateObject/Run/Exec dựng động, gọi trực tiếp không qua biến, nhiều câu lệnh trên một dòng, line-continuation hoặc biểu thức ghép/biến.",
            "Nội dung chỉ có consumer.script_file_name; Detector không mở file đó trên máy chạy để suy ra script.",
        ],
        "safety": "Detector chỉ đọc script_text như dữ liệu; không chạy script hay command trong script.",
    },
}


def _validate_normalized_bundle(normalized_bundle: Any) -> Dict[str, Any]:
    """Xác nhận hợp đồng đầu vào là bundle do normalize_data() trả về."""
    if not isinstance(normalized_bundle, dict):
        raise ValueError("Đầu vào Detector phải là một bundle Normalizer dạng đối tượng JSON")
    required = ("format_version", "normalization_status", "subscriptions", "issues", "counts")
    missing = [field for field in required if field not in normalized_bundle]
    if missing:
        raise ValueError("Bundle Normalizer thiếu trường: " + ", ".join(missing))
    if not isinstance(normalized_bundle["format_version"], str):
        raise ValueError("format_version của bundle Normalizer phải là chuỗi")
    if normalized_bundle["normalization_status"] not in {"ok", "partial"}:
        raise ValueError("normalization_status phải là 'ok' hoặc 'partial'")
    if not isinstance(normalized_bundle["subscriptions"], list):
        raise ValueError("subscriptions của bundle Normalizer phải là danh sách")
    if not isinstance(normalized_bundle["issues"], list):
        raise ValueError("issues của bundle Normalizer phải là danh sách")
    if not isinstance(normalized_bundle["counts"], dict):
        raise ValueError("counts của bundle Normalizer phải là đối tượng")
    for index, subscription in enumerate(normalized_bundle["subscriptions"]):
        if not isinstance(subscription, dict):
            raise ValueError(f"subscriptions[{index}] phải là đối tượng")
    return normalized_bundle


def _data_status(subscription: Dict[str, Any], rule_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Cho biết thiếu dữ liệu có ảnh hưởng đến phân tích từng Subscription."""
    unavailable = []
    if subscription.get("resolution_status") != "complete":
        unavailable.extend(subscription.get("missing_objects", []))
    consumer = subscription.get("consumer")
    if consumer is None or not isinstance(consumer, dict):
        if "consumer" not in unavailable:
            unavailable.append("consumer")
    for rule_id in ENABLED_RULE_IDS:
        for field in rule_results[rule_id].get("unavailable_fields", []):
            if field not in unavailable:
                unavailable.append(field)
    return {"data_status": "incomplete" if unavailable else "complete", "unavailable_fields": unavailable}


def _unanalysed_forms(
    subscription: Dict[str, Any], rule_results: Dict[str, Dict[str, Any]],
) -> List[Dict[str, str]]:
    """Nêu riêng dữ liệu thực tế bị để ngoài phạm vi cú pháp các rule."""
    consumer = subscription.get("consumer")
    if not isinstance(consumer, dict):
        return []
    forms = []
    script_text = consumer.get("script_text")
    if isinstance(script_text, str) and script_text.strip():
        forms.append({
            "field": "consumer.script_text",
            "rule_id": "R03",
            "reason": "R03 không suy ra đích thực thi từ consumer.script_text hoặc script động.",
        })
    for form in rule_results["R03"].get("unanalysed_forms", []):
        forms.append({**form, "rule_id": "R03"})
    for form in rule_results["R04"].get("unanalysed_forms", []):
        forms.append({**form, "rule_id": "R04"})
    return forms


def analyze_subscription(subscription: Dict[str, Any]) -> Dict[str, Any]:
    """Phân tích một Subscription chuẩn hóa mà không làm thay đổi đầu vào."""
    if not isinstance(subscription, dict):
        raise ValueError("Subscription chuẩn hóa phải là đối tượng")
    rule_results = evaluate_subscription(subscription)
    completeness = _data_status(subscription, rule_results)
    matched_rule_ids = [
        rule_id for rule_id in ENABLED_RULE_IDS
        if rule_results[rule_id]["status"] == "matched"
    ]
    return {
        "subscription_id": subscription.get("subscription_id"),
        "computer": subscription.get("computer"),
        "namespace": subscription.get("namespace"),
        "resolution_status": subscription.get("resolution_status"),
        "data_status": completeness["data_status"],
        "unavailable_fields": completeness["unavailable_fields"],
        "matched_rule_ids": matched_rule_ids,
        "rule_results": rule_results,
        "unanalysed_forms": _unanalysed_forms(subscription, rule_results),
    }


def _summary(analyses: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Tổng hợp trực tiếp từ outputs để không lệch với analyses/alerts."""
    status_names = ("matched", "not_matched", "not_applicable", "insufficient_data")
    rule_status_counts = {
        rule_id: {
            status: sum(analysis["rule_results"][rule_id]["status"] == status for analysis in analyses)
            for status in status_names
        }
        for rule_id in ENABLED_RULE_IDS
    }
    return {
        "subscriptions": len(analyses),
        "subscriptions_with_alerts": sum(bool(analysis["matched_rule_ids"]) for analysis in analyses),
        "alerts": len(alerts),
        "incomplete_subscriptions": sum(
            analysis["data_status"] == "incomplete" for analysis in analyses
        ),
        "r01_status_counts": rule_status_counts["R01"],
        "r02_status_counts": rule_status_counts["R02"],
        "r03_status_counts": rule_status_counts["R03"],
        "r04_status_counts": rule_status_counts["R04"],
    }


def analyze_normalized(normalized_bundle: Dict[str, Any]) -> Dict[str, Any]:
    """API TV4: phân tích bundle đúng định dạng normalize_data() trả về.

    Mốc 4 bật R01-R04. Mỗi rule chỉ kết luận trong phạm vi ``rule_scope``.
    """
    bundle = _validate_normalized_bundle(normalized_bundle)
    analyses = [analyze_subscription(subscription) for subscription in bundle["subscriptions"]]
    alerts = []
    for subscription, analysis in zip(bundle["subscriptions"], analyses):
        for rule_id in analysis["matched_rule_ids"]:
            alerts.append(generate_alert(
                subscription, analysis["rule_results"][rule_id], analysis["data_status"],
            ))
    detector_status = "partial" if (
        bundle["normalization_status"] == "partial" or
        any(analysis["data_status"] == "incomplete" for analysis in analyses)
    ) else "ok"
    return {
        "format_version": REPORT_FORMAT_VERSION,
        "report_type": "wmi_subscription_detection",
        "input_format_version": bundle["format_version"],
        "detector_status": detector_status,
        "enabled_rule_ids": list(ENABLED_RULE_IDS),
        "not_implemented_rule_ids": list(NOT_IMPLEMENTED_RULE_IDS),
        "rule_scope": copy.deepcopy(RULE_SCOPE),
        "upstream": {
            "normalization_status": bundle["normalization_status"],
            "issues": copy.deepcopy(bundle["issues"]),
            "counts": copy.deepcopy(bundle["counts"]),
        },
        "analyses": analyses,
        "alerts": alerts,
        "summary": _summary(analyses, alerts),
    }


def write_json_atomic(path: Path, payload: Dict[str, Any]) -> None:
    """Ghi JSON UTF-8 qua file tạm để không làm hỏng file report cũ."""
    temporary_path = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as output:
            temporary_path = Path(output.name)
            output.write(text)
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    """CLI Mốc 4 cho một bundle Normalizer đã lưu ở JSON."""
    parser = argparse.ArgumentParser(
        description=__doc__, add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    options = parser.add_argument_group("Tùy chọn")
    options.add_argument("-h", "--help", action="help", help="Hiển thị hướng dẫn và thoát")
    options.add_argument("--input", required=True, type=Path, help="JSON bundle do normalizer.py tạo")
    options.add_argument("--output", required=True, type=Path, help="Đường dẫn JSON detection report")
    args = parser.parse_args()
    try:
        if args.input.resolve() == args.output.resolve():
            raise ValueError("Đường dẫn output phải khác input để bảo vệ dữ liệu nguồn")
        normalized_bundle = load_json(args.input)
        report = analyze_normalized(normalized_bundle)
        write_json_atomic(args.output, report)
        print(
            f"Phân tích {report['summary']['subscriptions']} Subscription, "
            f"{report['summary']['alerts']} Alert: {args.output}",
            file=sys.stderr,
        )
        return 0 if report["detector_status"] == "ok" else 2
    except (OSError, ValueError, TypeError) as exc:
        print(f"Detector thất bại: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
