"""chuẩn hóa JSON từ wmi_collector.py và eventlog_collector.py."""

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile


def canonical_json(value) -> str:
    """Tạo JSON nhất quán để sinh định danh và kiểm tra tính hợp lệ của số."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)


def text_value(value, field: str, required: bool = False):
    """Kiểm tra văn bản và giữ nguyên khoảng trắng, chữ hoa/thường trong bằng chứng."""
    if value is None and not required:
        return None
    if not isinstance(value, str) or (required and not value.strip()):
        raise ValueError(f"{field} phải là {'văn bản có nội dung' if required else 'văn bản hoặc null'}")
    return value


def integer_value(value, field: str, required: bool = False):
    """Nhận số nguyên, chuỗi thập phân hoặc hex có tiền tố 0x; giữ giá trị thiếu là null."""
    if value is None and not required:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} phải là số nguyên; giá trị bool không hợp lệ")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and re.fullmatch(r"(?:[0-9]+|0[xX][0-9a-fA-F]+)", value):
        result = int(value, 16 if value.lower().startswith("0x") else 10)
    else:
        raise ValueError(f"{field} phải là số nguyên không âm")
    if result < 0:
        raise ValueError(f"{field} phải lớn hơn hoặc bằng 0")
    return result


def normalize_namespace(value):
    """Chuẩn hóa dấu phân cách và chữ hoa/thường của namespace."""
    value = text_value(value, "namespace")
    if value is None:
        return None
    result = value.strip().replace("/", "\\").strip("\\").lower()
    if not result:
        raise ValueError("namespace phải có giá trị")
    return result


def normalize_timestamp(value: str) -> str:
    """Đổi thời điểm có múi giờ sang UTC, giữ tối đa 9 chữ số phần lẻ của giây."""
    value = text_value(value, "time_created", required=True)
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})",
        value,
    )
    if match is None:
        raise ValueError("time_created phải theo ISO 8601, có Z hoặc độ lệch múi giờ UTC")
    seconds, fraction, offset = match.groups()
    moment = datetime.fromisoformat(seconds + offset.replace("Z", "+00:00"))
    utc = moment.astimezone(timezone.utc)
    return utc.isoformat(timespec="seconds")[:-6] + (fraction or "") + "Z"


def normalize_component(component, kind: str):
    """Ánh xạ các trường WMI đã biết; giữ thành phần gốc trong trường raw."""
    if component is None:
        return None
    if not isinstance(component, dict):
        raise ValueError(f"{kind} phải là đối tượng hoặc null")
    mappings = {
        "filter": {
            "name": "Name", "query": "Query", "query_language": "QueryLanguage",
            "event_namespace": "EventNamespace", "path": "path", "identity": "identity",
        },
        "consumer": {
            "name": "Name", "type": "type", "command_line": "CommandLineTemplate",
            "executable_path": "ExecutablePath", "script_text": "ScriptText",
            "script_file_name": "ScriptFileName", "scripting_engine": "ScriptingEngine",
            "path": "path", "identity": "identity",
        },
    }
    result = {}
    for target, original in mappings[kind].items():
        value = component.get(target, component.get(original))
        result[target] = text_value(value, f"{kind}.{target}")
    if kind == "filter":
        result["event_namespace"] = normalize_namespace(result["event_namespace"])
    return result


def normalize_subscription(record: dict, namespace=None, computer=None) -> dict:
    """Chuẩn hóa một bản ghi theo Binding, giữ ID và thông tin đối tượng bị thiếu."""
    if not isinstance(record, dict):
        raise ValueError("Subscription phải là đối tượng")
    scope = normalize_namespace(record.get("namespace", namespace))
    if scope is None:
        raise ValueError("Subscription thiếu namespace")
    host = text_value(record.get("computer", computer), "computer")
    event_filter = normalize_component(record.get("filter"), "filter")
    consumer = normalize_component(record.get("consumer"), "consumer")
    binding = record.get("binding")
    if not isinstance(binding, dict):
        raise ValueError("binding phải là đối tượng")
    binding_fields = (
        "filter", "consumer", "filter_path", "consumer_path",
        "path", "identity", "filter_identity", "consumer_identity",
    )
    normalized_binding = {
        field: text_value(binding.get(field), f"binding.{field}")
        for field in binding_fields
    }
    missing = [name for name, value in (("filter", event_filter), ("consumer", consumer))
               if value is None]
    subscription_id = text_value(record.get("subscription_id"), "subscription_id")
    id_origin = "input"
    if not subscription_id:
        # Khi thiếu ID, tạo ID từ nội dung. Nội dung thay đổi có thể làm ID thay đổi.
        identity_data = {"computer": host, "namespace": scope, "record": record}
        subscription_id = hashlib.sha256(canonical_json(identity_data).encode("utf-8")).hexdigest()
        id_origin = "generated_from_content"
    return {
        "subscription_id": subscription_id, "id_origin": id_origin,
        "computer": host, "namespace": scope,
        "filter": event_filter, "consumer": consumer, "binding": normalized_binding,
        "resolution_status": "incomplete" if missing else "complete",
        "missing_objects": missing, "raw": copy.deepcopy(record),
    }


def normalize_event(record: dict) -> dict:
    """Giữ bằng chứng gốc và gom các trường EventData theo tên thành danh sách."""
    if not isinstance(record, dict):
        raise ValueError("Sự kiện phải là đối tượng")
    fields = record.get("event_data", [])
    if not isinstance(fields, list):
        raise ValueError("event_data phải là danh sách")
    data = {}
    unnamed_data = []
    for field in fields:
        if not isinstance(field, dict) or "value" not in field:
            raise ValueError("Mỗi phần tử event_data phải có trường value")
        name = text_value(field.get("name"), "event_data.name")
        value = text_value(field["value"], "event_data.value")
        if name is None or name == "":
            unnamed_data.append(value)
        else:
            data.setdefault(name, []).append(value)
    event_uid = text_value(record.get("event_uid"), "event_uid")
    id_origin = "input"
    if not event_uid:
        event_uid = hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()
        id_origin = "generated_from_content"
    execution = record.get("execution", {})
    if not isinstance(execution, dict):
        raise ValueError("execution phải là đối tượng")
    return {
        "event_uid": event_uid, "id_origin": id_origin,
        "source": text_value(record.get("source"), "source"),
        "channel": text_value(record.get("channel"), "channel"),
        "provider": text_value(record.get("provider"), "provider"),
        "computer": text_value(record.get("computer"), "computer"),
        "event_id": integer_value(record.get("event_id"), "event_id", required=True),
        "record_id": integer_value(record.get("record_id"), "record_id"),
        "level": integer_value(record.get("level"), "level"),
        "version": integer_value(record.get("version"), "version"),
        "time_created": normalize_timestamp(record.get("time_created")),
        "execution": copy.deepcopy(execution),
        "system_user_sid": text_value(record.get("system_user_sid"), "system_user_sid"),
        "data": data, "unnamed_data": unnamed_data,
        "user_data_xml": text_value(record.get("user_data_xml"), "user_data_xml"),
        "raw_xml": text_value(record.get("raw_xml"), "raw_xml"),
        "raw": copy.deepcopy(record),
    }


def split_input(payload, records_key: str):
    """Nhận đầu ra của hai Collector và dữ liệu mẫu dạng bản ghi hoặc danh sách."""
    if isinstance(payload, list):
        return payload, {}
    if not isinstance(payload, dict):
        raise ValueError(f"Đầu vào {records_key} phải là đối tượng hoặc danh sách")
    if records_key in payload:
        if not isinstance(payload[records_key], list):
            raise ValueError(f"{records_key} phải là danh sách")
        return payload[records_key], {
            key: copy.deepcopy(value) for key, value in payload.items() if key != records_key
        }
    marker = "binding" if records_key == "subscriptions" else "event_id"
    if marker in payload:
        return [payload], {}
    raise ValueError(f"Đầu vào thiếu {records_key} và có cấu trúc bản ghi mẫu không hợp lệ")


def normalize_data(wmi_data=None, eventlog_data=None) -> dict:
    """Chuẩn hóa từng nguồn đầu vào, giữ bản ghi lỗi và trạng thái nguồn."""
    if wmi_data is None and eventlog_data is None:
        raise ValueError("Cần cung cấp dữ liệu WMI, Event Log hoặc cả hai")
    # Kiểm tra dữ liệu truyền trực tiếp vào hàm cũng tương thích với JSON.
    canonical_json([wmi_data, eventlog_data])
    result = {
        "format_version": "1.0", "normalization_status": "ok",
        "normalized_at": datetime.now(timezone.utc).isoformat(),
        "subscriptions": [], "events": [], "collection_metadata": {},
        "issues": [], "rejected_records": [],
    }
    for source, payload, key in (
        ("wmi", wmi_data, "subscriptions"), ("eventlog", eventlog_data, "events")
    ):
        if payload is None:
            continue
        records, metadata = split_input(payload, key)
        result["collection_metadata"][source] = metadata
        if metadata.get("collection_status") in {"partial", "failed"}:
            result["issues"].append({
                "source": source, "code": "upstream_collection_issue",
                "message": f"Trạng thái Collector là {metadata['collection_status']}",
            })
        source_reports = metadata.get("sources", [])
        if not isinstance(source_reports, list):
            raise ValueError("Trường sources của Collector phải là danh sách")
        for report in source_reports:
            if not isinstance(report, dict):
                raise ValueError("Mỗi phần tử sources của Collector phải là đối tượng")
            if (report.get("status") != "ok" or report.get("truncated") or
                    report.get("channel_enabled") is False or report.get("parse_errors")):
                result["issues"].append({
                    "source": source, "code": "source_collection_issue",
                    "message": f"Kiểm tra collection_metadata.{source}.sources",
                    "channel": report.get("channel"), "status": report.get("status"),
                })
        for index, record in enumerate(records):
            try:
                if source == "wmi":
                    normalized = normalize_subscription(
                        record, metadata.get("namespace"), metadata.get("computer")
                    )
                else:
                    normalized = normalize_event(record)
                result[key].append(normalized)
                if source == "wmi":
                    for component_name, fields in (("filter", ("name", "query")),
                                                   ("consumer", ("name", "type"))):
                        component = normalized[component_name]
                        if component is not None:
                            absent = [field for field in fields if component[field] is None]
                            if absent:
                                result["issues"].append({
                                    "source": source, "index": index, "code": "missing_fields",
                                    "message": f"{component_name} thiếu các trường: {', '.join(absent)}",
                                })
                if normalized.get("resolution_status") == "incomplete":
                    result["issues"].append({
                        "source": source, "index": index, "code": "incomplete_subscription",
                        "message": "Đối tượng bị thiếu: " + ", ".join(normalized["missing_objects"]),
                    })
            except (ValueError, TypeError) as exc:
                issue = {"source": source, "index": index,
                         "code": "invalid_record", "message": str(exc)}
                result["issues"].append(issue)
                result["rejected_records"].append({**issue, "raw": copy.deepcopy(record)})
    # So sánh thời gian UTC, bổ sung số 0 cho phần lẻ đến độ chính xác nano giây.
    def event_order(event):
        seconds, _, fraction = event["time_created"][:-1].partition(".")
        return seconds, fraction.ljust(9, "0"), event["event_uid"]

    result["events"].sort(key=event_order)
    if result["issues"]:
        result["normalization_status"] = "partial"
    result["counts"] = {
        "subscriptions": len(result["subscriptions"]), "events": len(result["events"]),
        "rejected_records": len(result["rejected_records"]), "issues": len(result["issues"]),
    }
    return result


def load_json(path: Path):
    """Đọc JSON UTF-8 có thể kèm BOM, kiểm tra khóa trùng và số không hữu hạn."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Khóa JSON bị trùng: {key}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f"Giá trị số JSON không hợp lệ: {value}")

    with path.open(encoding="utf-8-sig") as source:
        return json.load(source, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    options = parser.add_argument_group("Tùy chọn")
    options.add_argument("-h", "--help", action="help", help="Hiển thị hướng dẫn và thoát")
    options.add_argument("--wmi", type=Path, help="File JSON kết quả của wmi_collector.py")
    options.add_argument("--eventlogs", type=Path, help="File JSON kết quả của eventlog_collector.py")
    options.add_argument("--output", type=Path, default=Path("output/normalized.json"), help="Đường dẫn JSON đã chuẩn hóa")
    args = parser.parse_args()
    temporary_path = None
    try:
        if args.wmi is None and args.eventlogs is None:
            raise ValueError("Cần truyền --wmi, --eventlogs hoặc cả hai")
        for input_path in (args.wmi, args.eventlogs):
            if input_path is not None and input_path.resolve() == args.output.resolve():
                raise ValueError("Đường dẫn đầu ra phải khác đường dẫn đầu vào")
        wmi_data = load_json(args.wmi) if args.wmi is not None else None
        eventlog_data = load_json(args.eventlogs) if args.eventlogs is not None else None
        if args.wmi is not None and wmi_data is None:
            raise ValueError("Đầu vào WMI phải có dữ liệu, không được là null")
        if args.eventlogs is not None and eventlog_data is None:
            raise ValueError("Đầu vào Event Log phải có dữ liệu, không được là null")
        result = normalize_data(wmi_data, eventlog_data)
        text = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=args.output.parent,
            prefix=f".{args.output.name}.", suffix=".tmp", delete=False,
        ) as output:
            temporary_path = Path(output.name)
            output.write(text)
        os.replace(temporary_path, args.output)
        print(f"Trạng thái chuẩn hóa {result['normalization_status']}: "
              f"{result['counts']} -> {args.output}", file=sys.stderr)
        return 0 if result["normalization_status"] == "ok" else 2
    except (OSError, ValueError, TypeError) as exc:
        print(f"Chuẩn hóa thất bại: {exc}", file=sys.stderr)
        return 1
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
