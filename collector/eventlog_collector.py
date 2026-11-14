"""thu thập Windows Event Log."""

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


SOURCES = {
    "wmi": {
        "channel": "Microsoft-Windows-WMI-Activity/Operational",
        "event_ids": [],
    },
    "sysmon": {
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "event_ids": [19, 20, 21],
    },
    "security": {"channel": "Security", "event_ids": [4688]},
}
EVENT_NAMESPACE = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
    $request = ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd())
    $log = Get-WinEvent -ListLog $request.channel -ErrorAction Stop
    $filter = @{
        LogName = [string]$request.channel
        StartTime = [DateTimeOffset]::Parse($request.start_time).UtcDateTime
        EndTime = [DateTimeOffset]::Parse($request.end_time).UtcDateTime
    }
    if (@($request.event_ids).Count -gt 0) {
        $filter['Id'] = [int[]]$request.event_ids
    }
    $limit = [int]$request.max_events
    $events = @()
    try {
        # Đọc thêm một bản ghi để xác định có vượt giới hạn số sự kiện hay không.
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents ($limit + 1) -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            throw
        }
    }
    $truncated = $events.Count -gt $limit
    $xmlRows = @(
        foreach ($event in ($events | Select-Object -First $limit)) {
            try { $event.ToXml() } finally { $event.Dispose() }
        }
    )
    if ($truncated) { $events[$limit].Dispose() }
    $reply = @{
        status = 'ok'
        channel_enabled = [bool]$log.IsEnabled
        truncated = $truncated
        events = $xmlRows
    }
} catch {
    $status = 'error'
    $errorId = [string]$_.FullyQualifiedErrorId
    if ($errorId -like 'NoMatchingLogsFound*') { $status = 'missing' }
    if ($_.CategoryInfo.Category -eq 'PermissionDenied' -or
        $_.Exception -is [System.UnauthorizedAccessException] -or
        $_.Exception.HResult -eq -2147024891) { $status = 'access_denied' }
    $reply = @{
        status = $status
        channel_enabled = $null
        truncated = $false
        events = @()
        error = $_.Exception.Message
        error_id = $errorId
    }
}
ConvertTo-Json -InputObject $reply -Depth 8 -Compress
"""


def query_eventlog(
    channel: str, event_ids: list[int], start_time: datetime,
    end_time: datetime, max_events: int = 1000, timeout: int = 60,
) -> dict:
    """Đọc một kênh log cục bộ và báo rõ lỗi khi truy vấn."""
    if sys.platform != "win32":
        raise RuntimeError("Hãy chạy eventlog_collector.py trên máy ảo Windows.")
    if max_events < 1 or max_events > 100000 or timeout < 1:
        raise ValueError("max_events phải từ 1 đến 100000 và timeout phải lớn hơn 0")
    if start_time.utcoffset() is None or end_time.utcoffset() is None:
        raise ValueError("Thời điểm bắt đầu và kết thúc phải có múi giờ")
    if start_time >= end_time:
        raise ValueError("Thời điểm bắt đầu phải trước thời điểm kết thúc")
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    encoded_script = base64.b64encode(POWERSHELL_SCRIPT.encode("utf-16-le")).decode("ascii")
    request = {
        "channel": channel, "event_ids": event_ids,
        "start_time": start_time.astimezone(timezone.utc).isoformat(),
        "end_time": end_time.astimezone(timezone.utc).isoformat(),
        "max_events": max_events,
    }
    try:
        result = subprocess.run(
            [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive",
             "-EncodedCommand", encoded_script],
            input=json.dumps(request), capture_output=True, text=True,
            encoding="utf-8", timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "events": [], "error": f"Đã vượt thời gian chờ {timeout} giây"}
    except (OSError, UnicodeError) as exc:
        return {"status": "error", "events": [], "error": str(exc)}
    if result.returncode:
        return {"status": "error", "events": [], "error": result.stderr.strip()}
    try:
        reply = json.loads(result.stdout.lstrip("\ufeff"))
        if not isinstance(reply, dict) or reply.get("status") not in {
            "ok", "error", "missing", "access_denied"
        }:
            raise ValueError("Trạng thái phản hồi không hợp lệ")
        if not isinstance(reply.get("events"), list):
            raise ValueError("Dữ liệu trả về phải là mảng các chuỗi XML sự kiện")
        if not all(isinstance(item, str) for item in reply["events"]):
            raise ValueError("Kiểu dữ liệu sự kiện không hợp lệ")
        return reply
    except (ValueError, TypeError) as exc:
        return {"status": "error", "events": [], "error": f"Phản hồi PowerShell không hợp lệ: {exc}"}


def parse_event_xml(xml_text: str, source: str) -> dict:
    """Trích xuất trường XML; giữ trường trùng tên, trường thiếu tên và XML gốc."""
    root = ET.fromstring(xml_text)
    system = root.find("e:System", EVENT_NAMESPACE)
    if system is None:
        raise ValueError("XML sự kiện thiếu phần tử System")
    event_id = system.findtext("e:EventID", namespaces=EVENT_NAMESPACE)
    timestamp = system.find("e:TimeCreated", EVENT_NAMESPACE)
    if event_id is None or timestamp is None or not timestamp.get("SystemTime"):
        raise ValueError("XML sự kiện thiếu EventID hoặc SystemTime")
    time_created = timestamp.get("SystemTime")
    parsed_time = datetime.fromisoformat(time_created.replace("Z", "+00:00"))
    if parsed_time.utcoffset() is None:
        raise ValueError("Thời điểm sự kiện thiếu múi giờ")
    provider = system.find("e:Provider", EVENT_NAMESPACE)
    execution = system.find("e:Execution", EVENT_NAMESPACE)
    security = system.find("e:Security", EVENT_NAMESPACE)
    user_data = root.find("e:UserData", EVENT_NAMESPACE)
    event_data = [
        {"name": field.get("Name"), "value": "".join(field.itertext())}
        for field in root.findall("e:EventData/e:Data", EVENT_NAMESPACE)
    ]
    record_id = system.findtext("e:EventRecordID", namespaces=EVENT_NAMESPACE)
    # Nội dung XML giống nhau tạo cùng ID để nhận diện bản ghi trùng.
    # ID được tính từ toàn bộ bản ghi để xét cả nội dung và thời điểm sự kiện.
    return {
        "event_uid": hashlib.sha256(xml_text.encode("utf-8")).hexdigest(),
        "source": source,
        "channel": system.findtext("e:Channel", namespaces=EVENT_NAMESPACE),
        "provider": provider.get("Name") if provider is not None else None,
        "event_id": int(event_id),
        "record_id": int(record_id) if record_id else None,
        "time_created": time_created,
        "computer": system.findtext("e:Computer", namespaces=EVENT_NAMESPACE),
        "level": system.findtext("e:Level", namespaces=EVENT_NAMESPACE),
        "version": system.findtext("e:Version", namespaces=EVENT_NAMESPACE),
        "execution": dict(execution.attrib) if execution is not None else {},
        "system_user_sid": security.get("UserID") if security is not None else None,
        "event_data": event_data,
        "user_data_xml": ET.tostring(user_data, encoding="unicode") if user_data is not None else None,
        "raw_xml": xml_text,
    }


def collect_eventlogs(
    sources=None, hours: float = 24, max_events: int = 1000,
    timeout: int = 60, end_time=None,
) -> dict:
    """Thu thập các nguồn trong cùng khoảng UTC và giữ thông tin chẩn đoán."""
    selected = list(dict.fromkeys(SOURCES if sources is None else sources))
    if not selected or any(name not in SOURCES for name in selected):
        raise ValueError("Chọn nguồn trong các giá trị: wmi, sysmon, security")
    if not math.isfinite(hours) or hours <= 0:
        raise ValueError("hours phải là số hữu hạn lớn hơn 0")
    if not 1 <= max_events <= 100000 or timeout <= 0:
        raise ValueError("max_events phải từ 1 đến 100000 và timeout phải lớn hơn 0")
    started_at = datetime.now(timezone.utc)
    end_time = end_time or started_at
    if end_time.utcoffset() is None:
        raise ValueError("end_time phải có múi giờ")
    end_time = end_time.astimezone(timezone.utc)
    try:
        start_time = end_time - timedelta(hours=hours)
    except OverflowError as exc:
        raise ValueError("Khoảng thời gian yêu cầu quá lớn") from exc
    reports = []
    events_by_uid = {}
    for name in selected:
        config = SOURCES[name]
        response = query_eventlog(
            config["channel"], config["event_ids"], start_time,
            end_time, max_events, timeout,
        )
        report = {
            "source": name, "channel": config["channel"],
            "event_ids": list(config["event_ids"]),
            "status": response["status"],
            "channel_enabled": response.get("channel_enabled"),
            "truncated": response.get("truncated", False),
            "returned_count": len(response["events"]),
            "parsed_count": 0, "parse_errors": [],
            "error": response.get("error"), "error_id": response.get("error_id"),
        }
        for index, xml_text in enumerate(response["events"]):
            try:
                event = parse_event_xml(xml_text, name)
                events_by_uid[event["event_uid"]] = event
                report["parsed_count"] += 1
            except (ET.ParseError, ValueError) as exc:
                report["parse_errors"].append({
                    "index": index, "error": str(exc), "raw_xml": xml_text,
                })
        if report["status"] == "ok" and (
            report["truncated"] or report["parse_errors"] or
            report["channel_enabled"] is False
        ):
            report["status"] = "partial"
        reports.append(report)
    events = sorted(
        events_by_uid.values(),
        key=lambda event: (
            datetime.fromisoformat(event["time_created"].replace("Z", "+00:00")),
            event["event_uid"],
        ),
    )
    statuses = {report["status"] for report in reports}
    status = "ok"
    if statuses != {"ok"}:
        status = "partial" if statuses & {"ok", "partial"} else "failed"
    return {
        "format_version": "1.0", "collection_status": status,
        "collection_started_at": started_at.isoformat(),
        "collection_finished_at": datetime.now(timezone.utc).isoformat(),
        "window_start": start_time.isoformat(), "window_end": end_time.isoformat(),
        "max_events_per_source": max_events, "selection_order": "newest_first",
        "output_order": "oldest_first", "sources": reports,
        "event_count": len(events), "events": events,
    }


def main() -> int:
    """Ghi kết quả và lỗi của từng nguồn thành JSON UTF-8."""
    parser = argparse.ArgumentParser(
        description=__doc__, add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    options = parser.add_argument_group("Tùy chọn")
    options.add_argument("-h", "--help", action="help", help="Hiển thị hướng dẫn và thoát")
    options.add_argument("--source", action="append", choices=list(SOURCES), dest="sources", help="Nguồn log; có thể truyền nhiều lần")
    options.add_argument("--hours", type=float, default=24, help="Số giờ gần nhất cần thu thập")
    options.add_argument("--max-events", type=int, default=1000, help="Giới hạn số sự kiện mỗi nguồn (1..100000)")
    options.add_argument("--timeout", type=int, default=60, help="Thời gian chờ mỗi nguồn, tính bằng giây")
    options.add_argument("--output", type=Path, help="Đường dẫn file JSON kết quả")
    args = parser.parse_args()
    temporary_path = None
    try:
        bundle = collect_eventlogs(args.sources, args.hours, args.max_events, args.timeout)
        text = json.dumps(bundle, ensure_ascii=False, indent=2) + "\n"
        if args.output is None:
            sys.stdout.reconfigure(encoding="utf-8")
            print(text, end="")
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=args.output.parent,
                prefix=f".{args.output.name}.", suffix=".tmp", delete=False,
            ) as output:
                temporary_path = Path(output.name)
                output.write(text)
            os.replace(temporary_path, args.output)
        print(f"Trạng thái thu thập {bundle['collection_status']}: {bundle['event_count']} sự kiện", file=sys.stderr)
        for source in bundle["sources"]:
            print(f"  {source['source']}: {source['status']}, "
                  f"đã phân tích={source['parsed_count']}, vượt giới hạn={source['truncated']}", file=sys.stderr)
            if source["error"]:
                print(f"    {source['error']}", file=sys.stderr)
        return 0 if bundle["collection_status"] == "ok" else 2
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"Thu thập thất bại: {exc}", file=sys.stderr)
        return 1
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
