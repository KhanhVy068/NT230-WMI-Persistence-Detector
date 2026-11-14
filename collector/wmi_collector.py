"""thu thập WMI Subscription trên máy cục bộ"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone


DEFAULT_NAMESPACE = r"root\subscription"

# COM API của WMI cung cấp đường dẫn đối tượng và thuộc tính tham chiếu.
# Tham số được truyền dưới dạng JSON qua đầu vào chuẩn.
POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Get-Identity([string]$Path, [string]$Namespace) {
    $parsed = New-Object -ComObject WbemScripting.SWbemObjectPath
    $parsed.Path = $Path
    $server = $parsed.Server
    if ([string]::IsNullOrEmpty($server) -or $server -eq '.') {
        $server = $env:COMPUTERNAME
    }
    $scope = $parsed.Namespace
    if ([string]::IsNullOrEmpty($scope)) { $scope = $Namespace }
    $keys = @($parsed.Keys | Sort-Object Name | ForEach-Object {
        @([string]$_.Name, [string]$_.Value)
    })
    $identity = @($server, $scope, $parsed.Class, $keys)
    return (ConvertTo-Json -InputObject $identity -Depth 8 -Compress).ToLowerInvariant()
}

try {
    $request = ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd())
    $locator = New-Object -ComObject WbemScripting.SWbemLocator
    $service = $locator.ConnectServer('.', $request.namespace)
    $service.Security_.ImpersonationLevel = 3
    $rows = @(
        foreach ($instance in $service.InstancesOf($request.class_name, 48)) {
            $row = [ordered]@{
                path = [string]$instance.Path_.Path
                type = [string]$instance.Path_.Class
                identity = Get-Identity $instance.Path_.Path $request.namespace
            }
            foreach ($property in $instance.Properties_) {
                # Đối tượng nhúng trong Consumer tùy chỉnh được biểu diễn bằng văn bản MOF.
                if ($property.CIMType -eq 13 -and $null -ne $property.Value) {
                    $row[$property.Name] = @($property.Value | ForEach-Object {
                        $_.GetObjectText_(0)
                    })
                } else {
                    $row[$property.Name] = $property.Value
                }
            }
            if ($request.class_name -eq '__FilterToConsumerBinding') {
                $row['filter_identity'] = Get-Identity $row['Filter'] $request.namespace
                $row['consumer_identity'] = Get-Identity $row['Consumer'] $request.namespace
            }
            [pscustomobject]$row
        }
    )
    ConvertTo-Json -InputObject $rows -Depth 16 -Compress
    exit 0
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
"""


def query_wmi(namespace: str, class_name: str, timeout: int = 60) -> list[dict]:
    """Đọc các instance của lớp WMI và lớp con; báo lỗi khi thu thập thất bại."""
    if sys.platform != "win32":
        raise RuntimeError("Thu thập WMI yêu cầu Windows. Hãy chạy trong máy ảo Windows.")
    if timeout <= 0:
        raise ValueError("Thời gian chờ timeout phải lớn hơn 0")
    namespace = namespace.replace("/", "\\").strip("\\")
    if not re.fullmatch(r"[A-Za-z_][\w]*(?:\\[A-Za-z_][\w]*)*", namespace):
        raise ValueError("Namespace WMI không hợp lệ")
    if not re.fullmatch(r"[A-Za-z_]\w*", class_name):
        raise ValueError("Tên lớp WMI không hợp lệ")
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    encoded_script = base64.b64encode(POWERSHELL_SCRIPT.encode("utf-16-le")).decode("ascii")
    try:
        result = subprocess.run(
            [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive",
             "-EncodedCommand", encoded_script],
            input=json.dumps({"namespace": namespace, "class_name": class_name}),
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        raise RuntimeError(f"Không thể truy vấn {namespace}/{class_name}: {exc}") from exc
    if result.returncode != 0:
        raise RuntimeError(
            f"Truy vấn WMI thất bại với {namespace}/{class_name}: {result.stderr.strip()}"
        )
    try:
        rows = json.loads(result.stdout.lstrip("\ufeff"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"JSON trả về cho {class_name} không hợp lệ") from exc
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise RuntimeError(f"Kết quả của {class_name} phải là mảng JSON chứa các đối tượng")
    return rows


def collect_filters(namespace: str, timeout: int = 60) -> list[dict]:
    """Thu thập điều kiện, namespace sự kiện, đường dẫn và các thuộc tính gốc."""
    return [
        {
            "name": item["Name"],
            "query": item["Query"],
            "query_language": item["QueryLanguage"],
            "event_namespace": item.get("EventNamespace"),
            "path": item["path"],
            "identity": item["identity"],
            "properties": item,
        }
        for item in query_wmi(namespace, "__EventFilter", timeout)
    ]


def collect_consumers(namespace: str, timeout: int = 60) -> list[dict]:
    """Thu thập các lớp con của Consumer và giữ cả thuộc tính tùy chỉnh."""
    return [
        {
            "name": item.get("Name"),
            "type": item["type"],
            "command_line": item.get("CommandLineTemplate"),
            "executable_path": item.get("ExecutablePath"),
            "script_text": item.get("ScriptText"),
            "script_file_name": item.get("ScriptFileName"),
            "scripting_engine": item.get("ScriptingEngine"),
            "path": item["path"],
            "identity": item["identity"],
            "properties": item,
        }
        for item in query_wmi(namespace, "__EventConsumer", timeout)
    ]


def collect_bindings(namespace: str, timeout: int = 60) -> list[dict]:
    """Thu thập đường dẫn tham chiếu và định danh được WMI phân tích."""
    return [
        {
            "path": item["path"],
            "identity": item["identity"],
            "filter_path": item["Filter"],
            "consumer_path": item["Consumer"],
            "filter_identity": item["filter_identity"],
            "consumer_identity": item["consumer_identity"],
            "properties": item,
        }
        for item in query_wmi(namespace, "__FilterToConsumerBinding", timeout)
    ]


def resolve_subscriptions(
    filters: list[dict], consumers: list[dict], bindings: list[dict]
) -> list[dict]:
    """Tạo một bản ghi cho mỗi Binding, giữ cả liên kết chưa đủ đối tượng."""
    filters_by_id = {item["identity"]: item for item in filters}
    consumers_by_id = {item["identity"]: item for item in consumers}
    subscriptions = []
    for binding in bindings:
        event_filter = filters_by_id.get(binding["filter_identity"])
        consumer = consumers_by_id.get(binding["consumer_identity"])
        missing = []
        if event_filter is None:
            missing.append("filter")
        if consumer is None:
            missing.append("consumer")
        subscription_id = hashlib.sha256(binding["identity"].encode("utf-8")).hexdigest()
        subscriptions.append({
            "subscription_id": subscription_id,
            "filter": event_filter,
            "consumer": consumer,
            "binding": {
                **binding,
                "filter": event_filter.get("name") if event_filter else None,
                "consumer": consumer.get("name") if consumer else None,
            },
            "resolution_status": "incomplete" if missing else "complete",
            "missing_objects": missing,
        })
    return subscriptions


def collect_subscriptions(namespace: str = DEFAULT_NAMESPACE, timeout: int = 60) -> dict:
    """Trả về kết quả thu thập hoặc báo lỗi nếu có truy vấn thất bại."""
    namespace = namespace.replace("/", "\\").strip("\\")
    started_at = datetime.now(timezone.utc).isoformat()
    filters = collect_filters(namespace, timeout)
    consumers = collect_consumers(namespace, timeout)
    bindings = collect_bindings(namespace, timeout)
    subscriptions = resolve_subscriptions(filters, consumers, bindings)
    for subscription in subscriptions:
        subscription["namespace"] = namespace
    return {
        "format_version": "1.0",
        "computer": os.environ.get("COMPUTERNAME", "unknown"),
        "namespace": namespace,
        "collection_started_at": started_at,
        "collection_finished_at": datetime.now(timezone.utc).isoformat(),
        "filters": filters,
        "consumers": consumers,
        "bindings": bindings,
        "subscriptions": subscriptions,
    }


def main() -> int:
    """Giao diện dòng lệnh: in JSON hoặc ghi file tạm rồi thay thế file đích."""
    parser = argparse.ArgumentParser(
        description=__doc__, add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    options = parser.add_argument_group("Tùy chọn")
    options.add_argument("-h", "--help", action="help", help="Hiển thị hướng dẫn và thoát")
    options.add_argument("--namespace", default=DEFAULT_NAMESPACE, help="Namespace WMI cần thu thập")
    options.add_argument("--timeout", type=int, default=60, help="Thời gian chờ cho mỗi truy vấn WMI, tính bằng giây")
    options.add_argument("--output", type=Path, help="Đường dẫn file JSON kết quả")
    args = parser.parse_args()
    temporary_path = None
    try:
        snapshot = collect_subscriptions(args.namespace, args.timeout)
        text = json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n"
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
            print(f"Đã lưu {len(snapshot['subscriptions'])} Subscription vào {args.output}",
                  file=sys.stderr)
        return 0
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"Thu thập thất bại: {exc}", file=sys.stderr)
        return 1
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
