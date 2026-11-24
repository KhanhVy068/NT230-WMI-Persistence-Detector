import base64
from contextlib import redirect_stderr
import copy
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET


PROJECT_ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_DIR = PROJECT_ROOT / "collector"


def load_module(name):
    """Nạp đúng module trong dự án, hỗ trợ thư mục chưa có __init__.py."""
    path = COLLECTOR_DIR / f"{name}.py"
    if not path.is_file():
        raise FileNotFoundError(f"Thiếu module cần kiểm thử: {path}")
    spec = importlib.util.spec_from_file_location(f"d12_test_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wmi = load_module("wmi_collector")
eventlog = load_module("eventlog_collector")
normalizer = load_module("normalizer")

START = datetime(2026, 11, 14, 0, 0, tzinfo=timezone.utc)
END = datetime(2026, 11, 15, 0, 0, tzinfo=timezone.utc)
XML_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def wmi_rows():
    """Mỗi lần gọi trả về dữ liệu mới để các ca kiểm thử độc lập."""
    return {
        "__EventFilter": [{
            "Name": "Bộ lọc thử nghiệm", "Query": " SELECT * FROM Win32_ProcessStartTrace ",
            "QueryLanguage": "WQL", "EventNamespace": "ROOT/CIMV2",
            "path": 'root\\subscription:__EventFilter.Name="Bộ lọc thử nghiệm"',
            "identity": "filter-identity",
        }],
        "__EventConsumer": [{
            "Name": "LabConsumer", "type": "CommandLineEventConsumer",
            "CommandLineTemplate": "  cmd /c echo D12  ",
            "ExecutablePath": r"C:\Windows\System32\cmd.exe",
            "path": 'root\\subscription:CommandLineEventConsumer.Name="LabConsumer"',
            "identity": "consumer-identity",
        }],
        "__FilterToConsumerBinding": [{
            "Filter": 'root\\subscription:__EventFilter.Name="Bộ lọc thử nghiệm"',
            "Consumer": 'root\\subscription:CommandLineEventConsumer.Name="LabConsumer"',
            "path": "binding-path", "identity": "binding-identity",
            "filter_identity": "filter-identity", "consumer_identity": "consumer-identity",
        }],
    }


def wmi_snapshot():
    """Chạy logic Collector thật với tầng truy vấn được thay bằng dữ liệu mẫu."""
    rows = wmi_rows()
    with patch.object(wmi, "query_wmi", side_effect=lambda ns, cls, timeout: rows[cls]):
        return wmi.collect_subscriptions()


def event_xml(event_id=19, record_id=7, timestamp="2026-11-14T10:00:00.1234567Z"):
    """XML mẫu có Unicode, tên trường trùng, trường thiếu tên và UserData."""
    root = ET.Element("Event", xmlns=XML_NS)
    system = ET.SubElement(root, "System")
    ET.SubElement(system, "Provider", Name="D12-Test-Provider")
    for name, value in {
        "EventID": event_id, "Version": 0, "Level": 4,
        "EventRecordID": record_id, "Channel": "D12-Test", "Computer": "D12-VM",
    }.items():
        ET.SubElement(system, name).text = str(value)
    ET.SubElement(system, "TimeCreated", SystemTime=timestamp)
    ET.SubElement(system, "Execution", ProcessID="100", ThreadID="200")
    ET.SubElement(system, "Security", UserID="S-1-5-18")
    payload = ET.SubElement(root, "EventData")
    ET.SubElement(payload, "Data", Name="Name").text = "Bộ lọc thử nghiệm"
    ET.SubElement(payload, "Data", Name="Name").text = "Giá trị thứ hai"
    ET.SubElement(payload, "Data", Name="CommandLine").text = "  cmd /c echo D12  "
    ET.SubElement(payload, "Data").text = "Dữ liệu chưa có tên"
    user_data = ET.SubElement(root, "UserData")
    ET.SubElement(user_data, "Details", xmlns="urn:d12-test").text = "Thông tin bổ sung"
    return ET.tostring(root, encoding="unicode")


def event_reply(events=None, **changes):
    """Phản hồi giả lập của tầng gọi PowerShell."""
    reply = {"status": "ok", "channel_enabled": True,
             "truncated": False, "events": [] if events is None else events}
    reply.update(changes)
    return reply


def event_bundle():
    with patch.object(eventlog, "query_eventlog", return_value=event_reply([event_xml()])):
        return eventlog.collect_eventlogs(sources=["wmi"], end_time=END)


class TestWmiQuery(unittest.TestCase):
    """Kiểm thử giao tiếp Python–PowerShell, chưa chạy COM WMI thật."""

    def query_with_result(self, stdout, returncode=0, stderr=""):
        process = subprocess.CompletedProcess([], returncode, stdout, stderr)
        with patch.object(wmi.sys, "platform", "win32"), patch.object(
            wmi.subprocess, "run", return_value=process
        ) as run:
            result = wmi.query_wmi("root/subscription", "__EventFilter", timeout=15)
        return result, run.call_args

    def test_empty_single_and_multiple_records(self):
        for records in (
            [],
            [{"Name": "Lọc", "path": "filter-a", "type": "__EventFilter", "identity": "a"}],
            [
                {"Name": "A", "path": "filter-a", "type": "__EventFilter", "identity": "a"},
                {"Name": "B", "path": "filter-b", "type": "__EventFilter", "identity": "b"},
            ],
        ):
            with self.subTest(count=len(records)):
                result, _ = self.query_with_result("\ufeff" + json.dumps(records))
                self.assertEqual(result, records)

    def test_empty_collection_object_is_rejected_before_filter_processing(self):
        pseudo_instance = [{"path": "", "type": "", "identity": ""}]
        process = subprocess.CompletedProcess([], 0, json.dumps(pseudo_instance), "")
        with patch.object(wmi.sys, "platform", "win32"), patch.object(
            wmi.subprocess, "run", return_value=process
        ), self.assertRaisesRegex(RuntimeError, "thiếu hoặc rỗng: path, type, identity"):
            wmi.collect_filters(wmi.DEFAULT_NAMESPACE)

    def test_powershell_indexes_swbem_object_set_before_reading_properties(self):
        script = wmi.POWERSHELL_SCRIPT
        self.assertIn("$instances = $service.InstancesOf($request.class_name)", script)
        self.assertIn("$instance = $instances.ItemIndex($index)", script)
        self.assertIn("foreach ($property in $instance.Properties_)", script)
        self.assertNotIn("$service.InstancesOf($request.class_name, 48)", script)
        self.assertIn("if ($rows.Count -eq 0)", script)

    def test_request_encoding_and_timeout(self):
        _, call = self.query_with_result("[]")
        self.assertEqual(json.loads(call.kwargs["input"]), {
            "namespace": r"root\subscription", "class_name": "__EventFilter",
        })
        command = call.args[0]
        encoded = command[command.index("-EncodedCommand") + 1]
        self.assertEqual(base64.b64decode(encoded).decode("utf-16-le"), wmi.POWERSHELL_SCRIPT)
        self.assertEqual(call.kwargs["timeout"], 15)
        self.assertEqual(call.kwargs["encoding"], "utf-8")

    def test_invalid_json_and_shapes_raise(self):
        for text in ("", "bad-json", "{}", "null", "[1]", '["abc"]'):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                self.query_with_result(text)

    def test_required_wmi_properties_are_reported_clearly(self):
        cases = (
            (
                wmi.collect_filters,
                {"path": "filter", "type": "__EventFilter", "identity": "filter-id"},
                "__EventFilter instance 0 thiếu hoặc rỗng: Name, Query, QueryLanguage",
            ),
            (
                wmi.collect_consumers,
                {"path": "consumer", "type": "CommandLineEventConsumer", "identity": "consumer-id"},
                "__EventConsumer instance 0 thiếu hoặc rỗng: Name",
            ),
            (
                wmi.collect_bindings,
                {"path": "binding", "type": "__FilterToConsumerBinding", "identity": "binding-id"},
                "__FilterToConsumerBinding instance 0 thiếu hoặc rỗng: Filter, Consumer, filter_identity, consumer_identity",
            ),
        )
        for collect, row, message in cases:
            with self.subTest(collect=collect.__name__), patch.object(
                wmi, "query_wmi", return_value=[row]
            ), self.assertRaisesRegex(RuntimeError, message):
                collect(wmi.DEFAULT_NAMESPACE)

    def test_powershell_failure_preserves_error(self):
        with self.assertRaisesRegex(RuntimeError, "access denied"):
            self.query_with_result("", returncode=1, stderr="access denied")

    def test_process_failures_raise(self):
        failures = [OSError("missing executable"), subprocess.TimeoutExpired("powershell", 1)]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), patch.object(
                wmi.sys, "platform", "win32"
            ), patch.object(wmi.subprocess, "run", side_effect=failure):
                with self.assertRaises(RuntimeError):
                    wmi.query_wmi(wmi.DEFAULT_NAMESPACE, "__EventFilter")

    def test_invalid_arguments_do_not_start_process(self):
        with patch.object(wmi.sys, "platform", "win32"), patch.object(wmi.subprocess, "run") as run:
            for namespace, class_name, timeout in (
                ("root;test", "__EventFilter", 1),
                ("root/subscription", "Class;test", 1),
                ("root/subscription", "__EventFilter", 0),
            ):
                with self.subTest(namespace=namespace, timeout=timeout), self.assertRaises(ValueError):
                    wmi.query_wmi(namespace, class_name, timeout)
            run.assert_not_called()

    def test_non_windows_is_rejected(self):
        with patch.object(wmi.sys, "platform", "linux"), self.assertRaises(RuntimeError):
            wmi.query_wmi(wmi.DEFAULT_NAMESPACE, "__EventFilter")


class TestWmiCollection(unittest.TestCase):
    """Kiểm tra dữ liệu thu thập và ghép đối tượng theo định danh."""

    def test_collect_fields_and_references(self):
        snapshot = wmi_snapshot()
        subscription = snapshot["subscriptions"][0]
        self.assertEqual(subscription["resolution_status"], "complete")
        self.assertEqual(subscription["missing_objects"], [])
        self.assertEqual(subscription["filter"]["name"], "Bộ lọc thử nghiệm")
        self.assertEqual(subscription["filter"]["identity"], "filter-identity")
        self.assertEqual(subscription["filter"]["properties"]["QueryLanguage"], "WQL")
        self.assertEqual(subscription["consumer"]["command_line"], "  cmd /c echo D12  ")
        self.assertEqual(subscription["consumer"]["identity"], "consumer-identity")
        self.assertEqual(subscription["binding"]["consumer"], "LabConsumer")
        self.assertEqual(subscription["binding"]["filter_identity"], "filter-identity")
        self.assertEqual(subscription["binding"]["consumer_identity"], "consumer-identity")
        self.assertEqual(subscription["namespace"], wmi.DEFAULT_NAMESPACE)
        self.assertEqual(len(subscription["subscription_id"]), 64)

    def test_id_is_repeatable(self):
        self.assertEqual(wmi_snapshot()["subscriptions"][0]["subscription_id"],
                         wmi_snapshot()["subscriptions"][0]["subscription_id"])

    def test_empty_namespace_results(self):
        with patch.object(wmi, "query_wmi", return_value=[]):
            snapshot = wmi.collect_subscriptions()
        for key in ("filters", "consumers", "bindings", "subscriptions"):
            self.assertEqual(snapshot[key], [])

    def test_missing_reference_is_retained(self):
        snapshot = wmi_snapshot()
        for filters, consumers, expected in (
            ([], snapshot["consumers"], ["filter"]),
            (snapshot["filters"], [], ["consumer"]),
            ([], [], ["filter", "consumer"]),
        ):
            with self.subTest(missing=expected):
                result = wmi.resolve_subscriptions(filters, consumers, snapshot["bindings"])
                self.assertEqual(result[0]["missing_objects"], expected)
                self.assertEqual(result[0]["resolution_status"], "incomplete")

    def test_same_name_different_identity_and_multiple_bindings(self):
        snapshot = wmi_snapshot()
        first = snapshot["consumers"][0]
        second = {**first, "identity": "consumer-2", "path": "consumer-path-2"}
        binding = snapshot["bindings"][0]
        second_binding = {**binding, "identity": "binding-2", "consumer_identity": "consumer-2"}
        result = wmi.resolve_subscriptions(snapshot["filters"], [first, second], [binding, second_binding])
        self.assertEqual([row["consumer"]["identity"] for row in result], ["consumer-identity", "consumer-2"])
        self.assertNotEqual(result[0]["subscription_id"], result[1]["subscription_id"])

    def test_script_and_custom_consumer_properties(self):
        records = [
            {"Name": "Script", "type": "ActiveScriptEventConsumer", "path": "s", "identity": "s",
             "ScriptText": "WScript.Echo \"D12\"", "ScriptingEngine": "VBScript"},
            {"Name": "Log", "type": "LogFileEventConsumer", "path": "l", "identity": "l",
             "Filename": r"C:\D12Lab\audit.log", "Text": "Audit"},
        ]
        with patch.object(wmi, "query_wmi", return_value=records):
            result = wmi.collect_consumers(wmi.DEFAULT_NAMESPACE)
        self.assertEqual(result[0]["script_text"], records[0]["ScriptText"])
        self.assertIsNone(result[1]["command_line"])
        self.assertEqual(result[1]["properties"]["Filename"], records[1]["Filename"])

    def test_orphan_objects_remain_in_raw_lists(self):
        rows = wmi_rows()
        rows["__FilterToConsumerBinding"] = []
        with patch.object(wmi, "query_wmi", side_effect=lambda ns, cls, timeout: rows[cls]):
            snapshot = wmi.collect_subscriptions()
        self.assertEqual(snapshot["subscriptions"], [])
        self.assertEqual(len(snapshot["filters"]), 1)
        self.assertEqual(len(snapshot["consumers"]), 1)

    def test_failed_query_is_not_reported_as_empty(self):
        with patch.object(wmi, "query_wmi", side_effect=RuntimeError("access denied")):
            with self.assertRaises(RuntimeError):
                wmi.collect_subscriptions()


class TestEventLogQuery(unittest.TestCase):
    """Kiểm thử phản hồi và lỗi của tầng gọi Get-WinEvent."""

    def query(self):
        return eventlog.query_eventlog("Security", [4688], START, END, max_events=10, timeout=5)

    def test_success_request_and_bom(self):
        reply = event_reply([event_xml()])
        process = subprocess.CompletedProcess([], 0, "\ufeff" + json.dumps(reply), "")
        with patch.object(eventlog.sys, "platform", "win32"), patch.object(
            eventlog.subprocess, "run", return_value=process
        ) as run:
            self.assertEqual(self.query(), reply)
        request = json.loads(run.call_args.kwargs["input"])
        self.assertEqual(request["event_ids"], [4688])
        self.assertEqual(request["max_events"], 10)
        self.assertEqual(request["start_time"], START.isoformat())
        self.assertEqual(run.call_args.kwargs["timeout"], 5)

    def test_source_failure_statuses(self):
        for status in ("missing", "access_denied", "error"):
            reply = event_reply(status=status, error="Lỗi nguồn")
            process = subprocess.CompletedProcess([], 0, json.dumps(reply), "")
            with self.subTest(status=status), patch.object(eventlog.sys, "platform", "win32"), patch.object(
                eventlog.subprocess, "run", return_value=process
            ):
                self.assertEqual(self.query()["status"], status)

    def test_bad_response_shapes(self):
        for stdout in ("bad", "[]", "{}", '{"status":"ok","events":{}}',
                       '{"status":"ok","events":[3]}'):
            with self.subTest(stdout=stdout), patch.object(eventlog.sys, "platform", "win32"), patch.object(
                eventlog.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout, "")
            ):
                self.assertEqual(self.query()["status"], "error")

    def test_timeout_os_error_and_nonzero_exit(self):
        for exception, status in ((subprocess.TimeoutExpired("ps", 5), "timeout"), (OSError("missing"), "error")):
            with self.subTest(status=status), patch.object(eventlog.sys, "platform", "win32"), patch.object(
                eventlog.subprocess, "run", side_effect=exception
            ):
                self.assertEqual(self.query()["status"], status)
        with patch.object(eventlog.sys, "platform", "win32"), patch.object(
            eventlog.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "native error")
        ):
            self.assertEqual(self.query()["error"], "native error")

    def test_invalid_window_and_limits(self):
        with patch.object(eventlog.sys, "platform", "win32"), patch.object(eventlog.subprocess, "run") as run:
            for start, end, limit in ((END, START, 10), (START.replace(tzinfo=None), END, 10), (START, END, 0)):
                with self.subTest(start=start, limit=limit), self.assertRaises(ValueError):
                    eventlog.query_eventlog("Security", [4688], start, end, limit)
            run.assert_not_called()


class TestEventLogData(unittest.TestCase):
    """Kiểm thử XML, dữ liệu thiếu, giới hạn và tổng hợp nhiều nguồn."""

    def test_xml_fields_unicode_and_raw_evidence(self):
        xml = event_xml()
        event = eventlog.parse_event_xml(xml, "wmi")
        self.assertEqual(event["event_id"], 19)
        self.assertEqual(event["record_id"], 7)
        self.assertEqual(event["computer"], "D12-VM")
        self.assertEqual(event["execution"]["ProcessID"], "100")
        self.assertEqual(event["system_user_sid"], "S-1-5-18")
        self.assertEqual([field["name"] for field in event["event_data"]], ["Name", "Name", "CommandLine", None])
        self.assertEqual(event["event_data"][0]["value"], "Bộ lọc thử nghiệm")
        self.assertIn("Thông tin bổ sung", event["user_data_xml"])
        self.assertEqual(event["raw_xml"], xml)
        self.assertEqual(event["event_uid"], eventlog.parse_event_xml(xml, "wmi")["event_uid"])

    def test_invalid_xml_and_missing_system_fields(self):
        invalid = ["<bad", f'<Event xmlns="{XML_NS}"/>',
                   f'<Event xmlns="{XML_NS}"><System><EventID>19</EventID></System></Event>',
                   event_xml(timestamp="2026-11-14T10:00:00")]
        for xml in invalid:
            with self.subTest(xml=xml), self.assertRaises((ET.ParseError, ValueError)):
                eventlog.parse_event_xml(xml, "wmi")

    def test_deduplication_and_chronological_sort(self):
        later = event_xml(record_id=9, timestamp="2026-11-14T11:00:00Z")
        earlier = event_xml(record_id=8, timestamp="2026-11-14T10:00:00Z")
        with patch.object(eventlog, "query_eventlog", return_value=event_reply([later, earlier, earlier])):
            bundle = eventlog.collect_eventlogs(["wmi"], end_time=END)
        self.assertEqual([row["record_id"] for row in bundle["events"]], [8, 9])
        self.assertEqual(bundle["event_count"], 2)

    def test_fixed_window_and_unique_sources(self):
        with patch.object(eventlog, "query_eventlog", return_value=event_reply()) as query:
            bundle = eventlog.collect_eventlogs(["wmi", "security", "wmi"], hours=24, end_time=END)
        self.assertEqual(query.call_count, 2)
        for call in query.call_args_list:
            self.assertEqual(call.args[2:4], (START, END))
        self.assertEqual(bundle["collection_status"], "ok")
        self.assertEqual(bundle["events"], [])

    def test_truncation_disabled_and_bad_xml_are_partial(self):
        for reply in (event_reply(truncated=True), event_reply(channel_enabled=False),
                      event_reply([event_xml(), "<bad"])):
            with self.subTest(reply=reply), patch.object(eventlog, "query_eventlog", return_value=reply):
                bundle = eventlog.collect_eventlogs(["wmi"], end_time=END)
                self.assertEqual(bundle["collection_status"], "partial")
                if "<bad" in reply["events"]:
                    self.assertEqual(bundle["sources"][0]["parse_errors"][0]["raw_xml"], "<bad")
                    self.assertEqual(bundle["event_count"], 1)

    def test_partial_and_all_failed_sources(self):
        failure = event_reply(status="access_denied", error="Thiếu quyền")
        with patch.object(eventlog, "query_eventlog", side_effect=[event_reply([event_xml()]), failure]):
            bundle = eventlog.collect_eventlogs(["wmi", "security"], end_time=END)
        self.assertEqual(bundle["collection_status"], "partial")
        self.assertEqual(bundle["event_count"], 1)
        with patch.object(eventlog, "query_eventlog", return_value=failure):
            self.assertEqual(eventlog.collect_eventlogs(end_time=END)["collection_status"], "failed")

    def test_invalid_collection_options(self):
        for kwargs in ({"sources": []}, {"sources": ["unknown"]}, {"hours": 0},
                       {"hours": float("nan")}, {"hours": float("inf")},
                       {"max_events": 0}, {"timeout": 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                eventlog.collect_eventlogs(**kwargs)


class TestNormalizer(unittest.TestCase):
    """Kiểm tra đầu ra hai Collector đi qua Normalizer và giữ đúng bằng chứng."""

    def test_both_collectors_and_input_immutability(self):
        snapshot, logs = wmi_snapshot(), event_bundle()
        original = copy.deepcopy((snapshot, logs))
        result = normalizer.normalize_data(snapshot, logs)
        self.assertEqual(result["normalization_status"], "ok")
        self.assertEqual(result["counts"]["subscriptions"], 1)
        self.assertEqual(result["counts"]["events"], 1)
        subscription = result["subscriptions"][0]
        self.assertEqual(subscription["subscription_id"], snapshot["subscriptions"][0]["subscription_id"])
        self.assertEqual(subscription["consumer"]["command_line"], "  cmd /c echo D12  ")
        self.assertEqual(subscription["filter"]["query"], " SELECT * FROM Win32_ProcessStartTrace ")
        self.assertEqual(subscription["filter"]["event_namespace"], r"root\cimv2")
        self.assertEqual((snapshot, logs), original)

    def test_duplicate_and_unnamed_event_data(self):
        event = normalizer.normalize_event(eventlog.parse_event_xml(event_xml(), "wmi"))
        self.assertEqual(event["data"]["Name"], ["Bộ lọc thử nghiệm", "Giá trị thứ hai"])
        self.assertEqual(event["unnamed_data"], ["Dữ liệu chưa có tên"])
        self.assertEqual(event["level"], 4)
        self.assertEqual(event["raw_xml"], event["raw"]["raw_xml"])

    def test_utc_offset_and_fraction_precision(self):
        self.assertEqual(normalizer.normalize_timestamp("2026-11-14T17:00:00.1234567+07:00"),
                         "2026-11-14T10:00:00.1234567Z")
        self.assertEqual(normalizer.normalize_timestamp("2026-11-14T00:00:00+07:00"),
                         "2026-11-13T17:00:00Z")
        times = ["2026-11-14T10:00:00.1234568Z", "2026-11-14T10:00:00Z", "2026-11-14T10:00:00.1234567Z"]
        records = [eventlog.parse_event_xml(event_xml(record_id=i, timestamp=value), "wmi")
                   for i, value in enumerate(times)]
        result = normalizer.normalize_data(eventlog_data=records)
        self.assertEqual([row["time_created"] for row in result["events"]], [times[1], times[2], times[0]])

    def test_single_sample_and_generated_id(self):
        sample = {"namespace": "root/subscription", "filter": {"name": "F", "query": "Q"},
                  "consumer": {"name": "C", "type": "LogFileEventConsumer"},
                  "binding": {"filter": "F", "consumer": "C"}}
        first = normalizer.normalize_data(sample)["subscriptions"][0]
        second = normalizer.normalize_data([sample])["subscriptions"][0]
        self.assertEqual(first["subscription_id"], second["subscription_id"])
        self.assertEqual(first["id_origin"], "generated_from_content")

    def test_missing_objects_fields_and_rejected_records(self):
        snapshot = wmi_snapshot()
        snapshot["subscriptions"][0]["consumer"] = None
        result = normalizer.normalize_data(snapshot)
        self.assertIsNone(result["subscriptions"][0]["consumer"])
        self.assertIn("incomplete_subscription", [issue["code"] for issue in result["issues"]])
        snapshot["subscriptions"][0]["consumer"] = {}
        result = normalizer.normalize_data(snapshot)
        self.assertIn("missing_fields", [issue["code"] for issue in result["issues"]])
        invalid = {"event_id": "bad", "time_created": "bad"}
        result = normalizer.normalize_data(eventlog_data=[invalid])
        self.assertEqual(result["rejected_records"][0]["raw"], invalid)
        self.assertEqual(result["normalization_status"], "partial")

    def test_upstream_failure_and_orphan_inventory_preserved(self):
        logs = event_bundle()
        logs["collection_status"] = "partial"
        logs["sources"][0]["truncated"] = True
        snapshot = wmi_snapshot()
        snapshot["subscriptions"] = []
        result = normalizer.normalize_data(snapshot, logs)
        self.assertEqual(result["normalization_status"], "partial")
        self.assertEqual(result["collection_metadata"]["wmi"]["filters"], snapshot["filters"])
        self.assertEqual(result["collection_metadata"]["eventlog"]["sources"], logs["sources"])

    def test_empty_inputs_and_invalid_types(self):
        self.assertEqual(normalizer.normalize_data([], [])["normalization_status"], "ok")
        for args in ({}, {"wmi_data": {}}, {"wmi_data": {"subscriptions": {}}}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                normalizer.normalize_data(**args)
        for value in (True, -1, 3.5, "abc"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalizer.integer_value(value, "id")
        self.assertEqual(normalizer.integer_value("0x2bc", "pid"), 700)
        with self.assertRaises(ValueError):
            normalizer.normalize_timestamp("2026-11-14T10:00:00")

    def test_json_bom_duplicate_keys_and_nonfinite_numbers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_text('{"name":"Bộ lọc"}', encoding="utf-8-sig")
            self.assertEqual(normalizer.load_json(path)["name"], "Bộ lọc")
            for content in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
                path.write_text(content, encoding="utf-8")
                with self.subTest(content=content), self.assertRaises(ValueError):
                    normalizer.load_json(path)


class TestCommandLine(unittest.TestCase):
    """Chạy main và CLI thật, kiểm tra mã thoát và file kết quả."""

    def test_all_help_commands(self):
        for name in ("wmi_collector", "eventlog_collector", "normalizer"):
            with self.subTest(module=name):
                result = subprocess.run([sys.executable, str(COLLECTOR_DIR / f"{name}.py"), "--help"],
                                        capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0)
                self.assertTrue(result.stdout)

    def test_wmi_main_writes_and_preserves_old_file_on_collection_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wmi.json"
            with patch.object(wmi, "collect_subscriptions", return_value=wmi_snapshot()), patch.object(
                sys, "argv", ["collector", "--output", str(path)]
            ), redirect_stderr(io.StringIO()):
                self.assertEqual(wmi.main(), 0)
            before = path.read_bytes()
            self.assertEqual(len(json.loads(before)["subscriptions"]), 1)
            with patch.object(wmi, "collect_subscriptions", side_effect=RuntimeError("Lỗi thử nghiệm")), patch.object(
                sys, "argv", ["collector", "--output", str(path)]
            ), redirect_stderr(io.StringIO()):
                self.assertEqual(wmi.main(), 1)
            self.assertEqual(path.read_bytes(), before)

    def test_eventlog_main_saves_failure_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            for status, expected_exit in (("ok", 0), ("partial", 2), ("failed", 2)):
                bundle = event_bundle()
                bundle["collection_status"] = status
                with self.subTest(status=status), patch.object(eventlog, "collect_eventlogs", return_value=bundle), patch.object(
                    sys, "argv", ["collector", "--output", str(path)]
                ), redirect_stderr(io.StringIO()):
                    self.assertEqual(eventlog.main(), expected_exit)
                self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["collection_status"], status)

    def test_normalizer_real_cli_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            wmi_path, event_path, output = directory / "wmi.json", directory / "events.json", directory / "normalized.json"
            wmi_path.write_text(json.dumps(wmi_snapshot()), encoding="utf-8")
            event_path.write_text(json.dumps(event_bundle()), encoding="utf-8")
            command = [sys.executable, str(COLLECTOR_DIR / "normalizer.py"), "--wmi", str(wmi_path),
                       "--eventlogs", str(event_path), "--output", str(output)]
            result = subprocess.run(command, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["counts"]["events"], 1)
            self.assertEqual(payload["counts"]["subscriptions"], 1)
            before = output.read_bytes()
            event_path.write_text("{bad", encoding="utf-8")
            result = subprocess.run(command, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(output.read_bytes(), before)

    def test_atomic_replace_failure_keeps_previous_file_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wmi.json"
            path.write_text("previous result", encoding="utf-8")
            with patch.object(wmi, "collect_subscriptions", return_value=wmi_snapshot()), patch.object(
                sys, "argv", ["collector", "--output", str(path)]
            ), patch.object(wmi.os, "replace", side_effect=PermissionError("Lỗi ghi file")), redirect_stderr(io.StringIO()):
                self.assertEqual(wmi.main(), 1)
            self.assertEqual(path.read_text(encoding="utf-8"), "previous result")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_normalizer_refuses_input_as_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data.json"
            path.write_text("[]", encoding="utf-8")
            with patch.object(sys, "argv", ["normalizer", "--wmi", str(path), "--output", str(path)]), redirect_stderr(io.StringIO()):
                self.assertEqual(normalizer.main(), 1)
            self.assertEqual(path.read_text(encoding="utf-8"), "[]")


@unittest.skipUnless(
    sys.platform == "win32" and os.environ.get("D12_RUN_LIVE_TESTS") == "1",
    "Chỉ chạy trên Windows khi đặt D12_RUN_LIVE_TESTS=1",
)
class TestLiveWindows(unittest.TestCase):
    """Kiểm thử đọc thực tế; cần Windows VM có quyền truy cập nguồn dữ liệu."""

    def test_live_wmi_query(self):
        snapshot = wmi.collect_subscriptions(timeout=30)
        self.assertIsInstance(snapshot["filters"], list)
        self.assertIsInstance(snapshot["consumers"], list)
        self.assertIsInstance(snapshot["bindings"], list)
        self.assertEqual(len(snapshot["subscriptions"]), len(snapshot["bindings"]))

    def test_live_wmi_activity_log(self):
        bundle = eventlog.collect_eventlogs(["wmi"], hours=1, max_events=20, timeout=30)
        report = bundle["sources"][0]
        self.assertIn(report["status"], {"ok", "partial"}, report.get("error"))
        self.assertEqual(report["parse_errors"], [])
        self.assertLessEqual(bundle["event_count"], 20)


if __name__ == "__main__":
    unittest.main(verbosity=2)
