"""Kiểm thử TV3 Mốc 4: bundle Normalizer, R01-R04, report và CLI."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import uuid

from collector.normalizer import load_json, normalize_data
from detector import engine


PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Danh sách cố định này chỉ dùng cho test. Detector không đọc labels.json,
# expected_rule_ids hay đường dẫn phân loại để đưa ra quyết định.
DEVELOPMENT_RULE_EXPECTATIONS = {
    "dataset/suspicious/sample_s002.json": ("R03",),
    "dataset/benign/sample_s004.json": (),
    "dataset/benign/sample_s005.json": (),
    "dataset/suspicious/sample_s007.json": ("R02",),
    "dataset/suspicious/sample_s008.json": ("R02",),
    "dataset/suspicious/sample_s009.json": ("R01",),
    "dataset/benign/sample_s010.json": (),
    "dataset/benign/sample_s011.json": (),
    "dataset/benign/sample_s012.json": (),
    "dataset/benign/sample_s014.json": (),
    "dataset/benign/sample_s015.json": (),
    "dataset/suspicious/sample_s016.json": ("R01",),
    "dataset/suspicious/sample_s019.json": ("R04",),
    "dataset/suspicious/sample_s021.json": ("R03",),
    "dataset/benign/sample_s022.json": (),
    "dataset/suspicious/sample_s024.json": ("R04",),
}


def subscription(command_line, subscription_id="SUB-R01", computer="D12-VM", namespace="root\\subscription"):
    """Tạo input thô tương thích Normalizer, không dùng dataset labels."""
    return {
        "subscription_id": subscription_id,
        "computer": computer,
        "namespace": namespace,
        "filter": {"name": "F", "query": "SELECT * FROM Win32_ProcessStartTrace"},
        "consumer": {
            "name": "C", "type": "CommandLineEventConsumer",
            "command_line": command_line,
        },
        "binding": {"filter": "F", "consumer": "C"},
    }


def normalized_subscription(command_line, **changes):
    """Trả bundle thật của normalize_data() để TV3 chỉ nhận đúng hợp đồng."""
    raw = subscription(command_line, **changes)
    return normalize_data(wmi_data=raw)


def normalized_with_consumer(command_line, **consumer_changes):
    """Tạo một bundle Normalizer rồi điều chỉnh Consumer cho edge case Detector."""
    bundle = normalized_subscription(command_line)
    bundle["subscriptions"][0]["consumer"].update(consumer_changes)
    return bundle


def normalized_active_script(script_text, **consumer_changes):
    """Tạo bundle ActiveScript thật qua Normalizer, không đọc labels/dataset."""
    raw = subscription(None)
    raw["consumer"] = {
        "name": "C",
        "type": "ActiveScriptEventConsumer",
        "scripting_engine": "VBScript",
        "script_text": script_text,
        "script_file_name": None,
    }
    raw["consumer"].update(consumer_changes)
    return normalize_data(wmi_data=raw)


def python_environment():
    """Bảo đảm các tiến trình Python con mã hóa được thông điệp tiếng Việt."""
    environment = os.environ.copy()
    environment["PYTHONUTF8"] = "1"
    return environment


class TestDevelopmentData(unittest.TestCase):
    """Chỉ dùng nội dung mẫu development đã chốt cho phát triển R01-R04."""

    def test_development_samples_match_all_enabled_rules_only_when_expected(self):
        for relative_path, expected_rule_ids in DEVELOPMENT_RULE_EXPECTATIONS.items():
            with self.subTest(path=relative_path):
                raw = load_json(PROJECT_ROOT / relative_path)
                report = engine.analyze_normalized(normalize_data(wmi_data=raw))
                analysis = report["analyses"][0]
                self.assertEqual(tuple(analysis["matched_rule_ids"]), expected_rule_ids)
                self.assertEqual(len(report["alerts"]), len(expected_rule_ids))
                self.assertNotEqual(analysis["rule_results"]["R04"]["status"], "not_implemented")


class TestR01Matching(unittest.TestCase):
    def test_non_commandline_consumer_type_is_case_insensitive_when_command_is_missing(self):
        bundle = normalized_with_consumer(None, type=" activescripteventconsumer ")
        report = engine.analyze_normalized(bundle)
        analysis = report["analyses"][0]
        self.assertEqual(analysis["rule_results"]["R01"]["status"], "not_applicable")
        self.assertEqual(analysis["rule_results"]["R02"]["status"], "not_applicable")

    def test_case_quotes_and_whitespace_preserve_original_evidence(self):
        command_line = (
            '"C:\\Program Files\\PowerShell\\7\\PoWeRsHeLl.ExE"   '
            '"-EnCoDeDcOmMaNd"   "VwByAGkAdABlAA=="'
        )
        report = engine.analyze_normalized(normalized_subscription(command_line))
        r01 = report["analyses"][0]["rule_results"]["R01"]
        self.assertEqual(r01["status"], "matched")
        self.assertEqual(r01["evidence"], [{
            "field": "consumer.command_line",
            "value": command_line,
            "matched_text": '"-EnCoDeDcOmMaNd"',
        }])

    def test_mentions_inside_output_or_command_payload_do_not_match(self):
        cases = {
            "powershell.exe -Command \"Write-Output '-EncodedCommand VwByAGkAdABlAA=='\"": "not_matched",
            "cmd.exe /c echo powershell.exe -EncodedCommand VwByAGkAdABlAA==": "not_applicable",
        }
        for command_line, expected_status in cases.items():
            with self.subTest(command_line=command_line):
                report = engine.analyze_normalized(normalized_subscription(command_line))
                result = report["analyses"][0]["rule_results"]["R01"]
                self.assertEqual(result["status"], expected_status)
                self.assertEqual(report["alerts"], [])

    def test_missing_or_unparseable_r01_data_is_insufficient(self):
        bundle = normalized_subscription("powershell.exe -NoProfile")
        bundle["subscriptions"][0]["consumer"] = None
        bundle["subscriptions"][0]["resolution_status"] = "incomplete"
        bundle["subscriptions"][0]["missing_objects"] = ["consumer"]
        report = engine.analyze_normalized(bundle)
        analysis = report["analyses"][0]
        self.assertEqual(analysis["rule_results"]["R01"]["status"], "insufficient_data")
        self.assertEqual(analysis["data_status"], "incomplete")
        self.assertIn("consumer", analysis["unavailable_fields"])

        bundle = normalized_subscription("powershell.exe -NoProfile")
        bundle["subscriptions"][0]["consumer"]["command_line"] = 'powershell.exe -EncodedCommand "bad'
        report = engine.analyze_normalized(bundle)
        self.assertEqual(
            report["analyses"][0]["rule_results"]["R01"]["status"], "insufficient_data",
        )
        self.assertIn(
            "consumer.command_line.parseability",
            report["analyses"][0]["unavailable_fields"],
        )

        report = engine.analyze_normalized(
            normalized_subscription("powershell.exe -EncodedCommand -NoProfile")
        )
        analysis = report["analyses"][0]
        self.assertEqual(analysis["rule_results"]["R01"]["status"], "insufficient_data")
        self.assertIn(
            "consumer.command_line.-EncodedCommand.value",
            analysis["unavailable_fields"],
        )

    def test_r01_does_not_interpret_file_arguments_as_powershell_options(self):
        report = engine.analyze_normalized(
            normalized_subscription("powershell.exe -File .\\check.ps1 -EncodedCommand VwByAGkAdABlAA==")
        )
        result = report["analyses"][0]["rule_results"]["R01"]
        self.assertEqual(result["status"], "not_matched")
        self.assertTrue(result["notes"])

    def test_alert_id_is_stable_and_contains_host_and_namespace_context(self):
        command_line = "powershell.exe -EncodedCommand VwByAGkAdABlAA=="
        first = engine.analyze_normalized(normalized_subscription(command_line))
        second = engine.analyze_normalized(normalized_subscription(command_line))
        self.assertEqual(first["alerts"][0]["alert_id"], second["alerts"][0]["alert_id"])
        self.assertEqual(first["alerts"][0]["computer"], "D12-VM")
        self.assertEqual(first["alerts"][0]["namespace"], "root\\subscription")

        other_host = engine.analyze_normalized(normalized_subscription(command_line, computer="D12-VM-02"))
        other_namespace = engine.analyze_normalized(
            normalized_subscription(command_line, namespace="root\\other")
        )
        self.assertNotEqual(first["alerts"][0]["alert_id"], other_host["alerts"][0]["alert_id"])
        self.assertNotEqual(first["alerts"][0]["alert_id"], other_namespace["alerts"][0]["alert_id"])


class TestR02Matching(unittest.TestCase):
    def test_hidden_supports_case_quotes_and_whitespace_with_original_evidence(self):
        command_line = '"pwSh.ExE"   "-WiNdOwStYle"   "HiDdEn"   -NoProfile'
        report = engine.analyze_normalized(normalized_subscription(command_line))
        r02 = report["analyses"][0]["rule_results"]["R02"]
        self.assertEqual(r02["status"], "matched")
        self.assertEqual(r02["evidence"], [{
            "field": "consumer.command_line",
            "value": command_line,
            "matched_text": '"-WiNdOwStYle" "HiDdEn"',
        }])

    def test_normal_and_keyword_mentions_in_payload_or_output_do_not_match(self):
        cases = {
            "powershell.exe -WindowStyle Normal -Command Get-Date": "not_matched",
            "powershell.exe -Command \"Write-Output '-WindowStyle Hidden'\"": "not_matched",
            "powershell.exe -File .\\check.ps1 -WindowStyle Hidden": "not_matched",
            "cmd.exe /c echo powershell.exe -WindowStyle Hidden": "not_applicable",
        }
        for command_line, expected_status in cases.items():
            with self.subTest(command_line=command_line):
                report = engine.analyze_normalized(normalized_subscription(command_line))
                result = report["analyses"][0]["rule_results"]["R02"]
                self.assertEqual(result["status"], expected_status)
                self.assertEqual(report["alerts"], [])

    def test_hidden_before_file_is_a_powershell_option(self):
        report = engine.analyze_normalized(
            normalized_subscription("powershell.exe -WindowStyle Hidden -File .\\check.ps1")
        )
        self.assertEqual(report["analyses"][0]["rule_results"]["R02"]["status"], "matched")

    def test_missing_windowstyle_value_or_command_line_is_insufficient(self):
        for command_line in ("powershell.exe -WindowStyle", "powershell.exe -WindowStyle -NoProfile"):
            with self.subTest(command_line=command_line):
                report = engine.analyze_normalized(normalized_subscription(command_line))
                analysis = report["analyses"][0]
                self.assertEqual(analysis["rule_results"]["R02"]["status"], "insufficient_data")
                self.assertEqual(analysis["data_status"], "incomplete")
                self.assertIn(
                    "consumer.command_line.-WindowStyle.value",
                    analysis["unavailable_fields"],
                )

        bundle = normalized_subscription("powershell.exe -NoProfile")
        bundle["subscriptions"][0]["consumer"]["command_line"] = None
        report = engine.analyze_normalized(bundle)
        self.assertEqual(report["analyses"][0]["rule_results"]["R02"]["status"], "insufficient_data")
        self.assertIn("consumer.command_line", report["analyses"][0]["unavailable_fields"])

    def test_r01_and_r02_can_match_one_subscription_with_two_stable_alerts(self):
        command_line = "powershell.exe -EncodedCommand VwByAGkAdABlAA== -WindowStyle Hidden"
        first = engine.analyze_normalized(normalized_subscription(command_line, subscription_id="S-BOTH"))
        second = engine.analyze_normalized(normalized_subscription(command_line, subscription_id="S-BOTH"))
        analysis = first["analyses"][0]
        self.assertEqual(len(first["analyses"]), 1)
        self.assertEqual(analysis["matched_rule_ids"], ["R01", "R02"])
        self.assertEqual([alert["rule_id"] for alert in first["alerts"]], ["R01", "R02"])
        self.assertEqual(len(first["alerts"]), 2)
        self.assertEqual(
            [alert["alert_id"] for alert in first["alerts"]],
            [alert["alert_id"] for alert in second["alerts"]],
        )
        self.assertNotEqual(first["alerts"][0]["alert_id"], first["alerts"][1]["alert_id"])
        self.assertEqual(analysis["rule_results"]["R01"]["evidence"][0]["matched_text"], "-EncodedCommand")
        self.assertEqual(analysis["rule_results"]["R02"]["evidence"][0]["matched_text"], "-WindowStyle Hidden")
        self.assertEqual(first["summary"]["subscriptions_with_alerts"], 1)
        self.assertEqual(first["summary"]["alerts"], 2)


class TestR03Matching(unittest.TestCase):
    def test_consumer_type_is_case_insensitive_for_active_script_file(self):
        report = engine.analyze_normalized(normalized_with_consumer(
            None,
            type=" activescripteventconsumer ",
            executable_path=None,
            script_file_name="%TEMP%\\runner.vbs",
        ))
        self.assertEqual(report["analyses"][0]["rule_results"]["R03"]["status"], "matched")

    def test_supported_execution_sources_and_static_environment_variables(self):
        cases = [
            (
                normalized_with_consumer(
                    "cmd.exe /c echo safe",
                    executable_path='"C:\\Users\\Lab User\\AppData\\Local\\Temp\\evil tool.exe"',
                ),
                "configured_executable",
            ),
            (
                normalized_subscription('"C:\\Users\\Lab User\\Downloads\\drop.exe"'),
                "direct_executable",
            ),
            (
                normalized_subscription("%USERPROFILE%\\Downloads\\drop.exe"),
                "direct_executable",
            ),
            (
                normalized_subscription("C:/Users/Lab/AppData/Roaming/run.exe"),
                "direct_executable",
            ),
            (
                normalized_subscription('powershell.exe -File "%APPDATA%\\Lab Tools\\run.ps1"'),
                "powershell_file",
            ),
            (
                normalized_subscription('cmd.exe /c "%TMP%\\run.cmd"'),
                "cmd_c_target",
            ),
            (
                normalized_with_consumer(
                    None,
                    type="ActiveScriptEventConsumer",
                    executable_path=None,
                    script_file_name="%PUBLIC%\\agent.vbs",
                ),
                "active_script_file",
            ),
        ]
        for bundle, role in cases:
            with self.subTest(role=role):
                report = engine.analyze_normalized(bundle)
                result = report["analyses"][0]["rule_results"]["R03"]
                self.assertEqual(result["status"], "matched")
                self.assertEqual(result["evidence"][0]["execution_role"], role)
                self.assertTrue(result["evidence"][0]["path_groups"])

    def test_read_output_and_similar_directory_names_do_not_match(self):
        cases = {
            "powershell.exe -Command \"Get-Content 'C:\\Users\\Lab\\AppData\\value.txt'\"": "not_applicable",
            "cmd.exe /c echo C:\\Temp\\result.txt": "not_applicable",
            "C:\\TempTools\\evil.exe": "not_matched",
            "C:\\Users\\Lab\\DownloadsBackup\\evil.exe": "not_matched",
            "%UNKNOWN_LOCATION%\\Temp\\evil.exe": "not_applicable",
        }
        for command_line, expected_status in cases.items():
            with self.subTest(command_line=command_line):
                report = engine.analyze_normalized(normalized_subscription(command_line))
                analysis = report["analyses"][0]
                result = analysis["rule_results"]["R03"]
                self.assertEqual(result["status"], expected_status)
                self.assertEqual(result["evidence"], [])
                if "-Command" in command_line or "UNKNOWN_LOCATION" in command_line:
                    self.assertTrue(analysis["unanalysed_forms"])

    def test_missing_data_and_file_argument_are_reported_without_guessing(self):
        bundle = normalized_with_consumer(
            None, executable_path=None, script_file_name=None,
        )
        report = engine.analyze_normalized(bundle)
        analysis = report["analyses"][0]
        self.assertEqual(analysis["rule_results"]["R03"]["status"], "insufficient_data")
        self.assertIn("consumer.command_line", analysis["unavailable_fields"])

        report = engine.analyze_normalized(normalized_subscription("powershell.exe -File"))
        analysis = report["analyses"][0]
        self.assertEqual(analysis["rule_results"]["R03"]["status"], "insufficient_data")
        self.assertIn("consumer.command_line.-File.value", analysis["unavailable_fields"])

    def test_conflicting_executable_sources_are_kept_and_noted(self):
        bundle = normalized_with_consumer(
            "C:\\Temp\\from-command.exe",
            executable_path="C:\\Windows\\System32\\notepad.exe",
        )
        report = engine.analyze_normalized(bundle)
        result = report["analyses"][0]["rule_results"]["R03"]
        self.assertEqual(result["status"], "matched")
        self.assertTrue(result["notes"])
        self.assertEqual(result["evidence"][0]["field"], "consumer.command_line")

    def test_r02_and_r03_can_match_one_subscription_with_two_stable_alerts(self):
        command_line = 'powershell.exe -WindowStyle Hidden -File "%LOCALAPPDATA%\\Temp\\job.ps1"'
        first = engine.analyze_normalized(normalized_subscription(command_line, subscription_id="S-R02-R03"))
        second = engine.analyze_normalized(normalized_subscription(command_line, subscription_id="S-R02-R03"))
        analysis = first["analyses"][0]
        self.assertEqual(analysis["matched_rule_ids"], ["R02", "R03"])
        self.assertEqual([alert["rule_id"] for alert in first["alerts"]], ["R02", "R03"])
        self.assertEqual(
            [alert["alert_id"] for alert in first["alerts"]],
            [alert["alert_id"] for alert in second["alerts"]],
        )
        self.assertEqual(analysis["rule_results"]["R03"]["evidence"][0]["execution_role"], "powershell_file")
        self.assertEqual(first["summary"]["subscriptions_with_alerts"], 1)
        self.assertEqual(first["summary"]["alerts"], 2)


class TestR04Matching(unittest.TestCase):
    def test_run_exec_supports_renamed_variable_case_whitespace_quotes_and_comment(self):
        script = (
            "Rem harmless comment mentioning WScript.Shell\n"
            "  Set Runner = CreateObject( \"wScRiPt.ShElL\" ) ' creation comment\n"
            "rUnNeR . ExEc   ( \"PWSH.EXE -NoProfile\" ) ' execution comment"
        )
        report = engine.analyze_normalized(normalized_active_script(script))
        result = report["analyses"][0]["rule_results"]["R04"]
        self.assertEqual(result["status"], "matched")
        self.assertEqual([item["evidence_role"] for item in result["evidence"]], [
            "wscript_shell_creation", "wscript_shell_call",
        ])
        self.assertEqual(result["evidence"][0]["variable"], "Runner")
        self.assertEqual(result["evidence"][1]["method"], "exec")
        self.assertEqual(result["evidence"][1]["shell_name"], "pwsh.exe")
        self.assertIn("Set Runner", result["evidence"][0]["matched_text"])
        self.assertIn("rUnNeR . ExEc", result["evidence"][1]["matched_text"])

    def test_keyword_mentions_and_wrong_object_relationship_do_not_match(self):
        cases = {
            "' Set shell = CreateObject(\"WScript.Shell\")\nmessage = \"cmd.exe\"": "not_matched",
            "Set shell = CreateObject(\"WScript.Shell\")": "not_matched",
            (
                "Set shell = CreateObject(\"WScript.Shell\")\n"
                "Set other = CreateObject(\"Other.Object\")\n"
                "other.Run \"cmd.exe /c echo no\""
            ): "not_matched",
            (
                "Set runner = CreateObject(\"WScript.Shell\")\n"
                "Set runner = Nothing\n"
                "runner.Run \"cmd.exe /c echo no\""
            ): "not_matched",
            (
                "Set shell = CreateObject(\"WScript.Shell\")\n"
                "shell.Run \"notepad.exe cmd.exe is only data\""
            ): "not_matched",
        }
        for script, expected_status in cases.items():
            with self.subTest(script=script):
                report = engine.analyze_normalized(normalized_active_script(script))
                result = report["analyses"][0]["rule_results"]["R04"]
                self.assertEqual(result["status"], expected_status)
                self.assertEqual(result["evidence"], [])
                self.assertEqual(report["alerts"], [])

    def test_dynamic_or_direct_unsupported_forms_are_not_silently_interpreted(self):
        cases = [
            (
                "Set shell = CreateObject(\"WScript.Shell\")\n"
                "shell.Run commandLine"
            ),
            "CreateObject(\"WScript.Shell\").Run \"cmd.exe /c echo dynamic form\"",
            (
                "Set shell = CreateObject(\"WScript.Shell\") : "
                "shell.Run \"cmd.exe /c echo compact form\""
            ),
        ]
        for script in cases:
            with self.subTest(script=script):
                report = engine.analyze_normalized(normalized_active_script(script))
                analysis = report["analyses"][0]
                result = analysis["rule_results"]["R04"]
                self.assertEqual(result["status"], "not_applicable")
                self.assertEqual(result["evidence"], [])
                self.assertTrue(result["unanalysed_forms"])
                self.assertTrue(any(form["rule_id"] == "R04" for form in analysis["unanalysed_forms"]))

    def test_direct_run_on_other_createobject_is_not_treated_as_wscript_shell(self):
        report = engine.analyze_normalized(normalized_active_script(
            "CreateObject(\"Other.Object\").Run \"cmd.exe /c echo no\"",
        ))
        result = report["analyses"][0]["rule_results"]["R04"]
        self.assertEqual(result["status"], "not_matched")
        self.assertEqual(result["unanalysed_forms"], [])

    def test_missing_script_data_and_non_vbscript_are_explicit(self):
        no_consumer = normalized_subscription("cmd.exe /c echo no-consumer")
        no_consumer["subscriptions"][0]["consumer"] = None
        no_consumer["subscriptions"][0]["resolution_status"] = "incomplete"
        no_consumer["subscriptions"][0]["missing_objects"] = ["consumer"]
        report = engine.analyze_normalized(no_consumer)
        self.assertEqual(
            report["analyses"][0]["rule_results"]["R04"]["status"], "insufficient_data",
        )

        report = engine.analyze_normalized(normalized_active_script(
            None, script_file_name="C:\\Temp\\not-opened.vbs",
        ))
        analysis = report["analyses"][0]
        result = analysis["rule_results"]["R04"]
        self.assertEqual(result["status"], "insufficient_data")
        self.assertIn("consumer.script_text", analysis["unavailable_fields"])
        self.assertTrue(result["unanalysed_forms"])

        invalid_type = normalized_active_script("Set shell = CreateObject(\"WScript.Shell\")")
        invalid_type["subscriptions"][0]["consumer"]["script_text"] = []
        report = engine.analyze_normalized(invalid_type)
        self.assertEqual(
            report["analyses"][0]["rule_results"]["R04"]["status"], "insufficient_data",
        )

        missing_engine = normalized_active_script(
            "Set shell = CreateObject(\"WScript.Shell\")\nshell.Run \"cmd.exe\"",
        )
        missing_engine["subscriptions"][0]["consumer"]["scripting_engine"] = None
        report = engine.analyze_normalized(missing_engine)
        self.assertEqual(
            report["analyses"][0]["rule_results"]["R04"]["status"], "insufficient_data",
        )

        report = engine.analyze_normalized(normalized_active_script(
            "Set shell = CreateObject(\"WScript.Shell\")\nshell.Run \"cmd.exe\"",
            scripting_engine="JScript",
        ))
        self.assertEqual(
            report["analyses"][0]["rule_results"]["R04"]["status"], "not_applicable",
        )

    def test_r03_and_r04_can_match_with_stable_alerts_and_summary(self):
        script = (
            "Set launcher = CreateObject(\"WScript.Shell\")\n"
            "launcher.Run \"powershell.exe -NoProfile\""
        )
        first = engine.analyze_normalized(normalized_active_script(
            script, script_file_name="%TEMP%\\launcher.vbs",
        ))
        second = engine.analyze_normalized(normalized_active_script(
            script, script_file_name="%TEMP%\\launcher.vbs",
        ))
        analysis = first["analyses"][0]
        self.assertEqual(analysis["matched_rule_ids"], ["R03", "R04"])
        self.assertEqual([alert["rule_id"] for alert in first["alerts"]], ["R03", "R04"])
        self.assertEqual(
            [alert["alert_id"] for alert in first["alerts"]],
            [alert["alert_id"] for alert in second["alerts"]],
        )
        self.assertEqual(first["summary"]["subscriptions_with_alerts"], 1)
        self.assertEqual(first["summary"]["alerts"], 2)
        r04_evidence = analysis["rule_results"]["R04"]["evidence"]
        self.assertEqual([item["evidence_role"] for item in r04_evidence], [
            "wscript_shell_creation", "wscript_shell_call",
        ])


class TestEngineReport(unittest.TestCase):
    def test_api_preserves_input_and_summary_matches_actual_outputs(self):
        records = [
            subscription("powershell.exe -EncodedCommand VwByAGkAdABlAA==", "S-MATCH"),
            subscription("powershell.exe -Command Get-Date", "S-NO-MATCH"),
            subscription("cmd.exe /c echo hello", "S-NOT-APPLICABLE"),
        ]
        bundle = normalize_data(wmi_data=records)
        before = copy.deepcopy(bundle)
        report = engine.analyze_normalized(bundle)
        self.assertEqual(bundle, before)
        self.assertEqual(report["enabled_rule_ids"], ["R01", "R02", "R03", "R04"])
        self.assertEqual(report["not_implemented_rule_ids"], [])
        self.assertIn("R04", report["rule_scope"])
        self.assertEqual(report["summary"]["subscriptions"], len(report["analyses"]))
        self.assertEqual(report["summary"]["subscriptions_with_alerts"], 1)
        self.assertEqual(report["summary"]["alerts"], len(report["alerts"]))
        self.assertEqual(report["summary"]["r01_status_counts"], {
            "matched": 1,
            "not_matched": 1,
            "not_applicable": 1,
            "insufficient_data": 0,
        })
        self.assertEqual(report["summary"]["r02_status_counts"], {
            "matched": 0,
            "not_matched": 2,
            "not_applicable": 1,
            "insufficient_data": 0,
        })
        self.assertEqual(report["summary"]["r03_status_counts"], {
            "matched": 0,
            "not_matched": 0,
            "not_applicable": 3,
            "insufficient_data": 0,
        })
        self.assertEqual(report["summary"]["r04_status_counts"], {
            "matched": 0,
            "not_matched": 0,
            "not_applicable": 3,
            "insufficient_data": 0,
        })
        self.assertEqual(report["alerts"][0]["subscription_id"], "S-MATCH")
        self.assertEqual(report["alerts"][0]["rule_id"], "R01")
        self.assertIsInstance(report["alerts"], list)
        self.assertNotIn("alert", report)

    def test_upstream_partial_issues_are_preserved_and_exit_status_is_partial(self):
        bundle = normalized_subscription("powershell.exe -EncodedCommand VwByAGkAdABlAA==")
        issue = {"source": "eventlog", "code": "source_collection_issue", "message": "truncated"}
        bundle["normalization_status"] = "partial"
        bundle["issues"].append(issue)
        report = engine.analyze_normalized(bundle)
        self.assertEqual(report["detector_status"], "partial")
        self.assertEqual(report["upstream"]["normalization_status"], "partial")
        self.assertEqual(report["upstream"]["issues"], [issue])
        self.assertEqual(len(report["alerts"]), 1)

    def test_invalid_bundle_is_rejected(self):
        for value in ([], {}, {"format_version": "1.0", "normalization_status": "ok", "subscriptions": []}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    engine.analyze_normalized(value)


class TestDetectorCommandLine(unittest.TestCase):
    def command(self, input_path, output_path):
        return [
            sys.executable, "-X", "utf8", "-m", "detector.engine",
            "--input", str(input_path), "--output", str(output_path),
        ]

    def make_test_paths(self):
        """Dùng file tạm trong tests/ để tránh ACL private của %TEMP% trên Windows."""
        token = uuid.uuid4().hex
        directory = PROJECT_ROOT / "tests"
        input_path = directory / f".detector_cli_{token}_input.json"
        output_path = directory / f".detector_cli_{token}_output.json"
        self.addCleanup(input_path.unlink, missing_ok=True)
        self.addCleanup(output_path.unlink, missing_ok=True)
        return input_path, output_path

    def test_cli_writes_r01_report_and_alert_does_not_change_success_exit(self):
        input_path, output_path = self.make_test_paths()
        input_path.write_text(
            json.dumps(normalized_subscription("powershell.exe -EncodedCommand VwByAGkAdABlAA==")),
            encoding="utf-8",
        )
        result = subprocess.run(
            self.command(input_path, output_path), cwd=PROJECT_ROOT,
            capture_output=True, timeout=15, env=python_environment(),
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        report = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["alerts"], 1)
        self.assertEqual(report["detector_status"], "ok")

    def test_cli_writes_two_alerts_when_r01_and_r02_match(self):
        input_path, output_path = self.make_test_paths()
        command_line = "powershell.exe -EncodedCommand VwByAGkAdABlAA== -WindowStyle Hidden"
        input_path.write_text(json.dumps(normalized_subscription(command_line)), encoding="utf-8")
        result = subprocess.run(
            self.command(input_path, output_path), cwd=PROJECT_ROOT,
            capture_output=True, timeout=15, env=python_environment(),
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        report = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(report["enabled_rule_ids"], ["R01", "R02", "R03", "R04"])
        self.assertEqual([alert["rule_id"] for alert in report["alerts"]], ["R01", "R02"])
        self.assertEqual(report["summary"]["subscriptions_with_alerts"], 1)
        self.assertEqual(report["summary"]["alerts"], 2)

    def test_cli_writes_two_alerts_when_r02_and_r03_match(self):
        input_path, output_path = self.make_test_paths()
        command_line = 'powershell.exe -WindowStyle Hidden -File "%TEMP%\\job.ps1"'
        input_path.write_text(json.dumps(normalized_subscription(command_line)), encoding="utf-8")
        result = subprocess.run(
            self.command(input_path, output_path), cwd=PROJECT_ROOT,
            capture_output=True, timeout=15, env=python_environment(),
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        report = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual([alert["rule_id"] for alert in report["alerts"]], ["R02", "R03"])
        self.assertEqual(report["summary"]["subscriptions_with_alerts"], 1)
        self.assertEqual(report["summary"]["alerts"], 2)

    def test_cli_writes_r04_alert_for_normalized_active_script(self):
        input_path, output_path = self.make_test_paths()
        bundle = normalized_active_script(
            "Set shell = CreateObject(\"WScript.Shell\")\n"
            "shell.Run \"cmd.exe /c echo detector\"",
        )
        input_path.write_text(json.dumps(bundle), encoding="utf-8")
        result = subprocess.run(
            self.command(input_path, output_path), cwd=PROJECT_ROOT,
            capture_output=True, timeout=15, env=python_environment(),
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        report = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual([alert["rule_id"] for alert in report["alerts"]], ["R04"])
        self.assertEqual(report["summary"]["r04_status_counts"]["matched"], 1)

    def test_cli_returns_two_for_partial_report_and_one_for_errors_without_overwrite(self):
        input_path, output_path = self.make_test_paths()
        bundle = normalized_subscription("powershell.exe -Command Get-Date")
        bundle["normalization_status"] = "partial"
        bundle["issues"].append({"code": "upstream_collection_issue"})
        input_path.write_text(json.dumps(bundle), encoding="utf-8")
        result = subprocess.run(
            self.command(input_path, output_path), cwd=PROJECT_ROOT,
            capture_output=True, timeout=15, env=python_environment(),
        )
        self.assertEqual(result.returncode, 2, result.stderr.decode("utf-8"))
        self.assertEqual(json.loads(output_path.read_text(encoding="utf-8"))["detector_status"], "partial")

        before = output_path.read_bytes()
        input_path.write_text("{bad", encoding="utf-8")
        result = subprocess.run(
            self.command(input_path, output_path), cwd=PROJECT_ROOT,
            capture_output=True, timeout=15, env=python_environment(),
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(output_path.read_bytes(), before)

        source = PROJECT_ROOT / "tests" / f".detector_cli_{uuid.uuid4().hex}_source.json"
        self.addCleanup(source.unlink, missing_ok=True)
        source.write_text(json.dumps(normalized_subscription("powershell.exe -Command Get-Date")), encoding="utf-8")
        before_source = source.read_bytes()
        result = subprocess.run(
            self.command(source, source), cwd=PROJECT_ROOT,
            capture_output=True, timeout=15, env=python_environment(),
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(source.read_bytes(), before_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
