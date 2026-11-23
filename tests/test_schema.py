"""Kiểm thử hợp đồng JSON Schema cho Normalizer và report/Alert TV3."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import uuid

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

from collector.normalizer import normalize_data
from detector import engine


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIRECTORY = PROJECT_ROOT / "schemas"


def command_subscription(command_line, subscription_id="SCHEMA-CMD"):
    return {
        "subscription_id": subscription_id,
        "computer": "SCHEMA-VM",
        "namespace": "root\\subscription",
        "filter": {"name": "F", "query": "SELECT * FROM Win32_ProcessStartTrace"},
        "consumer": {
            "name": "C",
            "type": "CommandLineEventConsumer",
            "command_line": command_line,
        },
        "binding": {"filter": "F", "consumer": "C"},
    }


def active_script_subscription(subscription_id="SCHEMA-SCRIPT"):
    return {
        "subscription_id": subscription_id,
        "computer": "SCHEMA-VM",
        "namespace": "root\\subscription",
        "filter": {"name": "F", "query": "SELECT * FROM Win32_ProcessStartTrace"},
        "consumer": {
            "name": "ScriptConsumer",
            "type": "ActiveScriptEventConsumer",
            "scripting_engine": "VBScript",
            "script_file_name": "%TEMP%\\launcher.vbs",
            "script_text": (
                "Set launcher = CreateObject(\"WScript.Shell\")\n"
                "launcher.Run \"powershell.exe -NoProfile\""
            ),
        },
        "binding": {"filter": "F", "consumer": "ScriptConsumer"},
    }


class SchemaTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schemas = {
            path.name: json.loads(path.read_text(encoding="utf-8"))
            for path in (
                SCHEMA_DIRECTORY / "subscription.schema.json",
                SCHEMA_DIRECTORY / "alert.schema.json",
                SCHEMA_DIRECTORY / "detection-report.schema.json",
            )
        }
        registry = Registry()
        for schema in cls.schemas.values():
            Draft202012Validator.check_schema(schema)
            registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
        cls.registry = registry
        cls.validators = {
            name: Draft202012Validator(schema, registry=registry)
            for name, schema in cls.schemas.items()
        }

    def assert_valid(self, schema_name, instance):
        errors = sorted(self.validators[schema_name].iter_errors(instance), key=lambda error: list(error.path))
        self.assertEqual([], errors, "\n".join(error.message for error in errors))

    def assert_invalid(self, schema_name, instance):
        with self.assertRaises(ValidationError):
            self.validators[schema_name].validate(instance)


class TestSubscriptionSchema(SchemaTestCase):
    def test_complete_and_incomplete_normalizer_subscriptions_are_valid(self):
        complete = normalize_data(wmi_data=command_subscription("cmd.exe /c echo safe"))
        self.assert_valid("subscription.schema.json", complete["subscriptions"][0])

        incomplete_raw = command_subscription("cmd.exe /c echo safe", "SCHEMA-INCOMPLETE")
        incomplete_raw["consumer"] = None
        incomplete = normalize_data(wmi_data=incomplete_raw)
        self.assertEqual(incomplete["subscriptions"][0]["resolution_status"], "incomplete")
        self.assert_valid("subscription.schema.json", incomplete["subscriptions"][0])

        without_computer = command_subscription("cmd.exe /c echo safe", "SCHEMA-NULL-COMPUTER")
        del without_computer["computer"]
        null_computer = normalize_data(wmi_data=without_computer)
        self.assertIsNone(null_computer["subscriptions"][0]["computer"])
        self.assert_valid("subscription.schema.json", null_computer["subscriptions"][0])


class TestDetectionReportSchema(SchemaTestCase):
    def test_actual_reports_and_alerts_are_valid_for_match_partial_and_no_alert(self):
        matched = engine.analyze_normalized(normalize_data(wmi_data=active_script_subscription()))
        self.assert_valid("detection-report.schema.json", matched)
        r04_alert = next(alert for alert in matched["alerts"] if alert["rule_id"] == "R04")
        self.assert_valid("alert.schema.json", r04_alert)

        no_alert = engine.analyze_normalized(
            normalize_data(wmi_data=command_subscription("cmd.exe /c echo safe", "SCHEMA-NO-ALERT"))
        )
        self.assertEqual(no_alert["alerts"], [])
        self.assert_valid("detection-report.schema.json", no_alert)

        partial_bundle = normalize_data(wmi_data=command_subscription(
            "powershell.exe -EncodedCommand VwByAGkAdABlAA==", "SCHEMA-PARTIAL",
        ))
        partial_bundle["normalization_status"] = "partial"
        partial_bundle["issues"].append({"source": "eventlog", "code": "truncated"})
        partial = engine.analyze_normalized(partial_bundle)
        self.assertEqual(partial["detector_status"], "partial")
        self.assert_valid("detection-report.schema.json", partial)

    def test_cli_output_is_a_schema_valid_report(self):
        token = uuid.uuid4().hex
        input_path = PROJECT_ROOT / "tests" / f".schema_cli_{token}_input.json"
        output_path = PROJECT_ROOT / "tests" / f".schema_cli_{token}_report.json"
        self.addCleanup(input_path.unlink, missing_ok=True)
        self.addCleanup(output_path.unlink, missing_ok=True)
        bundle = normalize_data(wmi_data=active_script_subscription())
        input_path.write_text(json.dumps(bundle), encoding="utf-8")
        environment = os.environ.copy()
        environment["PYTHONUTF8"] = "1"
        process = subprocess.run(
            [
                sys.executable, "-X", "utf8", "-m", "detector.engine",
                "--input", str(input_path), "--output", str(output_path),
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            timeout=15,
            env=environment,
        )
        self.assertEqual(process.returncode, 0, process.stderr.decode("utf-8"))
        self.assert_valid(
            "detection-report.schema.json",
            json.loads(output_path.read_text(encoding="utf-8")),
        )

    def test_schema_rejects_required_field_type_status_and_singular_analysis_errors(self):
        report = engine.analyze_normalized(normalize_data(wmi_data=active_script_subscription()))
        alert = next(alert for alert in report["alerts"] if alert["rule_id"] == "R04")

        missing_alert_id = copy.deepcopy(alert)
        del missing_alert_id["alert_id"]
        self.assert_invalid("alert.schema.json", missing_alert_id)

        invalid_alert_status = copy.deepcopy(alert)
        invalid_alert_status["data_status"] = "unknown"
        self.assert_invalid("alert.schema.json", invalid_alert_status)

        incomplete_r04_evidence = copy.deepcopy(alert)
        incomplete_r04_evidence["evidence"] = [
            item for item in incomplete_r04_evidence["evidence"]
            if item.get("evidence_role") != "wscript_shell_creation"
        ]
        self.assert_invalid("alert.schema.json", incomplete_r04_evidence)

        invalid_status = copy.deepcopy(report)
        invalid_status["detector_status"] = "unknown"
        self.assert_invalid("detection-report.schema.json", invalid_status)

        invalid_rule_status = copy.deepcopy(report)
        invalid_rule_status["analyses"][0]["rule_results"]["R04"]["status"] = "unknown"
        self.assert_invalid("detection-report.schema.json", invalid_rule_status)

        singular_analysis = copy.deepcopy(report)
        singular_analysis["analyses"] = singular_analysis["analyses"][0]
        self.assert_invalid("detection-report.schema.json", singular_analysis)

    def test_logic_relationships_match_alerts_analyses_and_summary(self):
        bundle = normalize_data(wmi_data=[
            command_subscription(
                "powershell.exe -EncodedCommand VwByAGkAdABlAA== -WindowStyle Hidden",
                "SCHEMA-R01-R02",
            ),
            active_script_subscription("SCHEMA-R03-R04"),
        ])
        report = engine.analyze_normalized(bundle)
        self.assert_valid("detection-report.schema.json", report)

        expected_alerts = []
        for analysis in report["analyses"]:
            for rule_id in analysis["matched_rule_ids"]:
                expected_alerts.append((
                    analysis["subscription_id"], analysis["computer"], analysis["namespace"], rule_id,
                ))
                self.assertEqual(analysis["rule_results"][rule_id]["status"], "matched")
        actual_alerts = [
            (alert["subscription_id"], alert["computer"], alert["namespace"], alert["rule_id"])
            for alert in report["alerts"]
        ]
        self.assertEqual(actual_alerts, expected_alerts)
        self.assertEqual(report["summary"]["subscriptions"], len(report["analyses"]))
        self.assertEqual(report["summary"]["alerts"], len(report["alerts"]))
        self.assertEqual(
            report["summary"]["subscriptions_with_alerts"],
            sum(bool(analysis["matched_rule_ids"]) for analysis in report["analyses"]),
        )
        for rule_id in ("R01", "R02", "R03", "R04"):
            counts = report["summary"][f"{rule_id.lower()}_status_counts"]
            self.assertEqual(sum(counts.values()), len(report["analyses"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
