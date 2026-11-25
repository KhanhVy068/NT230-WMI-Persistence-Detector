
# WMI Persistence PoC – User Guide

## 1. Introduction

This module is developed by TV1 for the WMI Persistence Detection project.

The module simulates WMI Permanent Event Subscription using harmless log markers.

## 2. Environment

- Operating system: Windows 10 VM
- PowerShell: Windows PowerShell 5.1 / PowerShell 7
- Virtualization: Oracle VirtualBox
- Project directory: C:\WMI-Lab
- Snapshot and isolated testing environment required

## 3. Main Components

- `poc/poc_generator_v2.ps1`: Creates WMI Filter, Consumer and Binding.
- `poc/cleanup.ps1`: Removes WMI objects for a selected scenario.
- `poc/scenarios/`: Stores scenario configurations.
- `automation/scenario_runner.ps1`: Runs scenarios and records results.
- `results/`: Stores log markers and JSON results.

## 4. Scenarios

| ID | Trigger | Consumer Type | Verification Source |
|---|---|---|---|
| P01 | notepad.exe | LogFileEventConsumer | C:\WMI-Lab\results\wmi_events.log |
| P02 | CalculatorApp.exe | LogFileEventConsumer | C:\WMI-Lab\results\wmi_p02.log |
| P03 | notepad.exe | NTEventLogEventConsumer | Windows Application Event Log |

Expected markers:
- P01: WMI_POC_SUCCESS
- P02: WMI_P02_SUCCESS
- P03: WMI_P03_SUCCESS

P03 uses Event Source "WMI-Lab-Test" and Event ID 1003.

P03 currently varies consumer output configuration, not consumer type or namespace.

## 5. Run a Scenario

Open PowerShell as Administrator inside the Windows VM.

Run P01:

    & "C:\WMI-Lab\automation\scenario_runner.ps1" -ScenarioId P01

Run P02:

    & "C:\WMI-Lab\automation\scenario_runner.ps1" -ScenarioId P02

Run P03:

    & "C:\WMI-Lab\automation\scenario_runner.ps1" -ScenarioId P03

## 6. Expected Results

The Scenario Runner:

1. Reads the scenario JSON.
2. Calls the PoC Generator.
3. Verifies Filter, Consumer and Binding.
4. Triggers the selected event.
5. Checks whether a new marker was written.
6. Saves a JSON result.

A successful test reports PASSED.

A missing marker reports FAILED.

## 7. Cleanup

Preview P01 cleanup:

    & "C:\WMI-Lab\poc\cleanup.ps1" -ScenarioId P01

Execute P01 cleanup:

    & "C:\WMI-Lab\poc\cleanup.ps1" -ScenarioId P01 -Execute

Replace P01 with P02 or P03 to select another scenario.

Cleanup removes Binding, Consumer and Filter in that order.

## 8. Safety

- Execute only inside an authorized Windows VM.
- Keep a clean snapshot for rollback.
- Use harmless marker actions only.
- Do not use Internet C2, credential theft or exfiltration.
- Do not disable Windows Firewall or Defender.
- Clean up subscriptions after testing.
## 9. Current Limitations

- The PoC Generator supports LogFileEventConsumer and NTEventLogEventConsumer.
- P01 and P03 use the same Notepad process-start trigger.
- The Scenario Runner uses a fixed 5-second delay to verify markers.
- PASSED/FAILED indicates PoC execution, not intrusion detection accuracy.
- Failures before marker verification may not produce a result JSON.
- Windows Event Log source "WMI-Lab-Test" must be registered before running P03.
- Further integration testing with TV2, TV3 and TV4 is required.
