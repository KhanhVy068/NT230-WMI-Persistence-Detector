
param(
    [ValidateSet("P01", "P02", "P03")]
    [string]$ScenarioId = "P01"
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ConfigPath = Join-Path $ProjectRoot "poc\scenarios\$ScenarioId.json"
$GeneratorPath = Join-Path $ProjectRoot "poc\poc_generator_v2.ps1"

if (-not (Test-Path $ConfigPath)) {
    throw "Scenario configuration not found: $ConfigPath"
}

if (-not (Test-Path $GeneratorPath)) {
    throw "PoC Generator not found: $GeneratorPath"
}

$Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

if ($Config.scenario_id -ne $ScenarioId) {
    throw "Scenario ID mismatch!"
}

Write-Host "=== WMI Scenario Runner ==="
Write-Host "Scenario: $($Config.scenario_id)"
Write-Host "Description: $($Config.description)"
Write-Host "Filter: $($Config.filter_name)"
Write-Host "Consumer: $($Config.consumer_name)"
Write-Host "Marker: $($Config.marker_path)"
Write-Host "Generator: $GeneratorPath"

Write-Host "Configuration loaded successfully."

# Run PoC Generator
Write-Host "=== Running PoC Generator ==="

& $GeneratorPath -ScenarioId $ScenarioId

if (-not $?) {
    throw "PoC Generator failed!"
}

Write-Host "PoC Generator executed."


# Verify WMI Subscription
Write-Host "=== Verifying WMI Subscription ==="

$Namespace = $Config.namespace
$FilterName = $Config.filter_name
$ConsumerName = $Config.consumer_name
$ConsumerType = [string]$Config.consumer_type
$Filter = Get-CimInstance -Namespace $Namespace -ClassName "__EventFilter" -Filter "Name='$FilterName'"

$Consumer = Get-CimInstance -Namespace $Namespace -ClassName $ConsumerType -Filter "Name='$ConsumerName'"

$Bindings = @(Get-CimInstance -Namespace $Namespace -ClassName "__FilterToConsumerBinding" | Where-Object { $_.Filter.Name -eq $FilterName -and $_.Consumer.Name -eq $ConsumerName })

if ($null -eq $Filter) {
    throw "Event Filter verification failed!"
}

if ($null -eq $Consumer) {
    throw "Event Consumer verification failed!"
}

if ($Bindings.Count -ne 1) {
    throw "Binding verification failed! Count: $($Bindings.Count)"
}

Write-Host "Event Filter: OK"
Write-Host "Event Consumer: OK"
Write-Host "Binding: OK"
Write-Host "WMI Subscription verified successfully."

# Trigger event and verify marker
Write-Host "=== Testing Event Trigger ==="

$MarkerPath = $Config.marker_path

if ($MarkerPath -and -not [System.IO.Path]::IsPathRooted($MarkerPath)) {
    $MarkerPath = Join-Path $ProjectRoot $MarkerPath
}
$MarkerText = $Config.marker_text

# Count matching markers before the test
$BeforeCount = 0

if ($ConsumerType -eq "NTEventLogEventConsumer") {
    $BeforeCount = @(
        Get-WinEvent -FilterHashtable @{
            LogName = "Application"
            ProviderName = $Config.event_source
            Id = [int]$Config.event_id
        } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -eq $MarkerText }
    ).Count
}
else {
    if (Test-Path $MarkerPath) {
        $BeforeCount = @(
            Get-Content $MarkerPath |
            Where-Object { $_ -eq $MarkerText }
        ).Count
    }
}

Write-Host "Marker count before: $BeforeCount"

# Trigger the selected scenario
switch ($ScenarioId) {
    "P01" {
        Start-Process "C:\Windows\System32\notepad.exe"
    }
  "P02" {
    $CalcPath = "C:\Windows\System32\calc.exe"

    if (-not (Test-Path $CalcPath)) {
        throw "Calculator executable not found: $CalcPath"
    }

    Start-Process -FilePath $CalcPath
}
    
    "P03" {
        Start-Process "C:\Windows\System32\notepad.exe"
    }
}

# Allow WMI to process the event
Start-Sleep -Seconds 5

# Count matching markers after the test
$AfterCount = 0

if ($ConsumerType -eq "NTEventLogEventConsumer") {
    $AfterCount = @(
        Get-WinEvent -FilterHashtable @{
            LogName = "Application"
            ProviderName = $Config.event_source
            Id = [int]$Config.event_id
        } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -eq $MarkerText }
    ).Count
}
else {
    if (Test-Path $MarkerPath) {
        $AfterCount = @(
            Get-Content $MarkerPath |
            Where-Object { $_ -eq $MarkerText }
        ).Count
    }
}
Write-Host "Marker count after: $AfterCount"

if ($AfterCount -gt $BeforeCount) {
    $ScenarioStatus = "PASSED"
    Write-Host "Scenario $ScenarioId PASSED!"
} else {
    $ScenarioStatus = "FAILED"
    Write-Host "Scenario $ScenarioId FAILED: No new marker detected."
}


# Save scenario result to JSON
$VerificationSource = if ($ConsumerType -eq "NTEventLogEventConsumer") { "WindowsEventLog" } else { "LogFile" }
Write-Host "=== Saving Scenario Result ==="

$Result = [ordered]@{
    scenario_id = $ScenarioId
    description = $Config.description
    filter_name = $Config.filter_name
    consumer_name = $Config.consumer_name
consumer_type = $ConsumerType
verification_source = $VerificationSource
    marker_path = if ($VerificationSource -eq "LogFile") { $MarkerPath } else { $null }
event_source = if ($VerificationSource -eq "WindowsEventLog") { $Config.event_source } else { $null }
event_id = if ($VerificationSource -eq "WindowsEventLog") { [int]$Config.event_id } else { $null }
    marker_text = $MarkerText
    marker_count_before = $BeforeCount
    marker_count_after = $AfterCount
    new_markers = $AfterCount - $BeforeCount
    status = $ScenarioStatus
    executed_at = (Get-Date).ToString("o")
}

$RunId = (Get-Date).ToString("yyyyMMdd_HHmmss_fffffff")
$ResultPath = Join-Path $ProjectRoot "results\${ScenarioId}_${RunId}_result.json"

$Result | ConvertTo-Json -Depth 5 | Set-Content -Path $ResultPath -Encoding UTF8

Write-Host "Result saved to: $ResultPath"
