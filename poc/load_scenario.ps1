
param(
    [ValidateSet("P01", "P02", "P03")]
    [string]$ScenarioId = "P01"
)

# Locate the scenario configuration file
$ConfigPath = Join-Path $PSScriptRoot "scenarios\$ScenarioId.json"

# Check if configuration exists
if (-not (Test-Path $ConfigPath)) {
    throw "Scenario configuration not found: $ConfigPath"
}

# Read JSON configuration
$Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

# Validate scenario ID
if ($Config.scenario_id -ne $ScenarioId) {
    throw "Scenario ID does not match configuration!"
}

# Display configuration
Write-Host "=== WMI PoC Scenario Configuration ==="
Write-Host "Scenario: $($Config.scenario_id)"
Write-Host "Description: $($Config.description)"
Write-Host "Namespace: $($Config.namespace)"
Write-Host "Event Namespace: $($Config.event_namespace)"
Write-Host "Filter: $($Config.filter_name)"
Write-Host "Consumer: $($Config.consumer_name)"
Write-Host "Consumer Type: $($Config.consumer_type)"
Write-Host "WQL: $($Config.query)"
Write-Host "Marker Path: $($Config.marker_path)"
Write-Host "Marker Text: $($Config.marker_text)"
