
param(
    [ValidateSet("P01", "P02", "P03")]
    [string]$ScenarioId = "P01",

    [switch]$Execute
)

$ErrorActionPreference = "Stop"

$Namespace = "root/subscription"
$FilterName = "WMI_Lab_Filter_$ScenarioId"
$ConsumerName = "WMI_Lab_Consumer_$ScenarioId"

Write-Host "=== WMI PoC Cleanup ==="
Write-Host "Scenario: $ScenarioId"

# Find Filter and Consumer
$Filter = Get-CimInstance -Namespace $Namespace -ClassName "__EventFilter" -Filter "Name='$FilterName'"
$Consumers = @()

foreach ($ConsumerType in @("LogFileEventConsumer", "NTEventLogEventConsumer")) {
    $Found = @(Get-CimInstance -Namespace $Namespace -ClassName $ConsumerType -Filter "Name='$ConsumerName'")
    $Consumers += $Found
}

# Find the matching Binding
$Bindings = @(Get-CimInstance -Namespace $Namespace -ClassName "__FilterToConsumerBinding" | Where-Object { $_.Filter.Name -eq $FilterName -and $_.Consumer.Name -eq $ConsumerName })

Write-Host "Filter found: $($null -ne $Filter)"
Write-Host "Consumers found: $($Consumers.Count)"
Write-Host "Bindings found: $($Bindings.Count)"

if (-not $Execute) {
    Write-Host "Preview only. No objects were deleted."
    Write-Host "Use -Execute to perform cleanup."
    return
}

# Remove Binding first
foreach ($Binding in $Bindings) {
    $Binding | Remove-CimInstance -ErrorAction Stop
    Write-Host "Binding removed."
}

# Remove Consumer
foreach ($Consumer in $Consumers) {
    $Consumer | Remove-CimInstance -ErrorAction Stop
    Write-Host "Consumer removed: $($Consumer.CimClass.CimClassName)"
}

# Remove Filter
if ($null -ne $Filter) {
    $Filter | Remove-CimInstance -ErrorAction Stop
    Write-Host "Filter removed."
}

Write-Host "Cleanup completed."
