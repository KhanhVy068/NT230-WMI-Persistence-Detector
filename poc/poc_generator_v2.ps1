# WMI Persistence Detection Project
# TV1 - PoC Generator P01


param(
    [ValidateSet("P01", "P02", "P03")]
    [string]$ScenarioId = "P01"
)

# Read scenario configuration
$ConfigPath = Join-Path $PSScriptRoot "scenarios\$ScenarioId.json"

if (-not (Test-Path $ConfigPath)) {
    throw "Scenario configuration not found: $ConfigPath"
}

$Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

if ($Config.scenario_id -ne $ScenarioId) {
    throw "Scenario ID does not match!"
}

# Scenario variables
$Namespace = $Config.namespace
$FilterName = $Config.filter_name
$ConsumerType = $Config.consumer_type
$ConsumerName = [string]$Config.consumer_name
$ProjectRoot = Split-Path -Parent $PSScriptRoot

$MarkerPath = $Config.marker_path

if ($MarkerPath -and -not [System.IO.Path]::IsPathRooted($MarkerPath)) {
    $MarkerPath = Join-Path $ProjectRoot $MarkerPath
}
$WqlQuery = $Config.query

# Event Filter configuration
$FilterConfig = @{
    Name = $FilterName
    EventNamespace = $Config.event_namespace
    QueryLanguage = $Config.query_language
    Query = $WqlQuery
}

# Event Consumer configuration
switch ($ConsumerType) {
    "LogFileEventConsumer" {
        $ConsumerConfig = @{
            Name = $ConsumerName
            Filename = $MarkerPath
            Text = $Config.marker_text
        }
    }

    "NTEventLogEventConsumer" {
        $ConsumerConfig = @{
            Name = $ConsumerName
            SourceName = $Config.event_source
            EventID = [uint32]$Config.event_id
            EventType = [uint32]$Config.event_type
            Category = [uint16]$Config.event_category
            NumberOfInsertionStrings = [uint32]1
            InsertionStringTemplates = [string[]]@($Config.marker_text)
        }
    }

    default {
        throw "Unsupported Consumer Type: $ConsumerType"
    }
}

# Binding configuration
$BindingConfig = @{
    FilterName = $FilterName
    ConsumerName = $ConsumerName
    Namespace = $Namespace
}

Write-Host "=== WMI PoC Generator ==="
Write-Host "Scenario: $ScenarioId"
Write-Host "Namespace: $Namespace"
Write-Host "Filter: $FilterName"
Write-Host "Consumer: $ConsumerName"
Write-Host "Consumer Type: $ConsumerType"
Write-Host "WQL: $WqlQuery"

Write-Host "=== Event Filter Configuration ==="
$FilterConfig | Format-List
Write-Host "=== Event Consumer Configuration ==="
$ConsumerConfig | Format-List
Write-Host "=== Binding Configuration ==="
$BindingConfig | Format-List

# Create Event Filter for P01
Write-Host "=== Creating Event Filter ==="

$ExistingFilter = Get-CimInstance -Namespace $Namespace -ClassName "__EventFilter" -Filter "Name='$FilterName'"

if ($null -eq $ExistingFilter) {
    $NewFilter = New-CimInstance -Namespace $Namespace -ClassName "__EventFilter" -Property $FilterConfig
    Write-Host "Event Filter created successfully!"
} else {
    Write-Host "Event Filter already exists!"
}

# Create Event Consumer for P01
Write-Host "=== Creating Event Consumer ==="

$ExistingConsumer = Get-CimInstance -Namespace $Namespace -ClassName $ConsumerType -Filter "Name='$ConsumerName'"

if ($null -eq $ExistingConsumer) {
$ConsumerClass = Get-CimClass -Namespace $Namespace -ClassName $ConsumerType -ErrorAction Stop
$NewConsumer = New-CimInstance -CimClass $ConsumerClass -Property $ConsumerConfig -ErrorAction Stop
    Write-Host "Event Consumer created successfully!"
} else {
    Write-Host "Event Consumer already exists!"
}


# Create Filter-to-Consumer Binding
Write-Host "=== Creating Binding ==="

$FilterObject = Get-CimInstance -Namespace $Namespace -ClassName "__EventFilter" -Filter "Name='$FilterName'"
$ConsumerObject = Get-CimInstance -Namespace $Namespace -ClassName $ConsumerType -Filter "Name='$ConsumerName'" -ErrorAction Stop

if ($null -eq $FilterObject -or $null -eq $ConsumerObject) {
    throw "Filter or Consumer does not exist!"
}

$ExistingBinding = Get-CimInstance -Namespace $Namespace -ClassName "__FilterToConsumerBinding" | Where-Object { $_.Filter.Name -eq $FilterName -and $_.Consumer.Name -eq $ConsumerName }

if ($null -eq $ExistingBinding) {
    $BindingProperties = @{
        Filter = [ref]$FilterObject
        Consumer = [ref]$ConsumerObject
    }

    $NewBinding = New-CimInstance -Namespace $Namespace -ClassName "__FilterToConsumerBinding" -Property $BindingProperties -ErrorAction Stop
    Write-Host "Binding created successfully!"
} else {
    Write-Host "Binding already exists!"
}