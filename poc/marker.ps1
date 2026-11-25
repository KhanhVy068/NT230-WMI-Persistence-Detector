$ProjectRoot = Split-Path -Parent $PSScriptRoot
$MarkerPath = Join-Path $ProjectRoot "results\marker.log"

if (-not (Test-Path (Split-Path $MarkerPath -Parent))) {
    New-Item -ItemType Directory -Path (Split-Path $MarkerPath -Parent) -Force | Out-Null
}

Add-Content -Path $MarkerPath -Value "WMI_POC_SUCCESS"