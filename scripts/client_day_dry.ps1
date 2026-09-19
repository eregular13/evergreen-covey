# SAMPLE client-day dry: sign (lab HMAC) → ready --strict-e2e → plan (no spawn).
# Optional pack_drop from committed fixtures. SAMPLE ≠ client. No live scan.
# LICENSE-LOCK: never apt-install, never vendor Nmap / masscan / etc.
# DESKTOP (no make / no gh): .\scripts\client_day_dry.ps1
param(
    [string]$Scope = "",
    [string]$Work = "",
    [string]$ExportFrom = "",
    [switch]$NoExport,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if ($Help) {
    Write-Host @"
usage: scripts/client_day_dry.ps1 [-Scope FILE] [-Work DIR] [-ExportFrom DIR] [-NoExport]

One command DESKTOP/client-host dry (no live client scan):
  sign (demo/lab HMAC only) → ready --strict-e2e → plan (no spawn)
  then pack_drop from SAMPLE fixtures if a full assess would need BYO.

Missing BYO fails closed (printed miss list). Never apt-installs scanners.
masscan / arp-scan / netdiscover / zmap stay argv+unit only — ready --strict-e2e refuses them.
SAMPLE ≠ client. No RiskReady. No CTA.
"@
    exit 0
}

if ($env:PYTHON) {
    $Python = $env:PYTHON
} elseif (Test-Path (Join-Path $Root ".venv\Scripts\python.exe")) {
    $Python = Join-Path $Root ".venv\Scripts\python.exe"
} else {
    $Python = "python"
}

$env:PYTHONPATH = (Join-Path $Root "src") + $(if ($env:PYTHONPATH) { ";" + $env:PYTHONPATH } else { "" })

$argv = @("-m", "covey", "client-day-dry")
if (-not [string]::IsNullOrWhiteSpace($Scope)) { $argv += @("--scope", $Scope) }
if (-not [string]::IsNullOrWhiteSpace($Work)) { $argv += @("--work", $Work) }
if (-not [string]::IsNullOrWhiteSpace($ExportFrom)) { $argv += @("--export-from", $ExportFrom) }
if ($NoExport) { $argv += "--no-export" }

& $Python @argv
exit $LASTEXITCODE
