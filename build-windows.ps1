$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    Write-Host "Python for Windows was not found." -ForegroundColor Red
    Write-Host "Install Python 3.12+ from python.org and enable the Python launcher (py.exe), then run this script again."
    exit 1
}

if (-not (Test-Path ".venv")) {
    py -3 -m venv .venv
}

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$pyinstaller = Join-Path $PSScriptRoot ".venv\Scripts\pyinstaller.exe"

& $python -m pip install --upgrade pip pyinstaller
& $pyinstaller --noconsole --onefile --clean --name "BLACKBOX" --icon "assets\icon.ico" "blackbox_desktop.pyw"

Write-Host ""
Write-Host "Built: $PSScriptRoot\dist\BLACKBOX.exe" -ForegroundColor Green
Write-Host "You can copy that EXE anywhere on this Windows PC."
