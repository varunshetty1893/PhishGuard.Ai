Write-Host "=======================================================================" -ForegroundColor Cyan
Write-Host "  PHISHGUARD AI - ONE-COMMAND REPRODUCIBILITY & EVALUATION SUITE" -ForegroundColor Cyan
Write-Host "=======================================================================" -ForegroundColor Cyan

# Check if venv exists
if (Test-Path "backend\venv\Scripts\python.exe") {
    $PYTHON = "backend\venv\Scripts\python.exe"
} else {
    $PYTHON = "python"
}

Write-Host "[*] Executing full reproducibility pipeline with $PYTHON..." -ForegroundColor Yellow
& $PYTHON "scripts\reproduce_all.py"
