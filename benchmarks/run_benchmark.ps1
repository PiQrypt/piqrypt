# ============================================================
# PiQrypt — Benchmark complet
# Ouvre venv, installe, mesure, ferme, nettoie
# Usage: .\run_benchmark.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$VENV_DIR = ".\venv_bench"
$BENCH_SCRIPT = "benchmark_pcp.py"
$RESULTS_DIR = ".\benchmark_results"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  PiQrypt Benchmark Runner" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Créer le venv ─────────────────────────────────────────
Write-Host "[1/5] Creation du venv..." -ForegroundColor Yellow
python -m venv $VENV_DIR
if ($LASTEXITCODE -ne 0) { Write-Host "ERREUR: python -m venv a echoue" -ForegroundColor Red; exit 1 }
Write-Host "      OK: $VENV_DIR cree" -ForegroundColor Green

# ── 2. Activer le venv ───────────────────────────────────────
Write-Host "[2/5] Activation du venv..." -ForegroundColor Yellow
$PIP  = "$VENV_DIR\Scripts\pip.exe"
$PY   = "$VENV_DIR\Scripts\python.exe"
if (-not (Test-Path $PY)) {
    Write-Host "ERREUR: python.exe introuvable dans $VENV_DIR\Scripts" -ForegroundColor Red
    exit 1
}
Write-Host "      OK: venv active" -ForegroundColor Green

# ── 3. Installer piqrypt ─────────────────────────────────────
Write-Host "[3/5] Installation de piqrypt..." -ForegroundColor Yellow
& $PIP install --upgrade pip --quiet
& $PIP install piqrypt --quiet
if ($LASTEXITCODE -ne 0) { Write-Host "ERREUR: pip install piqrypt a echoue" -ForegroundColor Red; exit 1 }
$version = & $PY -c "import piqrypt; print(getattr(piqrypt, '__version__', 'unknown'))"
Write-Host "      OK: piqrypt $version installe" -ForegroundColor Green

# ── 4. Lancer le benchmark ───────────────────────────────────
Write-Host "[4/5] Lancement du benchmark..." -ForegroundColor Yellow
Write-Host ""

if (-not (Test-Path $BENCH_SCRIPT)) {
    Write-Host "ERREUR: $BENCH_SCRIPT introuvable dans le repertoire courant" -ForegroundColor Red
    Write-Host "       Placez benchmark_pcp.py dans le meme dossier que ce script" -ForegroundColor Red
    exit 1
}

& $PY $BENCH_SCRIPT
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERREUR: le benchmark a echoue" -ForegroundColor Red
    exit 1
}

# ── Sauvegarder les résultats ────────────────────────────────
if (-not (Test-Path $RESULTS_DIR)) { New-Item -ItemType Directory -Path $RESULTS_DIR | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

if (Test-Path "benchmark_results.json") {
    Copy-Item "benchmark_results.json" "$RESULTS_DIR\benchmark_results_$timestamp.json"
    Write-Host "      Resultats JSON sauvegardes dans $RESULTS_DIR" -ForegroundColor Green
}
if (Test-Path "benchmark_report.txt") {
    Copy-Item "benchmark_report.txt"   "$RESULTS_DIR\benchmark_report_$timestamp.txt"
    Write-Host "      Rapport TXT sauvegarde dans $RESULTS_DIR" -ForegroundColor Green
}

# ── 5. Nettoyage ─────────────────────────────────────────────
Write-Host ""
Write-Host "[5/5] Nettoyage..." -ForegroundColor Yellow

# Supprimer les fichiers temporaires locaux
@("benchmark_results.json", "benchmark_report.txt") | ForEach-Object {
    if (Test-Path $_) { Remove-Item $_ -Force }
}

# Supprimer le venv
if (Test-Path $VENV_DIR) {
    Remove-Item $VENV_DIR -Recurse -Force
    Write-Host "      OK: venv supprime" -ForegroundColor Green
}

# ── Résumé final ─────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Benchmark termine." -ForegroundColor Cyan
Write-Host "  Resultats dans : $RESULTS_DIR\" -ForegroundColor Cyan
Write-Host "  Copiez les chiffres dans la section 11 du paper arXiv." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
