# ═══════════════════════════════════════════════════════════════
#  PiQrypt v1.7.0 — Legacy Demo (demo_piqrypt_live.py)
#  10 agents : trading / compliance / rogue / shadow
#  Usage : .\start_legacy.ps1
# ═══════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "  PiQrypt Legacy Demo — Trading / Compliance / Rogue" -ForegroundColor Cyan
Write-Host ""

# ── Reset données locales ─────────────────────────────────────
Write-Host "  Resetting .piqrypt..." -ForegroundColor Cyan
Remove-Item -Recurse -Force "$env:USERPROFILE\.piqrypt" -ErrorAction SilentlyContinue
Write-Host "  Done." -ForegroundColor Green

# ── Variables d'environnement ─────────────────────────────────
$env:VIGIL_DEV_DELETE  = "1"
$env:VIGIL_TOKEN       = "test_token_local_dev"
$env:PIQRYPT_SCRYPT_N  = "16384"
$env:VIGIL_NO_BROWSER  = "1"

# ── Stack dans une nouvelle fenêtre ──────────────────────────
Write-Host "  Starting stack..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "`$env:VIGIL_DEV_DELETE='1'; `$env:VIGIL_TOKEN='test_token_local_dev'; `$env:PIQRYPT_SCRYPT_N='16384'; `$env:VIGIL_NO_BROWSER='1'; python piqrypt_start.py --vigil"
)

# ── Attendre le stack ─────────────────────────────────────────
Write-Host "  Waiting for stack (10s)..." -ForegroundColor DarkGray
Start-Sleep -Seconds 10

# ── Reset des deux démos puis lancer legacy ───────────────────
Write-Host "  Starting legacy demo..." -ForegroundColor Cyan
$demoCmd = "python demos\demo_piqrypt_live.py --reset; python demos\demo_families.py --reset; Start-Sleep -Seconds 2; python demos\demo_piqrypt_live.py --loop --fast"
Start-Process powershell -ArgumentList @("-NoExit", "-Command", $demoCmd)

# ── Ouvrir Vigil une seule fois ───────────────────────────────
Start-Sleep -Seconds 3
Start-Process "http://localhost:8421/?token=test_token_local_dev"

Write-Host ""
Write-Host "  OK Stack running" -ForegroundColor Green
Write-Host "  OK Legacy demo (10 agents)" -ForegroundColor Green
Write-Host "  OK Vigil : http://localhost:8421" -ForegroundColor Green
Write-Host ""
