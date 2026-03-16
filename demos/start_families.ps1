param([string]$Family = "")

if ($Family -eq "") {
    Write-Host ""
    Write-Host "  PiQrypt -- Choisissez votre profil" -ForegroundColor Cyan
    Write-Host "  ------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [1]  Nexus Labs   -- DevOps / Infra    (Ollama + LangGraph)" -ForegroundColor Cyan
    Write-Host "  [2]  PixelFlow    -- Createur digital   (CrewAI + Claude Haiku)" -ForegroundColor Magenta
    Write-Host "  [3]  AlphaCore    -- Quant / Trading    (AutoGen + GPT-4o)" -ForegroundColor Yellow
    Write-Host ""
    $choice = Read-Host "  Votre choix [1/2/3]"
    if ($choice -eq "1") { $Family = "nexus" }
    elseif ($choice -eq "2") { $Family = "pixelflow" }
    elseif ($choice -eq "3") { $Family = "alphacore" }
    else { Write-Host "  Choix invalide." -ForegroundColor Red; exit 1 }
}

if ($Family -notin @("nexus","pixelflow","alphacore")) {
    Write-Host "  Famille invalide : $Family" -ForegroundColor Red
    exit 1
}

$labels = @{ nexus="Nexus Labs (DevOps)"; pixelflow="PixelFlow (Digital)"; alphacore="AlphaCore (Trading)" }
Write-Host ""
Write-Host "  >> $($labels[$Family])" -ForegroundColor Green

Write-Host "  Resetting .piqrypt..." -ForegroundColor Cyan
Remove-Item -Recurse -Force "$env:USERPROFILE\.piqrypt" -ErrorAction SilentlyContinue

$env:VIGIL_DEV_DELETE = "1"
$env:VIGIL_TOKEN      = "test_token_local_dev"
$env:PIQRYPT_SCRYPT_N = "16384"
$env:VIGIL_NO_BROWSER = "1"

Write-Host "  Starting stack..." -ForegroundColor Cyan
$stackCmd = "`$env:VIGIL_DEV_DELETE='1'; `$env:VIGIL_TOKEN='test_token_local_dev'; `$env:PIQRYPT_SCRYPT_N='16384'; `$env:VIGIL_NO_BROWSER='1'; python piqrypt_start.py --vigil"
Start-Process powershell -ArgumentList "-NoExit","-Command",$stackCmd

Write-Host "  Waiting for stack (10s)..." -ForegroundColor DarkGray
Start-Sleep -Seconds 10

Write-Host "  Starting demo : $Family..." -ForegroundColor Cyan
$demoCmd = "python demos\demo_piqrypt_live.py --reset; python demos\demo_families.py --reset; Start-Sleep -Seconds 2; python demos\demo_families.py --family $Family --loop --fast"
Start-Process powershell -ArgumentList "-NoExit","-Command",$demoCmd

Start-Sleep -Seconds 3
Start-Process "http://localhost:8421/?token=test_token_local_dev"

Write-Host ""
Write-Host "  OK Stack running" -ForegroundColor Green
Write-Host "  OK Demo : $($labels[$Family])" -ForegroundColor Green
Write-Host "  OK Vigil : http://localhost:8421" -ForegroundColor Green
Write-Host ""
