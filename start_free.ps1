# ===============================================================
#  PiQrypt v1.7.1 -- PiQrypt -- Free
#  Usage : .\start_free.ps1
# ===============================================================

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

# -- Features ----------------------------------------------------
Write-Host ""
Write-Host "  PiQrypt -- Free" -ForegroundColor Cyan
Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Vigil     : Dashboard + monitoring (lecture/ecriture)" -ForegroundColor Green
Write-Host "  TrustGate : non disponible -- upgrade Pro" -ForegroundColor DarkGray
Write-Host "  Alertes     : CRITICAL uniquement" -ForegroundColor DarkGray
Write-Host "  Historique  : 7 jours" -ForegroundColor DarkGray
Write-Host "  Bridges     : 2 types max" -ForegroundColor DarkGray
Write-Host "  Exports     : PDF local (non certifie)" -ForegroundColor DarkGray
Write-Host "  Agents max  : 3  --  Events/mois : 10 000" -ForegroundColor DarkGray
Write-Host ""

# -- Token local (genere automatiquement, pas de cle requise) ----
$tokenFile = "$env:USERPROFILE\.piqrypt\.vigil_token"

if (Test-Path $tokenFile) {
    $env:VIGIL_TOKEN = (Get-Content $tokenFile -Raw).Trim()
    Write-Host "  Token     : charge depuis cache" -ForegroundColor DarkGray
} else {
    $env:VIGIL_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
    New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.piqrypt" | Out-Null
    $env:VIGIL_TOKEN | Out-File -FilePath $tokenFile -Encoding utf8 -NoNewline
    Write-Host "  Token     : genere et sauvegarde" -ForegroundColor Green
}

if (-not $env:VIGIL_HOST) { $env:VIGIL_HOST = "127.0.0.1" }

# -- Lancement ---------------------------------------------------
Write-Host "  Demarrage stack..." -ForegroundColor Cyan

$stackCmd = "`$env:VIGIL_TOKEN='$($env:VIGIL_TOKEN)'; `$env:VIGIL_HOST='$($env:VIGIL_HOST)'; Set-Location '$ROOT'; python piqrypt_start.py --vigil"
Start-Process powershell -ArgumentList @("-NoExit", "-Command", $stackCmd)

# -- Attente port ------------------------------------------------
function Wait-Port {
    param([int]$Port, [string]$Name)
    Write-Host "  Attente $Name..." -ForegroundColor DarkGray -NoNewline
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt 15) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.Connect("127.0.0.1", $Port)
            $tcp.Close()
            Write-Host " pret" -ForegroundColor Green
            return $true
        } catch { Start-Sleep -Milliseconds 300 }
    }
    Write-Host " timeout" -ForegroundColor Red
    return $false
}

if (Wait-Port -Port 8421 -Name "Vigil") {
    Start-Sleep -Milliseconds 500
    Start-Process "http://localhost:8421/?token=$($env:VIGIL_TOKEN)"
}

# -- Resume ------------------------------------------------------
Write-Host ""
Write-Host "  ================================================" -ForegroundColor Cyan
Write-Host "  PiQrypt -- Free -- operationnel" -ForegroundColor Cyan
Write-Host "  ================================================" -ForegroundColor Cyan
Write-Host "  Vigil     : http://localhost:8421" -ForegroundColor White
Write-Host "  TrustGate : upgrade Pro pour activer" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Docs      : https://piqrypt.com/docs/agents" -ForegroundColor DarkGray
Write-Host "  Support   : piqrypt@gmail.com" -ForegroundColor DarkGray
Write-Host ""
