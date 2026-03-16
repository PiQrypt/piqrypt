# ===============================================================
#  PiQrypt v1.7.1 -- PiQrypt -- Pro
#  Usage : .\start_pro.ps1
# ===============================================================

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

# -- Features ----------------------------------------------------
Write-Host ""
Write-Host "  PiQrypt -- Pro" -ForegroundColor Cyan
Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Vigil     : Complet -- exports, alertes, enregistrement live" -ForegroundColor Green
Write-Host "  TrustGate : Manuel -- validation humaine (file d'attente)" -ForegroundColor Green
Write-Host "  Alertes     : tous niveaux (CRITICAL/HIGH/MEDIUM/LOW)" -ForegroundColor DarkGray
Write-Host "  Historique  : 90 jours" -ForegroundColor DarkGray
Write-Host "  Bridges     : illimites (9 types)" -ForegroundColor DarkGray
Write-Host "  Exports     : .pqz certifie + PDF" -ForegroundColor DarkGray
Write-Host "  Crypto      : Dilithium3 PQ + RFC 3161 TSA" -ForegroundColor DarkGray
Write-Host "  Agents max  : 50  --  Events/mois : 500 000" -ForegroundColor DarkGray
Write-Host ""

# -- Licence -----------------------------------------------------
$licenseFile = "$ROOT\.env.piqrypt"

if (Test-Path $licenseFile) {
    Get-Content $licenseFile | ForEach-Object {
        if ($_ -match "^PIQRYPT_LICENSE_KEY=(.+)$") { $env:PIQRYPT_LICENSE_KEY = $matches[1].Trim() }
        if ($_ -match "^VIGIL_TOKEN=(.+)$")         { $env:VIGIL_TOKEN         = $matches[1].Trim() }
        if ($_ -match "^TRUSTGATE_TOKEN=(.+)$")     { $env:TRUSTGATE_TOKEN     = $matches[1].Trim() }
        if ($_ -match "^VIGIL_HOST=(.+)$")          { $env:VIGIL_HOST          = $matches[1].Trim() }
        if ($_ -match "^TRUSTGATE_HOST=(.+)$")      { $env:TRUSTGATE_HOST      = $matches[1].Trim() }
    }
}

if (-not $env:PIQRYPT_LICENSE_KEY) {
    Write-Host "  Cle de licence non trouvee dans .env.piqrypt" -ForegroundColor Yellow
    Write-Host "  (recue par email apres achat sur piqrypt.com)" -ForegroundColor DarkGray
    Write-Host ""
    $env:PIQRYPT_LICENSE_KEY = Read-Host "  Entrez votre cle de licence PiQrypt"
    if (-not $env:PIQRYPT_LICENSE_KEY) {
        Write-Host "  Cle manquante -- arret." -ForegroundColor Red
        exit 1
    }
    $save = Read-Host "  Sauvegarder dans .env.piqrypt ? [O/n]"
    if ($save -ne "n") {
        "PIQRYPT_LICENSE_KEY=$($env:PIQRYPT_LICENSE_KEY)" | Out-File -FilePath $licenseFile -Encoding utf8 -Append
        Write-Host "  Sauvegarde. Ne committez jamais .env.piqrypt (dans .gitignore)" -ForegroundColor DarkGray
    }
}

# -- Activation --------------------------------------------------
Write-Host "  Activation licence..." -ForegroundColor Cyan
$result = python -c "
import sys; sys.path.insert(0, '.')
try:
    from aiss.license import activate, get_tier, get_license_info
    activate('$($env:PIQRYPT_LICENSE_KEY)')
    t = get_tier()
    info = get_license_info()
    agents = info.get('agent_limit') or 'illimite'
    events = info.get('events_month_limit') or 'illimite'
    print(f'OK:{t}:{agents}:{events}')
except Exception as e:
    print(f'ERR:{e}')
"

if ($result -match "^OK:([^:]+):([^:]+):(.+)$") {
    $tier   = $matches[1]
    $agents = $matches[2]
    $events = $matches[3]
    Write-Host "  Licence OK -- Tier : $($tier.ToUpper())  |  Agents : $agents  |  Events/mois : $events" -ForegroundColor Green
} else {
    Write-Host "  Erreur activation : $result" -ForegroundColor Red
    Write-Host "  Verifiez votre cle sur https://piqrypt.com/account" -ForegroundColor DarkGray
    exit 1
}

# -- Tokens ------------------------------------------------------
if (-not $env:VIGIL_TOKEN) {
    $env:VIGIL_TOKEN = python -c "import hashlib,os; k=os.getenv('PIQRYPT_LICENSE_KEY',''); print(hashlib.sha256(k.encode()).hexdigest()[:32])"
}
if (-not $env:TRUSTGATE_TOKEN) {
    $env:TRUSTGATE_TOKEN = python -c "import hashlib,os; k=os.getenv('PIQRYPT_LICENSE_KEY','')+'_tg'; print(hashlib.sha256(k.encode()).hexdigest()[:32])"
}
if (-not $env:VIGIL_HOST)     { $env:VIGIL_HOST     = "127.0.0.1" }
if (-not $env:TRUSTGATE_HOST) { $env:TRUSTGATE_HOST = "127.0.0.1" }

# -- Lancement ---------------------------------------------------
Write-Host "  Demarrage stack..." -ForegroundColor Cyan

$stackCmd = "`$env:PIQRYPT_LICENSE_KEY='$($env:PIQRYPT_LICENSE_KEY)'; `$env:VIGIL_TOKEN='$($env:VIGIL_TOKEN)'; `$env:TRUSTGATE_TOKEN='$($env:TRUSTGATE_TOKEN)'; `$env:VIGIL_HOST='$($env:VIGIL_HOST)'; `$env:TRUSTGATE_HOST='$($env:TRUSTGATE_HOST)'; Set-Location '$ROOT'; python piqrypt_start.py --vigil --trustgate"
Start-Process powershell -ArgumentList @("-NoExit", "-Command", $stackCmd)

# -- Attente ports -----------------------------------------------
function Wait-Port {
    param([int]$Port, [string]$Name)
    Write-Host "  Attente $Name..." -ForegroundColor DarkGray -NoNewline
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt 10) {
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

# Vigil en premier
if (Wait-Port -Port 8421 -Name "Vigil") {
    Start-Sleep -Milliseconds 500
    Start-Process "http://localhost:8421/?token=$($env:VIGIL_TOKEN)"
}

# TrustGate ensuite
if (Wait-Port -Port 8422 -Name "TrustGate") {
    Start-Sleep -Seconds 2
    Start-Process "http://localhost:8422/console?token=$($env:TRUSTGATE_TOKEN)"
}

# -- Resume ------------------------------------------------------
Write-Host ""
Write-Host "  ================================================" -ForegroundColor Cyan
Write-Host "  PiQrypt -- Pro -- operationnel" -ForegroundColor Cyan
Write-Host "  ================================================" -ForegroundColor Cyan
Write-Host "  Vigil     : http://localhost:8421" -ForegroundColor White
Write-Host "  TrustGate : http://localhost:8422" -ForegroundColor White
Write-Host ""
Write-Host "  Docs      : https://piqrypt.com/docs/agents" -ForegroundColor DarkGray
Write-Host "  Support   : piqrypt@gmail.com" -ForegroundColor DarkGray
Write-Host ""
