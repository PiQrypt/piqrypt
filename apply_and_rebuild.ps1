# ============================================================
#  PiQrypt — Appliquer corrections v1.7.9 + rebuild + republier
#  Depuis : C:\Users\julie\Documents\Papa\Github\piqrypt
#
#  Usage : .\apply_and_rebuild.ps1
#          .\apply_and_rebuild.ps1 -SkipPublish   # build sans publier
# ============================================================

param([switch]$SkipPublish)

$ROOT = "C:\Users\julie\Documents\Papa\Github\piqrypt"
Set-Location $ROOT

function OK   { param($msg) Write-Host "  [OK]  $msg" -ForegroundColor Green }
function FAIL { param($msg) Write-Host "  [FAIL] $msg" -ForegroundColor Red }
function INFO { param($msg) Write-Host "  [...]  $msg" -ForegroundColor Cyan }
function SEP  { Write-Host "  ──────────────────────────────────────────────" -ForegroundColor DarkGray }
function SECTION { param($t) Write-Host ""; Write-Host "  ═══ $t ═══" -ForegroundColor White; SEP }

# ── ÉTAPE 1 : Créer piqrypt/__init__.py ──────────────────────────────────────
SECTION "1. Création piqrypt/__init__.py"

if (-not (Test-Path "piqrypt")) {
    New-Item -ItemType Directory -Force -Path "piqrypt" | Out-Null
    OK "Dossier piqrypt/ créé"
} else {
    INFO "Dossier piqrypt/ existant"
}

$initContent = @'
# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
PiQrypt — Trust & Continuity Layer for Autonomous AI Agents
AISS v2.0 Reference Implementation
"""

__version__ = "1.7.9"
__author__ = "PiQrypt Inc."
__email__ = "contact@piqrypt.com"
__license__ = "Elastic-2.0"
__url__ = "https://piqrypt.com"

try:
    from aiss import (  # noqa: F401
        generate_keypair,
        derive_agent_id,
        stamp_event,
        stamp_genesis_event,
        verify_signature,
        verify_event,
        export_identity,
    )
    from aiss.license import (  # noqa: F401
        get_tier,
        get_license_info,
        activate_license,
        is_pro,
    )
except ImportError:
    pass

__all__ = [
    "__version__",
    "generate_keypair", "derive_agent_id",
    "stamp_event", "stamp_genesis_event",
    "verify_signature", "verify_event",
    "export_identity",
    "get_tier", "get_license_info", "activate_license", "is_pro",
]
'@

$initContent | Out-File -FilePath "piqrypt\__init__.py" -Encoding utf8
OK "piqrypt/__init__.py écrit"

# Vérifier
$ver = python -c "import sys; sys.path.insert(0, '.'); import piqrypt; print(piqrypt.__version__)" 2>&1
if ($LASTEXITCODE -eq 0) {
    OK "import piqrypt local → version $ver"
} else {
    FAIL "import piqrypt local échoue : $ver"
}

# ── ÉTAPE 2 : Créer piqrypt/py.typed ─────────────────────────────────────────
SECTION "2. py.typed (PEP 561)"
"" | Out-File -FilePath "piqrypt\py.typed" -Encoding utf8
OK "piqrypt/py.typed créé"

# ── ÉTAPE 3 : Vérifier pyproject.toml ────────────────────────────────────────
SECTION "3. Vérification pyproject.toml"

$pyproj = Get-Content "pyproject.toml" -Raw

# Vérifier que piqrypt* est dans find.include
if ($pyproj -match '"piqrypt\*"') {
    OK "piqrypt* déjà dans packages.find.include"
} else {
    INFO "Ajout de piqrypt* dans packages.find.include..."
    # Remplacement de la section include
    $pyproj = $pyproj -replace '(include = \[)', '$1
    "piqrypt*",'
    $pyproj | Out-File -FilePath "pyproject.toml" -Encoding utf8
    OK "piqrypt* ajouté à packages.find.include"
}

# Vérifier que "piqrypt" est dans package-data
if ($pyproj -match '"piqrypt"') {
    OK "piqrypt dans package-data"
} else {
    INFO "Ajout de piqrypt dans package-data..."
    $pyproj = $pyproj -replace '(\[tool\.setuptools\.package-data\])', '$1
"piqrypt"   = ["py.typed"]'
    $pyproj | Out-File -FilePath "pyproject.toml" -Encoding utf8
    OK "piqrypt ajouté à package-data"
}

# ── ÉTAPE 4 : Nettoyage dist/ ────────────────────────────────────────────────
SECTION "4. Nettoyage dist/"
if (Test-Path "dist") {
    Remove-Item -Recurse -Force "dist"
    OK "dist/ supprimé"
}
if (Test-Path "build") {
    Remove-Item -Recurse -Force "build"
    OK "build/ supprimé"
}
Get-ChildItem -Filter "*.egg-info" -Directory | Remove-Item -Recurse -Force
OK "*.egg-info supprimés"

# ── ÉTAPE 5 : Build ──────────────────────────────────────────────────────────
SECTION "5. Build wheel + sdist"
INFO "pip install build..."
python -m pip install --upgrade build --quiet

INFO "python -m build..."
python -m build 2>&1 | Tee-Object -Variable buildOut | Out-Null

if ($LASTEXITCODE -eq 0) {
    $wheel = Get-ChildItem "dist\*.whl" | Select-Object -First 1
    $sdist = Get-ChildItem "dist\*.tar.gz" | Select-Object -First 1
    OK "Build réussi"
    INFO "Wheel : $($wheel.Name) ($([math]::Round($wheel.Length/1KB, 0)) KB)"
    INFO "SDist : $($sdist.Name) ($([math]::Round($sdist.Length/1KB, 0)) KB)"
} else {
    FAIL "Build échoué"
    Write-Host $buildOut -ForegroundColor Red
    exit 1
}

# ── ÉTAPE 6 : Vérifier contenu du wheel ──────────────────────────────────────
SECTION "6. Vérification contenu du wheel"
INFO "Inspection du wheel..."

$wheelPath = (Get-ChildItem "dist\*.whl" | Select-Object -First 1).FullName
$wheelContent = python -c @"
import zipfile, sys
with zipfile.ZipFile(r'$wheelPath') as z:
    names = z.namelist()
    checks = {
        'piqrypt/__init__.py':          any('piqrypt/__init__' in n for n in names),
        'aiss/__init__.py':             any('aiss/__init__' in n for n in names),
        'vigil/vigil_server.py':        any('vigil/vigil_server' in n for n in names),
        'vigil/vigil_v4_final.html':    any('vigil_v4_final.html' in n for n in names),
        'trustgate/trustgate_server.py':any('trustgate/trustgate_server' in n for n in names),
        'cli/piqrypt_start.py':         any('cli/piqrypt_start' in n for n in names),
        'cli/auth_middleware.py':       any('cli/auth_middleware' in n for n in names),
    }
    for k, v in checks.items():
        print(f'{k}={"PRESENT" if v else "ABSENT"}')
"@ 2>&1

$allPresent = $true
$wheelContent | ForEach-Object {
    if ($_ -match "=PRESENT") {
        OK $_
    } elseif ($_ -match "=ABSENT") {
        FAIL "MANQUANT dans wheel : $_"
        $allPresent = $false
    } else {
        INFO $_
    }
}

if (-not $allPresent) {
    FAIL "Des fichiers critiques manquent dans le wheel — ne pas publier"
    exit 1
}

# ── ÉTAPE 7 : Test install local depuis wheel ─────────────────────────────────
SECTION "7. Test install local depuis wheel (venv isolé)"

$testVenv = "$env:TEMP\piqrypt_verify_$(Get-Random)"
python -m venv $testVenv 2>&1 | Out-Null
$testPY = "$testVenv\Scripts\python.exe"

INFO "Installation depuis le wheel local..."
& "$testVenv\Scripts\pip.exe" install $wheelPath --quiet 2>&1 | Out-Null

$testResult = & $testPY -c @"
import piqrypt
print(f'version={piqrypt.__version__}')
from aiss import generate_keypair, derive_agent_id, stamp_genesis_event, verify_signature
from aiss.chain import compute_event_hash
priv, pub = generate_keypair()
aid = derive_agent_id(pub)
g = stamp_genesis_event(priv, pub, aid, {'test': True})
ok = verify_signature(g, pub)
print(f'import_piqrypt=OK')
print(f'crypto={"OK" if ok else "FAIL"}')

# Vérifier que vigil_server est localisable
from pathlib import Path
pkg = Path(piqrypt.__file__).parent
vigil_html = pkg.parent / 'vigil' / 'vigil_v4_final.html'
vigil_srv  = pkg.parent / 'vigil' / 'vigil_server.py'
print(f'vigil_html={"PRESENT" if vigil_html.exists() else "ABSENT"}')
print(f'vigil_server={"PRESENT" if vigil_srv.exists() else "ABSENT"}')
"@ 2>&1

$testResult | ForEach-Object {
    if ($_ -match "=OK|=PRESENT") { OK $_ }
    elseif ($_ -match "=FAIL|=ABSENT") { FAIL $_ }
    else { INFO $_ }
}

Remove-Item -Recurse -Force $testVenv -ErrorAction SilentlyContinue

# ── ÉTAPE 8 : Commit Git ─────────────────────────────────────────────────────
SECTION "8. Commit Git"
git add piqrypt/__init__.py piqrypt/py.typed pyproject.toml 2>&1 | Out-Null
git status --short
$commitMsg = "feat: add piqrypt/ module package — fixes import piqrypt from PyPI"
git commit -m $commitMsg 2>&1
if ($LASTEXITCODE -eq 0) {
    OK "Commit : $commitMsg"
} else {
    INFO "Pas de changement à commiter (déjà en place ?)"
}

# ── ÉTAPE 9 : Publication PyPI ───────────────────────────────────────────────
SECTION "9. Publication PyPI"
if ($SkipPublish) {
    INFO "Publication ignorée (-SkipPublish)"
    INFO "Pour publier manuellement : twine upload dist/*"
} else {
    INFO "Publication sur PyPI..."
    INFO "(nécessite twine + credentials PyPI)"
    python -m pip install --upgrade twine --quiet
    python -m twine upload dist/* 2>&1
    if ($LASTEXITCODE -eq 0) {
        OK "Publié sur PyPI — https://pypi.org/project/piqrypt/"
    } else {
        FAIL "Publication échouée — vérifiez vos credentials PyPI"
    }
}

Write-Host ""
Write-Host "  ════════════════════════════════════════════════" -ForegroundColor White
Write-Host "  CORRECTIONS APPLIQUÉES — PiQrypt v1.7.9" -ForegroundColor White
Write-Host "  ════════════════════════════════════════════════" -ForegroundColor White
Write-Host ""
Write-Host "  Fichiers créés/modifiés :" -ForegroundColor Cyan
Write-Host "    piqrypt/__init__.py   — nouveau module piqrypt" -ForegroundColor White
Write-Host "    piqrypt/py.typed      — marker PEP 561" -ForegroundColor White
Write-Host "    pyproject.toml        — piqrypt* dans find + package-data" -ForegroundColor White
Write-Host ""
Write-Host "  Relancer le test complet :" -ForegroundColor Cyan
Write-Host "    .\test_piqrypt_pypi.ps1" -ForegroundColor White
Write-Host ""
