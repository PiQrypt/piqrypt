import sys
from pathlib import Path

# Force resolution locale de aiss/ en CI (pip install -e . avec importlib)
# Meme pattern que vigil_server.py et cli/piqrypt_start.py
_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Diagnostic CI
try:
    import aiss as _aiss_diag
    print(f"[conftest] aiss.__file__ = {getattr(_aiss_diag, '__file__', 'NO __file__')}")
    print(f"[conftest] aiss.__path__ = {getattr(_aiss_diag, '__path__', 'NO __path__')}")
    print(f"[conftest] sys.path[0:3] = {sys.path[0:3]}")
except Exception as e:
    print(f"[conftest] aiss import error: {e}")

# SPDX-License-Identifier: MIT
"""
Configuration pytest — PiQrypt v1.7.1

Les bridges nécessitent des packages optionnels (crewai, langchain, etc.) non
disponibles dans tous les environnements CI. Ce conftest.py gère le skip
conditionnel pour éviter les erreurs de collection.
"""

import sys
from pathlib import Path

# Ajouter les répertoires bridges au sys.path pour les modules locaux
_BRIDGES_DIR = Path(__file__).parent / "bridges"
for _bridge_dir in _BRIDGES_DIR.iterdir():
    if _bridge_dir.is_dir() and str(_bridge_dir) not in sys.path:
        sys.path.insert(0, str(_bridge_dir))

collect_ignore_glob = []

# autogen : lève ImportError au niveau package — ignorer inconditionnellement
collect_ignore_glob.append("bridges/autogen/*")

# Bridges avec dépendances optionnelles — skippés si la dépendance est absente
_BRIDGE_DEPS = {
    "bridges/crewai":    "crewai",
    "bridges/langchain": "langchain",
    "bridges/mcp":       "mcp",
    "bridges/ollama":    "ollama",
    "bridges/openclaw":  None,   # module local — path ajouté via sys.path ci-dessus
    "bridges/ros":       "rclpy",
    "bridges/rpi":       "RPi",
    "bridges/session":   None,   # module local — path ajouté via sys.path ci-dessus
}


def _dep_available(pkg):
    if pkg is None:
        return True
    try:
        __import__(pkg)
        return True
    except ImportError:
        return False


for bridge_path, dep in _BRIDGE_DEPS.items():
    if not _dep_available(dep):
        collect_ignore_glob.append(f"{bridge_path}/*")
