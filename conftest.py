import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent

def pytest_configure(config):
    """Insert repo root at head of sys.path before any test collection."""
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    # Force reload de aiss depuis le repo local si deja charge
    for mod_name in list(sys.modules.keys()):
        if mod_name == 'aiss' or mod_name.startswith('aiss.'):
            del sys.modules[mod_name]

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
