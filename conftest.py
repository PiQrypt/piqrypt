# SPDX-License-Identifier: MIT
"""
Configuration pytest — PiQrypt v1.7.1

Les bridges nécessitent des packages optionnels (crewai, langchain, etc.) non
disponibles dans tous les environnements CI. Ce conftest.py gère le skip
conditionnel pour éviter les erreurs de collection.
"""

collect_ignore_glob = []

# Bridges avec dépendances optionnelles — skippés si la dépendance est absente
_BRIDGE_DEPS = {
    "bridges/autogen":   "autogen",
    "bridges/crewai":    "crewai",
    "bridges/langchain": "langchain",
    "bridges/mcp":       "mcp",
    "bridges/ollama":    "ollama",
    "bridges/openclaw":  None,   # module local — vérifier autrement
    "bridges/ros":       "rclpy",
    "bridges/rpi":       "RPi",
    "bridges/session":   None,   # module local
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
