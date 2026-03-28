# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
Agent Registry — PiQrypt v1.8.4

Registre central des agents PiQrypt installés sur la machine.
Gère la résolution des répertoires, la création des structures,
et la liste des agents enregistrés.

Stockage :
    ~/.piqrypt/registry.json       ← liste des agents
    ~/.piqrypt/agents/<name>/      ← répertoire par agent

    Répertoire agent :
        identity.json              ← document identité public
        private.key.enc            ← clé privée chiffrée (v1.8.4)
        private.key.json           ← clé privée en clair (legacy / Free sans passphrase)
        events/plain/              ← événements Free tier
        events/encrypted/          ← événements Pro tier
        tsi/                       ← baseline TSI
        index.db                   ← SQLite index propre à l'agent

Philosophie :
    - Un agent = un répertoire autonome et transportable
    - Le registre est une liste de métadonnées — pas de données sensibles
    - Backward compat : agent "default" pour le code v1.6.0 et antérieur
"""

import json
import time
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from aiss.logger import get_logger

logger = get_logger(__name__)

# ─── Chemins ──────────────────────────────────────────────────────────────────
PIQRYPT_DIR  = Path.home() / ".piqrypt"
AGENTS_DIR   = PIQRYPT_DIR / "agents"
REGISTRY_FILE = PIQRYPT_DIR / "registry.json"

# Nom de l'agent fallback pour backward compat v1.6.0
DEFAULT_AGENT = "default"


# ─── Sanitization ─────────────────────────────────────────────────────────────

def _safe_name(name: str) -> str:
    """
    Sanitize un nom d'agent pour usage comme nom de répertoire.
    Autorise : lettres, chiffres, tirets, underscores.
    Max 64 caractères.
    """
    safe = re.sub(r'[^\w\-]', '_', name)[:64]
    if not safe:
        raise ValueError(f"Nom d'agent invalide : '{name}'")
    return safe


# ─── Résolution répertoires par agent ─────────────────────────────────────────

def get_agent_dir(agent_name: str) -> Path:
    """Répertoire racine de l'agent."""
    return AGENTS_DIR / _safe_name(agent_name)


def get_events_plain_dir(agent_name: str) -> Path:
    """Répertoire événements Free tier."""
    return get_agent_dir(agent_name) / "events" / "plain"


def get_events_enc_dir(agent_name: str) -> Path:
    """Répertoire événements Pro tier."""
    return get_agent_dir(agent_name) / "events" / "encrypted"


def get_keys_dir(agent_name: str) -> Path:
    """Répertoire clés de l'agent."""
    return get_agent_dir(agent_name) / "keys"


def get_tsi_dir(agent_name: str) -> Path:
    """Répertoire TSI baseline de l'agent."""
    return get_agent_dir(agent_name) / "tsi"


def get_index_path(agent_name: str) -> Path:
    """Chemin SQLite index de l'agent."""
    return get_agent_dir(agent_name) / "index.db"


def get_identity_path(agent_name: str) -> Path:
    """Chemin document identité de l'agent."""
    return get_agent_dir(agent_name) / "identity.json"


def get_key_enc_path(agent_name: str) -> Path:
    """Chemin clé privée chiffrée."""
    return get_agent_dir(agent_name) / "private.key.enc"


def get_key_plain_path(agent_name: str) -> Path:
    """Chemin clé privée en clair (legacy / Free sans passphrase)."""
    return get_agent_dir(agent_name) / "private.key.json"


# ─── Initialisation structure ─────────────────────────────────────────────────

def init_agent_dirs(agent_name: str) -> Path:
    """
    Crée la structure de répertoires complète pour un agent.

    Structure créée :
        ~/.piqrypt/agents/<name>/
            events/plain/
            events/encrypted/
            keys/
            tsi/

    Returns:
        Path du répertoire agent créé
    """
    agent_dir = get_agent_dir(agent_name)

    dirs = [
        agent_dir,
        get_events_plain_dir(agent_name),
        get_events_enc_dir(agent_name),
        get_keys_dir(agent_name),
        get_tsi_dir(agent_name),
    ]

    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)

    # Permissions restrictives sur le répertoire agent
    agent_dir.chmod(0o700)

    logger.info(f"[Registry] Répertoires créés pour '{agent_name}' : {agent_dir}")
    return agent_dir


# ─── Registre ─────────────────────────────────────────────────────────────────

def _load_registry() -> Dict[str, Any]:
    """Charge le registre depuis le fichier JSON."""
    PIQRYPT_DIR.mkdir(parents=True, exist_ok=True)

    if not REGISTRY_FILE.exists():
        return {"version": "1.8.4", "agents": {}}

    try:
        data = json.loads(REGISTRY_FILE.read_text())
        if "agents" not in data:
            data["agents"] = {}
        return data
    except Exception as e:
        logger.warning(f"[Registry] Fichier registre illisible : {e} — reset")
        return {"version": "1.8.4", "agents": {}}


def _save_registry(data: Dict[str, Any]) -> None:
    """Sauvegarde le registre."""
    PIQRYPT_DIR.mkdir(parents=True, exist_ok=True)
    REGISTRY_FILE.write_text(json.dumps(data, indent=2))
    REGISTRY_FILE.chmod(0o600)


def register_agent(
    agent_name: str,
    agent_id: str,
    tier: str = "free",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Enregistre un agent dans le registre.

    Args:
        agent_name: Nom lisible de l'agent
        agent_id:   ID cryptographique (BASE58 32 chars)
        tier:       "free" ou "pro"
        metadata:   Métadonnées optionnelles

    Returns:
        Entrée du registre créée/mise à jour
    """
    data = _load_registry()
    now = int(time.time())

    entry: Dict[str, Any] = {
        "agent_id":   agent_id,
        "tier":       tier,
        "created_at": data["agents"].get(agent_name, {}).get(
            "created_at", now
        ),
        "last_seen":  now,
        "version":    "1.8.4",
    }

    if metadata:
        entry["metadata"] = metadata

    data["agents"][agent_name] = entry
    _save_registry(data)

    logger.info(f"[Registry] Agent '{agent_name}' enregistré ({agent_id[:16]}...)")
    return entry


def update_last_seen(agent_name: str) -> None:
    """Met à jour le timestamp last_seen d'un agent."""
    data = _load_registry()
    if agent_name in data["agents"]:
        data["agents"][agent_name]["last_seen"] = int(time.time())
        _save_registry(data)


def get_agent_info(agent_name: str) -> Optional[Dict[str, Any]]:
    """
    Retourne les infos d'un agent depuis le registre.
    Retourne None si l'agent n'est pas enregistré.
    """
    data = _load_registry()
    entry = data["agents"].get(agent_name)
    if entry:
        return {"name": agent_name, **entry}
    return None


def list_agents() -> List[Dict[str, Any]]:
    """
    Liste tous les agents enregistrés avec leurs métadonnées.

    Returns:
        Liste triée par last_seen décroissant
    """
    data = _load_registry()
    agents = []

    for name, info in data["agents"].items():
        agent_dir = get_agent_dir(name)
        entry = {
            "name":       name,
            "agent_id":   info.get("agent_id", "unknown"),
            "tier":       info.get("tier", "free"),
            "created_at": info.get("created_at", 0),
            "last_seen":  info.get("last_seen", 0),
            "dir_exists": agent_dir.exists(),
        }
        agents.append(entry)

    return sorted(agents, key=lambda a: a["last_seen"], reverse=True)


def agent_exists(agent_name: str) -> bool:
    """Vérifie si un agent est enregistré ET son répertoire existe."""
    data = _load_registry()
    if agent_name not in data["agents"]:
        return False
    return get_agent_dir(agent_name).exists()


def unregister_agent(agent_name: str, delete_files: bool = False) -> None:
    """
    Supprime un agent du registre.

    Args:
        agent_name:   Nom de l'agent à supprimer
        delete_files: Si True, supprime aussi le répertoire de l'agent
                      (IRRÉVERSIBLE — à utiliser avec précaution)
    """
    data = _load_registry()

    if agent_name not in data["agents"]:
        logger.warning(f"[Registry] Agent '{agent_name}' non trouvé dans le registre")
        return

    del data["agents"][agent_name]
    _save_registry(data)

    if delete_files:
        import shutil
        agent_dir = get_agent_dir(agent_name)
        if agent_dir.exists():
            shutil.rmtree(agent_dir)
            logger.warning(
                f"[Registry] Répertoire supprimé : {agent_dir} — IRRÉVERSIBLE"
            )

    logger.info(f"[Registry] Agent '{agent_name}' supprimé du registre")


# ─── Résolution agent depuis session ou fallback ──────────────────────────────

def resolve_agent_name(
    agent_name: Optional[str] = None,
    session: Optional[Any] = None,
) -> str:
    """
    Résout le nom d'agent à utiliser.

    Priorité :
        1. agent_name explicite
        2. session.agent_name (si session fournie)
        3. PIQRYPT_AGENT_NAME (variable d'environnement)
        4. "default" (fallback backward compat v1.6.0)

    Args:
        agent_name: Nom explicite (prioritaire)
        session:    IdentitySession (pour déduire le nom)

    Returns:
        Nom d'agent résolu
    """
    import os

    if agent_name:
        return agent_name

    if session is not None and hasattr(session, '_agent_name') and session._agent_name:
        return session._agent_name

    env_name = os.environ.get("PIQRYPT_AGENT_NAME")
    if env_name:
        return env_name

    return DEFAULT_AGENT


# ─── Détection structure legacy ───────────────────────────────────────────────

def detect_legacy_structure() -> bool:
    """
    Détecte si une structure v1.6.0 ou antérieure existe.
    Utilisé par migration.py pour proposer la migration automatique.

    Structure legacy = events/plain/ ou events/encrypted/ à la racine
    de ~/.piqrypt/ (pas dans un sous-répertoire agents/).
    """
    old_plain = PIQRYPT_DIR / "events" / "plain"
    old_enc   = PIQRYPT_DIR / "events" / "encrypted"
    return old_plain.exists() or old_enc.exists()


def get_legacy_event_counts() -> Dict[str, int]:
    """
    Compte les événements legacy (avant migration).
    Utilisé pour informer l'utilisateur avant la migration.
    """
    counts = {"plain": 0, "encrypted": 0}

    plain_dir = PIQRYPT_DIR / "events" / "plain"
    if plain_dir.exists():
        for f in plain_dir.glob("*.json"):
            try:
                events = json.loads(f.read_text())
                counts["plain"] += len(events)
            except Exception:
                pass

    enc_dir = PIQRYPT_DIR / "events" / "encrypted"
    if enc_dir.exists():
        counts["encrypted"] += len(list(enc_dir.glob("*.enc")))

    return counts


# ─── Formatage CLI ────────────────────────────────────────────────────────────

def format_agent_list(agents: List[Dict[str, Any]]) -> str:
    """
    Formate la liste des agents pour affichage CLI.

    Exemple :
        Agents PiQrypt enregistrés
        ──────────────────────────────────────────────────
          trading_bot_A    pq_7f3a9b...  Pro   il y a 2min
          sentiment_bot_B  pq_9mK4pQ...  Free  il y a 1h
    """
    if not agents:
        return "  Aucun agent enregistré.\n  Créez un agent : piqrypt identity create"

    now = int(time.time())
    lines = [
        "\nAgents PiQrypt enregistrés",
        f"  {'Nom':<24} {'Agent ID':<20} {'Tier':<6} {'Vu':<15} {'Dir'}",
        f"  {'─'*24} {'─'*20} {'─'*6} {'─'*15} {'─'*3}",
    ]

    for a in agents:
        age = now - a.get("last_seen", now)
        if age < 60:
            seen = "à l'instant"
        elif age < 3600:
            seen = f"il y a {age // 60}min"
        elif age < 86400:
            seen = f"il y a {age // 3600}h"
        else:
            seen = f"il y a {age // 86400}j"

        tier  = a.get("tier", "free").capitalize()
        aid   = a.get("agent_id", "?")[:16] + "..."
        exists = "✅" if a.get("dir_exists") else "❌"

        lines.append(
            f"  {a['name']:<24} {aid:<20} {tier:<6} {seen:<15} {exists}"
        )

    return "\n".join(lines)


# ─── Classe wrapper (compat tests / API objet) ────────────────────────────────

class AgentRegistry:
    """
    Wrapper orienté-objet autour des fonctions standalone du registre.
    Permet un usage : reg = AgentRegistry(path); reg.register(...); reg.list()

    Le paramètre `registry_path` est optionnel — s'il est fourni, il est
    utilisé comme chemin du fichier registre (utile en tests avec tmpdir).
    """

    def __init__(self, registry_path: Optional[Path] = None):
        self._registry_path = Path(registry_path) if registry_path else REGISTRY_FILE
        # Patch temporaire du chemin global si un path custom est fourni
        self._custom_path = (registry_path is not None)

    def _use_path(self):
        """Context : utilise le chemin custom si fourni."""
        import contextlib

        @contextlib.contextmanager
        def _ctx():
            global REGISTRY_FILE  # noqa: PLW0603
            if self._custom_path:
                _ = REGISTRY_FILE
                # On patch au niveau du module pour que _load/_save utilisent notre path
                import aiss.agent_registry as _mod
                original_mod = _mod.REGISTRY_FILE
                _mod.REGISTRY_FILE = self._registry_path
                try:
                    yield
                finally:
                    _mod.REGISTRY_FILE = original_mod
            else:
                yield

        return _ctx()

    def register(self, name: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Enregistre un agent. metadata peut contenir tier, type, etc."""
        meta = metadata or {}
        tier = meta.get("tier", "free")
        agent_id = meta.get("agent_id", f"AGENT_{name.upper()}")
        with self._use_path():
            return register_agent(name, agent_id, tier=tier, metadata=meta)

    def list(self) -> List[Dict[str, Any]]:
        """Retourne la liste des agents enregistrés."""
        with self._use_path():
            return list_agents()

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        """Retourne les métadonnées d'un agent."""
        with self._use_path():
            return get_agent_info(name)

    def unregister(self, name: str) -> None:
        """Supprime un agent du registre."""
        with self._use_path():
            unregister_agent(name)

    def exists(self, name: str) -> bool:
        """Vérifie si un agent est enregistré."""
        with self._use_path():
            return agent_exists(name)


# ─── Public API ───────────────────────────────────────────────────────────────
__all__ = [
    # Résolution répertoires
    "get_agent_dir",
    "get_events_plain_dir",
    "get_events_enc_dir",
    "get_keys_dir",
    "get_tsi_dir",
    "get_index_path",
    "get_identity_path",
    "get_key_enc_path",
    "get_key_plain_path",
    # Init
    "init_agent_dirs",
    # Registre
    "register_agent",
    "update_last_seen",
    "get_agent_info",
    "list_agents",
    "agent_exists",
    "unregister_agent",
    # Résolution
    "resolve_agent_name",
    "DEFAULT_AGENT",
    # Legacy
    "detect_legacy_structure",
    "get_legacy_event_counts",
    # Formatage
    "format_agent_list",
    # Classe wrapper
    "AgentRegistry",
    # Constantes
    "PIQRYPT_DIR",
    "AGENTS_DIR",
    "REGISTRY_FILE",
]
