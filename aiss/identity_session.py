# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
Identity Session — PiQrypt v1.8.1

Gestion de la session d'identité d'un agent.
La clé privée est chargée en RAM uniquement pendant la session,
puis effacée de manière sécurisée à la fermeture.

Modes de déverrouillage :
    1. Interactif  : passphrase tapée par l'humain (getpass)
    2. Autonome    : depuis variables d'environnement
                     PIQRYPT_AGENT_NAME + PIQRYPT_PASSPHRASE
    3. Sans passphrase : Free tier (clé en clair — déconseillé en production)

Usage typique :

    # Mode context manager (recommandé — garantit l'effacement)
    with IdentitySession.open("trading_bot_A", passphrase="...") as session:
        event = stamp_event(session.private_key, session.agent_id, payload)
        store_event(event, session=session)

    # Mode autonome (production / Docker / IoT)
    session = IdentitySession()
    session.unlock_from_env()
    # ... utilisation ...
    session.lock()  # toujours appeler à la fin

    # Mode interactif (dev / CLI)
    session = IdentitySession()
    session.unlock_interactive("trading_bot_A")

Philosophie :
    - Clé privée jamais persistée en clair
    - Effacement RAM à la fermeture (bytearray + zéros)
    - SessionLockedError si on tente de signer sans session ouverte
    - Compatible mode autonome (IoT, robots, Docker)
"""

import os
import time
from pathlib import Path
from typing import Optional

from aiss.logger import get_logger
from aiss.key_store import (
    load_encrypted_key,
    load_plaintext_key,
    is_encrypted,
    _secure_erase,
    InvalidPassphraseError,
    KeyFileCorruptedError,
)

logger = get_logger(__name__)

# ─── Variables d'environnement ────────────────────────────────────────────────
ENV_AGENT_NAME  = "PIQRYPT_AGENT_NAME"
ENV_PASSPHRASE  = "PIQRYPT_PASSPHRASE"

# ─── Répertoire agents ────────────────────────────────────────────────────────
PIQRYPT_DIR = Path.home() / ".piqrypt"
AGENTS_DIR  = PIQRYPT_DIR / "agents"


# ─── Exceptions ───────────────────────────────────────────────────────────────

class SessionLockedError(Exception):
    """Tentative d'utilisation d'une session verrouillée."""


class AgentNotFoundError(Exception):
    """Agent introuvable dans ~/.piqrypt/agents/."""


class SessionAlreadyOpenError(Exception):
    """Une session est déjà ouverte pour cet agent."""


# ─── Helpers répertoires ──────────────────────────────────────────────────────

def _safe_name(name: str) -> str:
    """Sanitize le nom d'agent pour usage comme nom de répertoire."""
    import re
    return re.sub(r'[^\w\-]', '_', name)[:64]


def get_agent_dir(agent_name: str) -> Path:
    """Retourne le répertoire d'un agent."""
    return AGENTS_DIR / _safe_name(agent_name)


def get_key_path(agent_name: str) -> Optional[Path]:
    """
    Retourne le chemin de la clé privée d'un agent.
    Cherche d'abord .enc (chiffré), puis .json (clair legacy).
    Retourne None si aucun fichier trouvé.
    """
    agent_dir = get_agent_dir(agent_name)

    # Format v1.8.1 chiffré
    enc_path = agent_dir / "private.key.enc"
    if enc_path.exists():
        return enc_path

    # Format legacy JSON en clair
    json_path = agent_dir / "private.key.json"
    if json_path.exists():
        return json_path

    # Compat v1.6.0 — clé dans le répertoire racine legacy
    legacy_path = PIQRYPT_DIR / "keys" / "identity.json"
    if legacy_path.exists():
        return legacy_path

    return None


def get_identity_path(agent_name: str) -> Path:
    """Retourne le chemin du document d'identité d'un agent."""
    return get_agent_dir(agent_name) / "identity.json"


# ─── IdentitySession ──────────────────────────────────────────────────────────

class IdentitySession:
    """
    Session d'identité sécurisée.

    La clé privée est stockée dans un bytearray mutable
    pour permettre l'effacement sécurisé à la fermeture.
    """

    def __init__(self):
        self._agent_name:   Optional[str]       = None
        self._agent_id:     Optional[str]       = None
        self._private_key:  Optional[bytearray] = None
        self._public_key:   Optional[bytes]     = None
        self._locked:       bool                = True
        self._opened_at:    Optional[int]       = None

    # ── Propriétés ────────────────────────────────────────────────────────────

    @property
    def agent_name(self) -> str:
        self._require_unlocked()
        return self._agent_name

    @property
    def agent_id(self) -> str:
        self._require_unlocked()
        return self._agent_id

    @property
    def public_key(self) -> bytes:
        self._require_unlocked()
        return self._public_key

    @property
    def private_key(self) -> bytes:
        """
        Retourne une copie bytes de la clé privée.
        ⚠️  Utiliser session.sign() de préférence — évite les copies.
        """
        self._require_unlocked()
        return bytes(self._private_key)

    @property
    def is_locked(self) -> bool:
        return self._locked

    # ── Déverrouillage ────────────────────────────────────────────────────────

    def unlock(self, agent_name: str, passphrase: Optional[str] = None) -> "IdentitySession":
        """
        Déverrouille la session pour un agent.

        Args:
            agent_name: Nom de l'agent (doit exister dans ~/.piqrypt/agents/)
            passphrase: Passphrase de déchiffrement (None = clé en clair)

        Returns:
            self (pour chaînage)

        Raises:
            AgentNotFoundError:    Agent introuvable
            InvalidPassphraseError: Passphrase incorrecte
            SessionAlreadyOpenError: Session déjà ouverte
        """
        if not self._locked:
            raise SessionAlreadyOpenError(
                f"Session déjà ouverte pour {self._agent_name}"
            )

        agent_dir = get_agent_dir(agent_name)
        if not agent_dir.exists():
            raise AgentNotFoundError(
                f"Agent '{agent_name}' introuvable dans {AGENTS_DIR}\n"
                f"Créez l'agent avec : piqrypt identity create"
            )

        # Charger la clé privée
        key_path = get_key_path(agent_name)
        if key_path is None:
            raise AgentNotFoundError(
                f"Fichier de clé introuvable pour '{agent_name}'"
            )

        if is_encrypted(key_path):
            if passphrase is None:
                raise InvalidPassphraseError(
                    f"La clé de '{agent_name}' est chiffrée — passphrase requise"
                )
            raw_key = load_encrypted_key(key_path, passphrase)
        else:
            raw_key = load_plaintext_key(key_path)
            if passphrase is not None:
                logger.warning(
                    f"[Session] Clé de '{agent_name}' non chiffrée — "
                    f"passphrase ignorée. Utilisez piqrypt identity secure."
                )

        # Stocker dans bytearray pour effacement sécurisé
        self._private_key = bytearray(raw_key)

        # Charger l'identité publique
        self._agent_name = agent_name
        self._agent_id, self._public_key = self._load_identity(agent_name)
        self._locked = False
        self._opened_at = int(time.time())

        logger.info(f"[Session] Ouverte pour '{agent_name}' ({self._agent_id[:16]}...)")
        return self

    def unlock_from_env(self) -> "IdentitySession":
        """
        Déverrouille depuis les variables d'environnement.

        Variables requises :
            PIQRYPT_AGENT_NAME  : nom de l'agent
            PIQRYPT_PASSPHRASE  : passphrase (optionnel si clé en clair)

        Retourne self pour chaînage.
        Idéal pour Docker, Kubernetes, IoT, robots autonomes.
        """
        agent_name = os.environ.get(ENV_AGENT_NAME)
        if not agent_name:
            raise AgentNotFoundError(
                f"Variable d'environnement {ENV_AGENT_NAME} non définie.\n"
                f"Exemple : export {ENV_AGENT_NAME}=trading_bot_A"
            )

        passphrase = os.environ.get(ENV_PASSPHRASE)

        logger.debug(
            f"[Session] Déverrouillage depuis env — agent={agent_name}"
        )
        return self.unlock(agent_name, passphrase)

    def unlock_interactive(self, agent_name: str) -> "IdentitySession":
        """
        Déverrouillage interactif — demande la passphrase via getpass.
        Utilisé par le CLI.
        """
        import getpass

        key_path = get_key_path(agent_name)
        if key_path and is_encrypted(key_path):
            passphrase = getpass.getpass(
                f"🔒 Passphrase pour '{agent_name}' : "
            )
        else:
            passphrase = None

        return self.unlock(agent_name, passphrase)

    # ── Verrouillage ──────────────────────────────────────────────────────────

    def lock(self) -> None:
        """
        Verrouille la session et efface la clé privée de la RAM.
        Toujours appeler à la fin d'une session.
        """
        if self._private_key is not None:
            _secure_erase(self._private_key)
            self._private_key = None

        duration = (
            int(time.time()) - self._opened_at
            if self._opened_at else 0
        )
        logger.info(
            f"[Session] Fermée pour '{self._agent_name}' "
            f"(durée : {duration}s)"
        )

        self._locked = True
        self._agent_name = None
        self._agent_id = None
        self._public_key = None
        self._opened_at = None

    # ── Signature ─────────────────────────────────────────────────────────────

    def sign(self, data: bytes) -> bytes:
        """
        Signe des données avec la clé privée de la session.

        Préférer cette méthode à session.private_key pour éviter
        les copies de la clé en mémoire.

        Args:
            data: Données à signer (bytes canoniques)

        Returns:
            Signature Ed25519 (64 bytes)

        Raises:
            SessionLockedError: Session verrouillée
        """
        self._require_unlocked()

        from aiss.crypto import ed25519
        return ed25519.sign(bytes(self._private_key), data)

    # ── Context Manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "IdentitySession":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Garantit l'effacement de la clé même en cas d'exception."""
        self.lock()
        return False  # Ne supprime pas les exceptions

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def open(
        cls,
        agent_name: str,
        passphrase: Optional[str] = None,
    ) -> "IdentitySession":
        """
        Factory — crée et déverrouille une session en une ligne.

        Usage recommandé avec context manager :
            with IdentitySession.open("trading_bot_A", "passphrase") as s:
                ...
        """
        session = cls()
        session.unlock(agent_name, passphrase)
        return session

    @classmethod
    def from_env(cls) -> "IdentitySession":
        """
        Factory — crée une session depuis les variables d'environnement.

        Usage :
            with IdentitySession.from_env() as session:
                ...
        """
        session = cls()
        session.unlock_from_env()
        return session

    # ── Helpers internes ──────────────────────────────────────────────────────

    def _require_unlocked(self) -> None:
        if self._locked:
            raise SessionLockedError(
                "Session verrouillée. "
                "Appelez session.unlock() ou utilisez IdentitySession.open()."
            )

    def _load_identity(self, agent_name: str):
        """
        Charge agent_id et public_key depuis identity.json.

        Returns:
            (agent_id: str, public_key: bytes)
        """
        import json
        import base64

        identity_path = get_identity_path(agent_name)

        if not identity_path.exists():
            # Tenter la dérivation depuis la clé privée chargée
            from aiss.crypto import ed25519 as ed
            from aiss.identity import derive_agent_id

            priv_key_obj = ed.Ed25519PrivateKey.from_private_bytes(
                bytes(self._private_key)
            )
            pub_key_obj = priv_key_obj.public_key()
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat
            )
            public_key_bytes = pub_key_obj.public_bytes(
                Encoding.Raw, PublicFormat.Raw
            )
            agent_id = derive_agent_id(public_key_bytes)
            logger.warning(
                f"[Session] identity.json absent pour '{agent_name}' "
                f"— agent_id dérivé de la clé"
            )
            return agent_id, public_key_bytes

        try:
            identity = json.loads(identity_path.read_text())
            agent_id = identity["agent_id"]
            public_key = base64.b64decode(identity["public_key"])
            return agent_id, public_key
        except Exception as e:
            raise KeyFileCorruptedError(
                f"identity.json invalide pour '{agent_name}': {e}"
            )

    # ── Représentation ────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        if self._locked:
            return "IdentitySession(locked)"
        return (
            f"IdentitySession("
            f"agent='{self._agent_name}', "
            f"id={self._agent_id[:16]}..., "
            f"unlocked)"
        )


# ─── Public API ───────────────────────────────────────────────────────────────
__all__ = [
    "IdentitySession",
    "get_agent_dir",
    "get_key_path",
    "get_identity_path",
    "_safe_name",
    "SessionLockedError",
    "AgentNotFoundError",
    "SessionAlreadyOpenError",
    "AGENTS_DIR",
    "ENV_AGENT_NAME",
    "ENV_PASSPHRASE",
]
