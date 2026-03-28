# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute -- see root LICENSE for details.

"""
Agent Identity Management (RFC Sections 5-6)

This module implements:
- Deterministic agent ID derivation (Section 5.1)
- Identity document generation (Section 6)
- Key rotation attestation (Section 12)

v1.8.4 additions:
- create_agent_identity() : création complète avec nom + passphrase + stockage
- load_agent_identity()   : chargement depuis ~/.piqrypt/agents/<n>/
- list_agent_identities() : liste tous les agents enregistrés
"""

import json
import time
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

from aiss.crypto import ed25519
from aiss.canonical import hash_bytes
from aiss.exceptions import InvalidAgentIDError
from aiss.logger import get_logger
from aiss.telemetry import track as _telemetry_track

logger = get_logger(__name__)


def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate Ed25519 keypair for agent identity.

    Uses cryptographically secure random number generator (CSPRNG)
    as required by RFC Section 14.1.

    Returns:
        Tuple of (private_key_bytes, public_key_bytes)

    Example:
        >>> private_key, public_key = generate_keypair()
        >>> agent_id = derive_agent_id(public_key)
    """
    return ed25519.generate_keypair()


def derive_agent_id(public_key: bytes) -> str:
    """
    Derive deterministic agent ID from public key.

    RFC Section 5.1 mandates:
        agent_id = BASE58( SHA256(public_key_bytes) )[0:32]

    This ensures:
    - Collision resistance (~186 bits entropy)
    - No registry dependency
    - Cryptographic binding to identity
    - Verifiability

    Args:
        public_key: 32-byte Ed25519 public key

    Returns:
        32-character Base58 agent ID

    Example:
        >>> public_key = b'\\x01' * 32  # Example key
        >>> agent_id = derive_agent_id(public_key)
        >>> len(agent_id)
        32
    """
    # Hash the public key
    key_hash = hash_bytes(public_key)

    # Convert hex to bytes for Base58 encoding
    hash_bytes_val = bytes.fromhex(key_hash)

    # Encode to Base58 and truncate to 32 chars
    agent_id = ed25519.encode_base58(hash_bytes_val)[:32]

    return agent_id


def verify_agent_id(agent_id: str, public_key: bytes) -> bool:
    """
    Verify that agent_id correctly derives from public_key.

    Args:
        agent_id: Claimed agent ID
        public_key: Public key bytes

    Returns:
        True if agent_id is valid

    Raises:
        InvalidAgentIDError: If agent_id does not match
    """
    derived = derive_agent_id(public_key)
    if agent_id != derived:
        raise InvalidAgentIDError(agent_id, derived)
    return True


def export_identity(
    agent_id: str,
    public_key: bytes,
    algorithm: str = "Ed25519",
    metadata: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Export agent identity document (RFC Section 6.1).

    Creates AISS-1.0 compliant identity document with:
    - version: AISS-1.0
    - agent_id: Deterministic ID
    - public_key: Base58 encoded
    - algorithm: Signature algorithm
    - created_at: Unix UTC timestamp
    - metadata: Optional application data

    Args:
        agent_id: Agent ID (must match public_key)
        public_key: Public key bytes
        algorithm: Signature algorithm (default: Ed25519)
        metadata: Optional metadata dict

    Returns:
        Identity document dict

    Example:
        >>> private_key, public_key = generate_keypair()
        >>> agent_id = derive_agent_id(public_key)
        >>> identity = export_identity(agent_id, public_key)
        >>> identity['version']
        'AISS-1.0'
    """
    # Verify agent_id matches public_key
    verify_agent_id(agent_id, public_key)

    identity = {
        "version": "AISS-1.0",
        "agent_id": agent_id,
        "public_key": ed25519.encode_base64(public_key),
        "algorithm": algorithm,
        "created_at": int(time.time())
    }

    if metadata:
        identity["metadata"] = metadata

    return identity


def create_rotation_attestation(
    old_private_key: bytes,
    old_public_key: bytes,
    new_public_key: bytes
) -> Dict[str, Any]:
    """
    Create key rotation attestation (RFC Section 12).

    When rotating keys, agent_id changes (since it derives from public_key).
    This attestation proves continuity between old and new identities.

    The attestation is signed by the OLD private key to prove:
    "I (old agent) certify that (new agent) is my successor"

    Args:
        old_private_key: Current private key (to sign attestation)
        old_public_key: Current public key
        new_public_key: New public key

    Returns:
        Rotation attestation document

    Example:
        >>> old_priv, old_pub = generate_keypair()
        >>> new_priv, new_pub = generate_keypair()
        >>> attestation = create_rotation_attestation(old_priv, old_pub, new_pub)
        >>> attestation['attestation_type']
        'key_rotation'
    """
    from aiss.canonical import canonicalize

    old_agent_id = derive_agent_id(old_public_key)
    new_agent_id = derive_agent_id(new_public_key)

    # Build attestation (without signature)
    attestation = {
        "version": "AISS-1.0",
        "attestation_type": "key_rotation",
        "previous_agent_id": old_agent_id,
        "previous_public_key": ed25519.encode_base64(old_public_key),
        "new_agent_id": new_agent_id,
        "new_public_key": ed25519.encode_base64(new_public_key),
        "rotation_timestamp": int(time.time())
    }

    # Sign with old key
    canonical = canonicalize(attestation)
    signature = ed25519.sign(old_private_key, canonical)
    attestation["rotation_signature"] = ed25519.encode_base64(signature)

    return attestation


# Public API
__all__ = [
    "generate_keypair",
    "derive_agent_id",
    "verify_agent_id",
    "export_identity",
    "create_rotation_attestation",
]


def create_rotation_pcp_event(
    old_private_key: bytes,
    old_public_key: bytes,
    new_public_key: bytes,
    previous_hash: str,
    store_in_memory: bool = True
) -> dict:
    """
    Create key rotation as a PROPER PCP chain event (RFC Section 9.4 / 12).

    FIXES: Previous implementation returned a standalone document.
    This function inserts the rotation as the FINAL event of the old chain,
    and binds the new chain's genesis to this event's hash.

    Flow:
        old_chain: E1 → E2 → ... → En → ROTATION_EVENT ← this function
        new_chain: genesis(new_pubkey, prev=hash(ROTATION_EVENT)) → E1' → ...

    Args:
        old_private_key: Current private key (signs the rotation event)
        old_public_key:  Current public key
        new_public_key:  New public key
        previous_hash:   Hash of last event in old chain
        store_in_memory: Auto-store in PCP memory

    Returns:
        Rotation event dict (signed, ready for chain insertion)

    Example:
        >>> rot_event = create_rotation_pcp_event(old_priv, old_pub, new_pub, last_hash)
        >>> rot_hash = compute_event_hash(rot_event)
        >>> # New chain genesis uses rot_hash as previous_hash
        >>> genesis = stamp_genesis_event(new_priv, new_pub, new_id, payload,
        ...                               rotation_previous_hash=rot_hash)
    """
    import time
    import uuid
    from aiss.canonical import canonicalize

    old_agent_id = derive_agent_id(old_public_key)
    new_agent_id = derive_agent_id(new_public_key)

    rotation_payload = {
        "event_type": "key_rotation",
        "attestation_type": "key_rotation",
        "previous_agent_id": old_agent_id,
        "previous_public_key": ed25519.encode_base64(old_public_key),
        "new_agent_id": new_agent_id,
        "new_public_key": ed25519.encode_base64(new_public_key),
        "rotation_timestamp": int(time.time()),
    }

    event = {
        "version": "AISS-1.0",
        "agent_id": old_agent_id,
        "timestamp": int(time.time()),
        "nonce": str(uuid.uuid4()),
        "payload": rotation_payload,
        "previous_hash": previous_hash,
    }

    canonical = canonicalize(event)
    signature = ed25519.sign(old_private_key, canonical)
    event["signature"] = ed25519.encode_base64(signature)

    if store_in_memory:
        try:
            from aiss.memory import store_event
            store_event(event)
        except Exception:
            pass  # Memory may not be initialized

    return event


# ─── v1.8.4 : Création identité avec stockage isolé ──────────────────────────

def create_agent_identity(
    agent_name: str,
    passphrase: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    tier: str = "free",
    base_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Crée une identité complète pour un agent et la stocke dans
    ~/.piqrypt/agents/<agent_name>/ (ou base_dir/agents/<agent_name>/ si fourni).

    Args:
        agent_name: Nom lisible de l'agent (ex: "trading_bot_A")
        passphrase: Passphrase pour chiffrer la clé privée.
                    None = stockage en clair (Free tier, déconseillé en prod)
        metadata:   Métadonnées optionnelles (description, version, etc.)
        tier:       "free" ou "pro"
        base_dir:   Répertoire racine optionnel (utile en tests/CI).
                    Si omis, utilise ~/.piqrypt/agents/.

    Returns:
        Dict avec identity, agent_id, agent_name, key_path, encrypted

    Raises:
        ValueError: Si agent_name est vide ou invalide
    """
    if not agent_name or not agent_name.strip():
        raise ValueError("Le nom de l'agent ne peut pas être vide")

    # Générer les clés
    private_key, public_key = generate_keypair()
    agent_id = derive_agent_id(public_key)

    # Créer le document d'identité
    identity = export_identity(agent_id, public_key, metadata=metadata)

    # Créer la structure de répertoires
    from aiss.agent_registry import init_agent_dirs, register_agent, get_agent_dir

    if base_dir is not None:
        # Mode test : stockage dans base_dir/agents/<agent_name>/
        agent_dir = Path(base_dir) / "agents" / agent_name
        agent_dir.mkdir(parents=True, exist_ok=True)
    else:
        init_agent_dirs(agent_name)
        agent_dir = get_agent_dir(agent_name)

    # Sauvegarder identity.json
    identity_path = agent_dir / "identity.json"
    identity_path.write_text(json.dumps(identity, indent=2))
    identity_path.chmod(0o644)

    # Sauvegarder la clé privée
    if passphrase:
        from aiss.key_store import save_encrypted_key
        key_path = agent_dir / "private.key.enc"
        save_encrypted_key(private_key, passphrase, key_path)
        encrypted = True
    else:
        from aiss.key_store import save_plaintext_key
        key_path = agent_dir / "private.key.json"
        save_plaintext_key(private_key, key_path)
        encrypted = False
        if tier == "pro":
            logger.warning(
                f"[Identity] Clé de '{agent_name}' non chiffrée en Pro tier. "
                f"Utilisez piqrypt identity secure pour chiffrer."
            )

    # Enregistrer dans le registre (sauf en mode base_dir test)
    if base_dir is None:
        register_agent(
            agent_name=agent_name,
            agent_id=agent_id,
            tier=tier,
            metadata=metadata,
        )

    logger.info(
        f"[Identity] Agent '{agent_name}' créé — "
        f"ID: {agent_id[:16]}... — "
        f"Clé: {'chiffrée' if encrypted else 'non chiffrée'}"
    )

    _telemetry_track("identity_created", algorithm="Ed25519", tier=tier)

    return {
        "agent_name":  agent_name,
        "agent_id":    agent_id,
        "identity":    identity,
        "key_path":    str(key_path),
        "encrypted":   encrypted,
        "tier":        tier,
        "created_at":  identity["created_at"],
    }


def load_agent_identity(agent_name: str) -> Dict[str, Any]:
    """
    Charge le document d'identité d'un agent depuis le disque.

    Args:
        agent_name: Nom de l'agent

    Returns:
        Dict identity (agent_id, public_key, algorithm, created_at)

    Raises:
        FileNotFoundError: Agent introuvable
    """
    from aiss.agent_registry import get_agent_dir

    identity_path = get_agent_dir(agent_name) / "identity.json"

    if not identity_path.exists():
        raise FileNotFoundError(
            f"Identité introuvable pour '{agent_name}'. "
            f"Créez l'agent avec : piqrypt identity create"
        )

    identity = json.loads(identity_path.read_text())
    identity["agent_name"] = agent_name
    return identity


def list_agent_identities() -> list:
    """
    Liste tous les agents enregistrés avec leurs identités.

    Returns:
        Liste de dicts {agent_name, agent_id, tier, created_at, last_seen}
    """
    from aiss.agent_registry import list_agents
    return list_agents()


def secure_agent_key(
    agent_name: str,
    new_passphrase: str,
    old_passphrase: Optional[str] = None,
) -> bool:
    """
    Chiffre (ou rechiffre) la clé privée d'un agent avec une passphrase.

    Utilisé par `piqrypt identity secure` pour protéger une clé
    précédemment stockée en clair.

    Args:
        agent_name:     Nom de l'agent
        new_passphrase: Nouvelle passphrase
        old_passphrase: Ancienne passphrase (si clé déjà chiffrée)

    Returns:
        True si succès
    """
    from aiss.agent_registry import get_agent_dir
    from aiss.key_store import (
        is_encrypted,
        load_plaintext_key, save_encrypted_key,
    )

    agent_dir = get_agent_dir(agent_name)
    enc_path   = agent_dir / "private.key.enc"
    plain_path = agent_dir / "private.key.json"

    key_path = enc_path if enc_path.exists() else plain_path

    if not key_path.exists():
        raise FileNotFoundError(f"Clé introuvable pour '{agent_name}'")

    if is_encrypted(key_path):
        # Rechiffrement : déchiffrer avec l'ancienne, chiffrer avec la nouvelle
        from aiss.key_store import load_encrypted_key
        raw_key = load_encrypted_key(key_path, old_passphrase)
        key_path.unlink()
        save_encrypted_key(raw_key, new_passphrase, enc_path)
    else:
        # Clé en clair → chiffrement initial
        raw_key = load_plaintext_key(key_path)
        plain_path_bak = plain_path.with_suffix(".json.bak")
        plain_path.rename(plain_path_bak)
        save_encrypted_key(raw_key, new_passphrase, enc_path)

    logger.info(f"[Identity] Clé de '{agent_name}' (re)chiffrée avec succès")
    return True


# ─── Public API update ────────────────────────────────────────────────────────
__all__ = [
    "generate_keypair",
    "derive_agent_id",
    "verify_agent_id",
    "export_identity",
    "create_rotation_attestation",
    "create_rotation_pcp_event",
    # v1.8.4
    "create_agent_identity",
    "load_agent_identity",
    "list_agent_identities",
    "secure_agent_key",
]
