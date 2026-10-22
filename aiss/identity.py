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

import hashlib
import json
import struct
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


def derive_agent_id_aiss21(public_key_ed: bytes, public_key_pq: bytes) -> str:
    """
    Derive deterministic AISS-2.1 agent ID from both public keys.

    Formule (AISS-2.1, spécification à rédiger — chantier G) :
        data  = b"PiQrypt-AISS-2.1-agent-id\\x00"
              || struct.pack(">I", len(pk_ed)) || pk_ed
              || struct.pack(">I", len(pk_pq)) || pk_pq
        agent_id = BASE58( SHA-512(data) )[0:32]

    La séparation de domaine empêche toute collision avec les agent_id AISS-1.

    Args:
        public_key_ed: Clé publique Ed25519 (exactement 32 bytes)
        public_key_pq: Clé publique ML-DSA-65 (exactement 1952 bytes)

    Returns:
        agent_id de 32 caractères Base58

    Raises:
        ValueError: Si les tailles de clés ne sont pas conformes
    """
    if len(public_key_ed) != 32:
        raise ValueError(
            f"public_key_ed doit faire 32 bytes (Ed25519), reçu {len(public_key_ed)}"
        )
    if len(public_key_pq) != 1952:
        raise ValueError(
            f"public_key_pq doit faire 1952 bytes (ML-DSA-65), reçu {len(public_key_pq)}"
        )
    data = (
        b"PiQrypt-AISS-2.1-agent-id\x00"
        + struct.pack(">I", len(public_key_ed))
        + public_key_ed
        + struct.pack(">I", len(public_key_pq))
        + public_key_pq
    )
    digest = hashlib.sha512(data).digest()
    return ed25519.encode_base58(digest)[:32]


def export_identity_aiss21(
    agent_id: str,
    public_key_ed: bytes,
    public_key_pq: bytes,
) -> Dict[str, Any]:
    """
    Export AISS-2.1 agent identity document (AISS-2.1, spécification à rédiger — chantier G).

    Contient les deux clés publiques (Ed25519 + ML-DSA-65) encodées avec le
    préfixe "base64:" (même convention que les signatures AISS-2.1).
    L'agent_id fourni est recalculé et comparé ; une incohérence lève ValueError.

    Args:
        agent_id:      agent_id AISS-2.1 (doit correspondre aux clés fournies)
        public_key_ed: Clé publique Ed25519 (32 bytes)
        public_key_pq: Clé publique ML-DSA-65 (1952 bytes)

    Returns:
        Document d'identité AISS-2.1

    Raises:
        ValueError: Si agent_id incohérent avec les clés ou tailles incorrectes
    """
    import base64 as _b64
    computed_id = derive_agent_id_aiss21(public_key_ed, public_key_pq)
    if computed_id != agent_id:
        raise ValueError(
            f"agent_id incohérent : fourni {agent_id!r}, calculé {computed_id!r}"
        )
    return {
        "version": "AISS-2.1",
        "agent_id": agent_id,
        "public_key_classical": "base64:" + _b64.b64encode(public_key_ed).decode("ascii"),
        "public_key_pq": "base64:" + _b64.b64encode(public_key_pq).decode("ascii"),
        "algorithms": ["Ed25519", "ML-DSA-65"],
        "created_at": int(time.time()),
    }


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
    hybrid: bool = False,
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
        hybrid:     False (défaut) : identité AISS-1, comportement inchangé.
                    True : identité hybride AISS-2.1 (Ed25519 + ML-DSA-65).
                    La passphrase est alors obligatoire (8 caractères minimum,
                    NIST SP 800-63B) et protège les deux clés privées, chacune
                    avec son propre sel : private.key.enc (v1) et
                    private_pq.key.enc (v2). Le retour ajoute pq_key_path et
                    hybrid=True.

    Returns:
        Dict avec identity, agent_id, agent_name, key_path, encrypted

    Raises:
        ValueError: Si agent_name est vide ou invalide, ou (hybrid) si la
                    passphrase est absente ou trop courte
        FileExistsError: (hybrid) si l'agent possède déjà une identité ou des clés
    """
    if not agent_name or not agent_name.strip():
        raise ValueError("Le nom de l'agent ne peut pas être vide")

    if hybrid:
        return _create_hybrid_agent_identity(
            agent_name, passphrase, metadata, tier, base_dir
        )

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


# ─── AISS-2.1 : identités hybrides (Ed25519 + ML-DSA-65) ─────────────────────

HYBRID_MIN_PASSPHRASE_LEN = 8  # NIST SP 800-63B


def _validate_hybrid_passphrase(passphrase: Any) -> None:
    """Passphrase obligatoire pour toute identité hybride (règle de create/upgrade)."""
    import unicodedata
    if not isinstance(passphrase, str) or not passphrase.strip():
        raise ValueError("Une passphrase est obligatoire pour une identité hybride")
    if len(unicodedata.normalize("NFKC", passphrase)) < HYBRID_MIN_PASSPHRASE_LEN:
        raise ValueError(
            f"La passphrase d'une identité hybride doit faire au moins "
            f"{HYBRID_MIN_PASSPHRASE_LEN} caractères (NIST SP 800-63B)"
        )


def _atomic_write_json(path: Path, obj: Dict[str, Any], mode: int = 0o644) -> None:
    """Écrit un JSON de façon atomique : temporaire O_EXCL + fsync + os.replace.

    Un temporaire périmé (plantage antérieur) est supprimé, avec une seule reprise.
    En cas d'échec, le fichier cible existant reste intact et aucun temporaire ne subsiste.
    """
    import os
    path = Path(path)
    tmp = path.parent / (path.name + ".tmp")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(str(tmp), flags, mode)
    except FileExistsError:
        os.unlink(str(tmp))
        fd = os.open(str(tmp), flags, mode)
    try:
        try:
            view = memoryview(json.dumps(obj, indent=2).encode("utf-8"))
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(str(tmp), str(path))
    except BaseException:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise


def _missing_dirs(paths) -> set:
    """Répertoires de `paths` (et leurs ancêtres) qui n'existent pas encore."""
    missing = set()
    for d in paths:
        p = Path(d)
        while not p.exists() and p not in missing:
            missing.add(p)
            p = p.parent
    return missing


def _create_hybrid_agent_identity(
    agent_name: str,
    passphrase: Optional[str],
    metadata: Optional[Dict[str, Any]],
    tier: str,
    base_dir: Optional[str],
) -> Dict[str, Any]:
    """Création d'une identité hybride AISS-2.1 (voir create_agent_identity(hybrid=True)).

    Ordre d'écriture : private.key.enc, private_pq.key.enc, identity.json (atomique),
    puis enregistrement au registre. Un identity.json présent signifie donc que les
    deux clés sont en place. En cas d'échec, seul ce que cet appel a créé est supprimé.

    Gating : aucun contrôle de licence propre à la création. La génération de la clé
    ML-DSA-65 passe par aiss.crypto.dilithium, dont le compteur de démonstration
    (1000 opérations par processus) avance sans licence 'quantum'.
    """
    import os
    from aiss.crypto import dilithium
    from aiss.exceptions import CryptoBackendError
    from aiss.agent_registry import (
        get_agent_dir, register_agent, unregister_agent,
        get_events_plain_dir, get_events_enc_dir, get_keys_dir, get_tsi_dir,
        _safe_name,
    )
    from aiss.key_store import save_encrypted_key, save_encrypted_pq_key

    _validate_hybrid_passphrase(passphrase)
    if dilithium is None or not dilithium.is_available():
        raise CryptoBackendError(
            "ML-DSA-65",
            "Une identité hybride requiert un backend ML-DSA-65 "
            "(pip install piqrypt[post-quantum])",
        )

    if base_dir is not None:
        agent_dir = Path(base_dir) / "agents" / agent_name
        wanted_dirs = [agent_dir]
    else:
        _safe_name(agent_name)
        agent_dir = get_agent_dir(agent_name)
        wanted_dirs = [
            agent_dir,
            get_events_plain_dir(agent_name),
            get_events_enc_dir(agent_name),
            get_keys_dir(agent_name),
            get_tsi_dir(agent_name),
        ]

    key_path = agent_dir / "private.key.enc"
    pq_key_path = agent_dir / "private_pq.key.enc"
    identity_path = agent_dir / "identity.json"
    for existing in (identity_path, key_path, pq_key_path, agent_dir / "private.key.json"):
        if existing.exists():
            raise FileExistsError(
                f"L'agent '{agent_name}' possède déjà une identité ou des clés "
                f"({existing.name}) : création hybride refusée"
            )

    private_key, public_key = generate_keypair()
    private_key_pq, public_key_pq = dilithium.generate_keypair()
    agent_id = derive_agent_id_aiss21(public_key, public_key_pq)
    identity = export_identity_aiss21(agent_id, public_key, public_key_pq)

    created_dirs = _missing_dirs(wanted_dirs)
    created_files = []
    registered = False
    try:
        for d in wanted_dirs:
            d.mkdir(parents=True, exist_ok=True)
        if base_dir is None:
            agent_dir.chmod(0o700)

        created_files.append(key_path)
        save_encrypted_key(private_key, passphrase, key_path)
        created_files.append(pq_key_path)
        save_encrypted_pq_key(private_key_pq, passphrase, pq_key_path)
        created_files.append(identity_path)
        _atomic_write_json(identity_path, identity)

        if base_dir is None:
            register_agent(
                agent_name=agent_name,
                agent_id=agent_id,
                tier=tier,
                metadata=metadata,
            )
            registered = True
    except BaseException:
        if registered:
            unregister_agent(agent_name)
        for f in created_files:
            for leftover in (f, f.parent / (f.name + ".tmp")):
                try:
                    os.unlink(str(leftover))
                except OSError:
                    pass
        for d in sorted(created_dirs, key=lambda p: len(p.parts), reverse=True):
            try:
                d.rmdir()
            except OSError:
                pass
        raise

    logger.info(
        f"[Identity] Agent hybride '{agent_name}' créé — "
        f"ID: {agent_id[:16]}... — clés Ed25519 + ML-DSA-65 chiffrées"
    )
    _telemetry_track("identity_created", algorithm="Ed25519+ML-DSA-65", tier=tier)

    return {
        "agent_name":  agent_name,
        "agent_id":    agent_id,
        "identity":    identity,
        "key_path":    str(key_path),
        "pq_key_path": str(pq_key_path),
        "encrypted":   True,
        "hybrid":      True,
        "tier":        tier,
        "created_at":  identity["created_at"],
    }


def load_agent_pq_key(
    agent_name: str,
    passphrase: str,
    base_dir: Optional[str] = None,
) -> bytes:
    """
    Charge et déchiffre la clé privée ML-DSA-65 (4032 octets) d'une identité hybride.

    Args:
        agent_name: Nom de l'agent
        passphrase: Passphrase de l'identité
        base_dir:   Répertoire racine optionnel (tests/CI), comme create_agent_identity

    Raises:
        FileNotFoundError:      Pas de private_pq.key.enc (identité non hybride)
        InvalidPassphraseError: Passphrase incorrecte
        KeyFileCorruptedError:  Fichier invalide
    """
    from aiss.agent_registry import get_agent_dir
    from aiss.key_store import load_encrypted_pq_key

    if base_dir is not None:
        agent_dir = Path(base_dir) / "agents" / agent_name
    else:
        agent_dir = get_agent_dir(agent_name)
    return load_encrypted_pq_key(agent_dir / "private_pq.key.enc", passphrase)


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
