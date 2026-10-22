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
from typing import Dict, Any, List, Tuple, Optional

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
    """Écrit un JSON de façon atomique (voir _atomic_write_bytes)."""
    _atomic_write_bytes(path, json.dumps(obj, indent=2).encode("utf-8"), mode)


def _stage_bytes(path: Path, data: bytes, mode: int = 0o644) -> Path:
    """Écrit `data` dans le temporaire <path>.tmp (O_EXCL, écriture complète, fsync) et
    renvoie son chemin, sans toucher à `path`. Un temporaire périmé (plantage
    antérieur) est supprimé, avec une seule reprise. En cas d'échec, le temporaire
    est supprimé."""
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
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise
    return tmp


def _atomic_write_bytes(path: Path, data: bytes, mode: int = 0o644) -> None:
    """Écrit des octets de façon atomique : temporaire O_EXCL + fsync + os.replace.

    En cas d'échec, le fichier cible existant reste intact et aucun temporaire ne subsiste.
    """
    import os
    tmp = _stage_bytes(path, data, mode)
    try:
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


def _erase_all(buffers) -> None:
    from aiss.key_store import _secure_erase
    for buf in buffers:
        _secure_erase(buf)


def _create_hybrid_agent_identity(
    agent_name: str,
    passphrase: Optional[str],
    metadata: Optional[Dict[str, Any]],
    tier: str,
    base_dir: Optional[str],
) -> Dict[str, Any]:
    """Création d'une identité hybride AISS-2.1 (voir create_agent_identity(hybrid=True)).

    Zéroïsation au mieux : les clés privées générées sont tenues dans des bytearray
    effacés dans un bloc finally. Cela réduit la fenêtre d'exposition sans la supprimer :
    bytes Python immuables et copiables par l'interpréteur, copies internes des
    bibliothèques de chiffrement, pas de mlock, swap non contrôlé.
    """
    buffers: list = []
    try:
        return _create_hybrid_agent_identity_impl(
            agent_name, passphrase, metadata, tier, base_dir, buffers)
    finally:
        _erase_all(buffers)


def _create_hybrid_agent_identity_impl(
    agent_name: str,
    passphrase: Optional[str],
    metadata: Optional[Dict[str, Any]],
    tier: str,
    base_dir: Optional[str],
    _buffers: list,
) -> Dict[str, Any]:
    """Corps de _create_hybrid_agent_identity ; _buffers recueille les clés à effacer.

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
    private_key = bytearray(private_key)
    _buffers.append(private_key)
    private_key_pq, public_key_pq = dilithium.generate_keypair()
    private_key_pq = bytearray(private_key_pq)
    _buffers.append(private_key_pq)
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


# ─── AISS-2.1 : mise à niveau d'une identité AISS-1 (liaison signée) ──────────

class IdentityBindingError(ValueError):
    """Liaison d'identité AISS-2.1 invalide, ou mise à niveau refusée."""


# Préfixe de domaine distinct de celui des événements (b"PiQrypt-AISS-2.1\x00").
_BINDING_DOMAIN_PREFIX = b"PiQrypt-AISS-2.1-binding\x00"
_ED25519_PK_SIZE = 32
_MLDSA65_PK_SIZE = 1952


def _domain_signed_message(domain_prefix: bytes, unsigned_doc: Dict[str, Any]) -> bytes:
    """Message M' : préfixe de domaine, étiquette d'algorithmes, contexte vide, puis JCS
    du document sans signatures (même construction que les événements AISS-2.1)."""
    from aiss.canonical_aiss21 import canonicalize
    from aiss.stamp_aiss2 import _ALGO_LABEL
    return (
        domain_prefix + bytes([len(_ALGO_LABEL)]) + _ALGO_LABEL + b"\x00"
        + canonicalize(unsigned_doc)
    )


def _binding_signed_message(unsigned_binding: Dict[str, Any]) -> bytes:
    """Message M' signé par les deux clés pour une liaison d'identité."""
    return _domain_signed_message(_BINDING_DOMAIN_PREFIX, unsigned_binding)


def _b64_prefixed(raw: bytes) -> str:
    import base64
    return "base64:" + base64.b64encode(raw).decode("ascii")


def _decode_b64_prefixed(value: Any, what: str, expected_len: Optional[int] = None) -> bytes:
    """Préfixe "base64:" obligatoire, alphabet strict (validate=True), taille exacte."""
    import base64
    import binascii
    if not isinstance(value, str) or not value.startswith("base64:"):
        raise IdentityBindingError(f"{what} : préfixe 'base64:' obligatoire")
    try:
        raw = base64.b64decode(value[7:], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise IdentityBindingError(f"{what} : base64 invalide ({exc})")
    if expected_len is not None and len(raw) != expected_len:
        raise IdentityBindingError(
            f"{what} : {len(raw)} octets au lieu de {expected_len}"
        )
    return raw


def _create_identity_binding(
    agent_id: str,
    private_key_ed: bytes,
    public_key_ed: bytes,
    private_key_pq: bytes,
    public_key_pq: bytes,
) -> Dict[str, Any]:
    """Construit et signe (Ed25519 ET ML-DSA-65, même message) la liaison AISS-2.1
    d'une identité AISS-1 : type "identity_binding", binding_assurance "classical_only"."""
    from aiss.crypto import dilithium
    if len(public_key_ed) != _ED25519_PK_SIZE:
        raise ValueError(f"public_key_ed doit faire {_ED25519_PK_SIZE} octets")
    if len(public_key_pq) != _MLDSA65_PK_SIZE:
        raise ValueError(f"public_key_pq doit faire {_MLDSA65_PK_SIZE} octets")

    unsigned = {
        "version": "AISS-2.1",
        "type": "identity_binding",
        "agent_id": agent_id,
        "public_key_classical": _b64_prefixed(public_key_ed),
        "public_key_pq": _b64_prefixed(public_key_pq),
        "binding_assurance": "classical_only",
        "created_at": int(time.time()),
    }
    message = _binding_signed_message(unsigned)
    binding = dict(unsigned)
    binding["signatures"] = {
        "classical": {
            "algorithm": "Ed25519",
            "signature": _b64_prefixed(ed25519.sign(private_key_ed, message)),
        },
        "post_quantum": {
            "algorithm": "ML-DSA-65",
            "signature": _b64_prefixed(dilithium.sign(private_key_pq, message)),
        },
    }
    return binding


def _check_identity_binding(identity: Any) -> None:
    """Lève IdentityBindingError (ou InvalidSignatureError) à la première anomalie."""
    from aiss.crypto import dilithium
    from aiss.exceptions import InvalidSignatureError

    if not isinstance(identity, dict):
        raise IdentityBindingError("identité absente ou invalide")
    binding = identity.get("binding")
    if not isinstance(binding, dict):
        raise IdentityBindingError("liaison absente")
    if binding.get("version") != "AISS-2.1" or binding.get("type") != "identity_binding":
        raise IdentityBindingError("version ou type de liaison inattendu")
    if binding.get("binding_assurance") != "classical_only":
        raise IdentityBindingError("binding_assurance inattendu")

    agent_id = identity.get("agent_id")
    if not isinstance(agent_id, str) or binding.get("agent_id") != agent_id:
        raise IdentityBindingError("agent_id de la liaison différent de celui de l'identité")

    pk_ed = _decode_b64_prefixed(
        binding.get("public_key_classical"), "public_key_classical", _ED25519_PK_SIZE)
    pk_pq = _decode_b64_prefixed(
        binding.get("public_key_pq"), "public_key_pq", _MLDSA65_PK_SIZE)

    import base64
    import binascii
    try:
        historical = base64.b64decode(identity.get("public_key"), validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise IdentityBindingError(f"public_key historique invalide ({exc})")
    if historical != pk_ed:
        raise IdentityBindingError("clé classique de la liaison différente de public_key")
    if "public_key_pq" in identity and _decode_b64_prefixed(
            identity["public_key_pq"], "identity.public_key_pq", _MLDSA65_PK_SIZE) != pk_pq:
        raise IdentityBindingError("public_key_pq de l'identité différente de la liaison")
    if derive_agent_id(pk_ed) != agent_id:
        raise IdentityBindingError("agent_id ne dérive pas de la clé classique")

    signatures = binding.get("signatures")
    if not isinstance(signatures, dict):
        raise IdentityBindingError("signatures absentes")
    classical, post_quantum = signatures.get("classical"), signatures.get("post_quantum")
    if not isinstance(classical, dict) or not isinstance(post_quantum, dict):
        raise IdentityBindingError("les deux signatures sont obligatoires")
    if classical.get("algorithm") != "Ed25519" or post_quantum.get("algorithm") != "ML-DSA-65":
        raise IdentityBindingError("algorithme de signature inattendu")
    sig_ed = _decode_b64_prefixed(classical.get("signature"), "signature Ed25519")
    sig_pq = _decode_b64_prefixed(post_quantum.get("signature"), "signature ML-DSA-65")

    message = _binding_signed_message(
        {k: v for k, v in binding.items() if k != "signatures"})
    try:
        ed25519.verify(pk_ed, message, sig_ed)
    except InvalidSignatureError:
        raise IdentityBindingError("signature Ed25519 de la liaison invalide")
    if not dilithium.verify(pk_pq, message, sig_pq):
        raise IdentityBindingError("signature ML-DSA-65 de la liaison invalide")


def verify_identity_binding(identity: Dict[str, Any]) -> bool:
    """
    Vérifie la liaison AISS-2.1 d'une identité AISS-1 mise à niveau.

    Contrôles : les deux signatures (Ed25519 et ML-DSA-65) sur le même message de
    domaine "binding" ; binding.agent_id == identity.agent_id ; clé classique de la
    liaison identique à public_key historique ; tailles 32 et 1952 octets ; préfixe
    "base64:" obligatoire et décodage strict ; agent_id dérivé de la clé classique
    (sinon un tiers pourrait lier sa propre clé à l'agent_id d'un autre).

    Returns:
        True si la liaison est valide, False pour toute anomalie (jamais d'exception
        sur un document malformé).

    Raises:
        CryptoBackendError: backend ML-DSA-65 absent (la vérification est impossible)
    """
    from aiss.exceptions import InvalidSignatureError
    try:
        _check_identity_binding(identity)
    except (IdentityBindingError, InvalidSignatureError, KeyError, TypeError,
            ValueError, AttributeError):
        return False
    return True


def identity_binding_assurance(identity: Dict[str, Any]) -> str:
    """
    Niveau d'assurance de l'identité, toujours recalculé (jamais lu comme valeur de confiance).

    - "hybrid" : identité AISS-2.1 native dont l'agent_id dérive des deux clés
      (derive_agent_id_aiss21).
    - "classical_only" : identité AISS-1 mise à niveau, reposant sur une liaison valide
      (agent_id issu de la clé Ed25519 seule ; la clé ML-DSA-65 lui est liée par signature).

    Un document qui porte public_key_classical avec binding ou avec public_key est ambigu :
    il est rejeté ici même.

    Raises:
        IdentityBindingError: document ambigu, et tous les autres cas, y compris une
            identité AISS-1 pure.
    """
    if not isinstance(identity, dict):
        raise IdentityBindingError("identité absente ou invalide")
    if "public_key_classical" in identity and ("binding" in identity or "public_key" in identity):
        raise IdentityBindingError(
            "identité ambiguë : public_key_classical ne peut pas être combinée à "
            "binding ou à public_key"
        )
    if "public_key_classical" in identity and "public_key_pq" in identity:
        pk_ed = _decode_b64_prefixed(
            identity["public_key_classical"], "public_key_classical", _ED25519_PK_SIZE)
        pk_pq = _decode_b64_prefixed(
            identity["public_key_pq"], "public_key_pq", _MLDSA65_PK_SIZE)
        if derive_agent_id_aiss21(pk_ed, pk_pq) != identity.get("agent_id"):
            raise IdentityBindingError("agent_id ne dérive pas des deux clés")
        return "hybrid"
    if "binding" in identity:
        if verify_identity_binding(identity):
            return "classical_only"
        raise IdentityBindingError("liaison d'identité invalide")
    raise IdentityBindingError("ni identité hybride ni liaison : identité AISS-1 pure")


def upgrade_agent_identity(
    agent_name: str,
    passphrase: str,
    old_passphrase: Optional[str] = None,
    base_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Met à niveau une identité AISS-1 existante vers l'AISS-2.1 sans changer l'agent_id.

    Génère une paire ML-DSA-65, signe une liaison (Ed25519 + ML-DSA-65), écrit
    private_pq.key.enc (v2, protégée par `passphrase`, 8 caractères minimum) puis
    met à jour identity.json atomiquement : champs historiques conservés tels quels
    (agent_id, public_key), ajout de public_key_pq et binding. L'ancien fichier est
    copié à l'identique dans identity.pre-upgrade.json. La clé Ed25519 garde son
    stockage actuel (pas de rechiffrement).

    Args:
        agent_name:     Nom de l'agent
        passphrase:     Passphrase de la clé ML-DSA-65 (obligatoire)
        old_passphrase: Passphrase actuelle de la clé Ed25519, si elle est chiffrée
        base_dir:       Répertoire racine optionnel (tests/CI), comme create_agent_identity

    Returns:
        Dict agent_name, agent_id, identity (nouveau document), pq_key_path,
        backup_path, binding_assurance ("classical_only")

    Raises:
        IdentityBindingError: Identité déjà hybride ou déjà mise à niveau, état
            incohérent (clé PQ orpheline, sauvegarde existante, clé ≠ public_key)
        ValueError: Passphrase invalide, ou clé Ed25519 chiffrée sans old_passphrase
        FileNotFoundError: Identité ou clé introuvable

    Zéroïsation au mieux : la clé Ed25519 chargée et la clé ML-DSA-65 générée sont
    tenues dans des bytearray effacés dans un bloc finally. Cela réduit la fenêtre
    d'exposition sans la supprimer : bytes Python immuables et copiables par
    l'interpréteur, copies internes des bibliothèques de chiffrement, pas de mlock,
    swap non contrôlé.
    """
    buffers: list = []
    try:
        return _upgrade_agent_identity_impl(
            agent_name, passphrase, old_passphrase, base_dir, buffers)
    finally:
        _erase_all(buffers)


def _upgrade_agent_identity_impl(
    agent_name: str,
    passphrase: str,
    old_passphrase: Optional[str],
    base_dir: Optional[str],
    _buffers: list,
) -> Dict[str, Any]:
    """Corps de upgrade_agent_identity ; _buffers recueille les clés à effacer."""
    import os
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from aiss.crypto import dilithium
    from aiss.exceptions import CryptoBackendError
    from aiss.agent_registry import get_agent_dir
    from aiss.key_store import (
        is_encrypted, load_encrypted_key, load_plaintext_key, save_encrypted_pq_key,
    )

    _validate_hybrid_passphrase(passphrase)

    if base_dir is not None:
        agent_dir = Path(base_dir) / "agents" / agent_name
    else:
        agent_dir = get_agent_dir(agent_name)
    identity_path = agent_dir / "identity.json"
    pq_key_path = agent_dir / "private_pq.key.enc"
    backup_path = agent_dir / "identity.pre-upgrade.json"

    if not identity_path.exists():
        raise FileNotFoundError(f"Identité introuvable pour '{agent_name}'")
    original_bytes = identity_path.read_bytes()
    identity = json.loads(original_bytes.decode("utf-8"))

    if (
        "binding" in identity or "public_key_pq" in identity
        or "public_key_classical" in identity
        or str(identity.get("version", "")).startswith("AISS-2")
    ):
        raise IdentityBindingError(
            f"L'identité de '{agent_name}' est déjà hybride ou déjà mise à niveau : "
            f"aucune régénération"
        )
    if pq_key_path.exists():
        raise IdentityBindingError(
            f"{pq_key_path.name} existe déjà sans liaison dans identity.json "
            f"(mise à niveau interrompue ?) : vérifiez puis supprimez-le manuellement"
        )
    if backup_path.exists():
        raise IdentityBindingError(
            f"{backup_path.name} existe déjà : vérifiez puis déplacez-le manuellement"
        )
    if dilithium is None or not dilithium.is_available():
        raise CryptoBackendError(
            "ML-DSA-65",
            "La mise à niveau requiert un backend ML-DSA-65 "
            "(pip install piqrypt[post-quantum])",
        )

    enc_path = agent_dir / "private.key.enc"
    key_path = enc_path if enc_path.exists() else agent_dir / "private.key.json"
    if not key_path.exists():
        raise FileNotFoundError(f"Clé Ed25519 introuvable pour '{agent_name}'")
    if is_encrypted(key_path):
        if old_passphrase is None:
            raise ValueError(
                "La clé Ed25519 est chiffrée : old_passphrase (passphrase actuelle) requise"
            )
        private_key = load_encrypted_key(key_path, old_passphrase)
    else:
        private_key = load_plaintext_key(key_path)
    private_key = bytearray(private_key)
    _buffers.append(private_key)

    public_key = Ed25519PrivateKey.from_private_bytes(private_key).public_key() \
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    agent_id = identity.get("agent_id")
    if (
        ed25519.encode_base64(public_key) != identity.get("public_key")
        or derive_agent_id(public_key) != agent_id
    ):
        raise IdentityBindingError(
            "La clé Ed25519 ne correspond pas à identity.json : mise à niveau refusée"
        )

    private_key_pq, public_key_pq = dilithium.generate_keypair()
    private_key_pq = bytearray(private_key_pq)
    _buffers.append(private_key_pq)
    binding = _create_identity_binding(
        agent_id, private_key, public_key, private_key_pq, public_key_pq)
    upgraded = dict(identity)
    upgraded["public_key_pq"] = _b64_prefixed(public_key_pq)
    upgraded["binding"] = binding
    if not verify_identity_binding(upgraded):  # auto-contrôle avant toute écriture
        raise IdentityBindingError("liaison générée invalide : mise à niveau annulée")

    created_files = []
    try:
        created_files.append(pq_key_path)
        save_encrypted_pq_key(private_key_pq, passphrase, pq_key_path)
        created_files.append(backup_path)
        _atomic_write_bytes(backup_path, original_bytes)
        _atomic_write_json(identity_path, upgraded)
    except BaseException:
        for f in created_files:
            for leftover in (f, f.parent / (f.name + ".tmp")):
                try:
                    os.unlink(str(leftover))
                except OSError:
                    pass
        raise

    logger.info(
        f"[Identity] Agent '{agent_name}' mis à niveau AISS-2.1 "
        f"(classical_only) — ID inchangé : {agent_id[:16]}..."
    )
    _telemetry_track("identity_upgraded", algorithm="Ed25519+ML-DSA-65", tier="n/a")

    return {
        "agent_name":        agent_name,
        "agent_id":          agent_id,
        "identity":          upgraded,
        "pq_key_path":       str(pq_key_path),
        "backup_path":       str(backup_path),
        "binding_assurance": "classical_only",
    }


# ─── AISS-2.1 : rotation de clés hybride (quatre signatures) ──────────────────

# Préfixe de domaine propre à la rotation (distinct des événements et de la liaison).
_ROTATION_DOMAIN_PREFIX = b"PiQrypt-AISS-2.1-rotation\x00"
_ROTATION_SIGNATURES = (
    ("previous_classical", "Ed25519"),
    ("previous_post_quantum", "ML-DSA-65"),
    ("new_classical", "Ed25519"),
    ("new_post_quantum", "ML-DSA-65"),
)


def _aiss21_identity_keys(identity: Any):
    """Valide une identité AISS-2.1 via identity_binding_assurance et renvoie
    (agent_id, clé Ed25519, clé ML-DSA-65) — hybride native ou mise à niveau.

    Raises:
        IdentityBindingError: identité invalide, ambiguë ou AISS-1 pure
    """
    if not isinstance(identity, dict):
        raise IdentityBindingError("identité absente ou invalide")
    if "public_key_classical" in identity and ("binding" in identity or "public_key" in identity):
        raise IdentityBindingError("identité ambiguë")
    identity_binding_assurance(identity)  # lève si invalide
    source = identity if "public_key_classical" in identity else identity["binding"]
    return (
        identity["agent_id"],
        _decode_b64_prefixed(source["public_key_classical"], "public_key_classical",
                             _ED25519_PK_SIZE),
        _decode_b64_prefixed(source["public_key_pq"], "public_key_pq", _MLDSA65_PK_SIZE),
    )


def create_rotation_attestation_hybrid(
    previous_identity: Dict[str, Any],
    previous_private_key_ed: bytes,
    previous_private_key_pq: bytes,
    new_private_key_ed: bytes,
    new_public_key_ed: bytes,
    new_private_key_pq: bytes,
    new_public_key_pq: bytes,
    rotation_timestamp: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Attestation de rotation hybride AISS-2.1 : l'ancienne identité désigne la nouvelle,
    et les DEUX paires de clés (ancienne et nouvelle) signent le même message.

    Document : version "AISS-2.1", type "key_rotation", previous_agent_id,
    previous_public_key_classical / previous_public_key_pq, new_agent_id (dérivé des
    deux nouvelles clés), new_public_key_classical / new_public_key_pq (préfixe
    "base64:"), rotation_timestamp. Quatre signatures (previous_classical,
    previous_post_quantum, new_classical, new_post_quantum) sur un message à préfixe de
    domaine b"PiQrypt-AISS-2.1-rotation\\x00" (étiquette d'algorithmes, contexte vide,
    JCS du document sans signatures).

    L'ancienne identité peut être hybride native ou mise à niveau ; ses clés sont celles
    de `previous_identity`, validée par identity_binding_assurance.

    Zéroïsation : les clés privées reçues appartiennent à l'appelant ; cette fonction n'en
    crée aucune copie et ne les efface pas. Pour réduire la fenêtre d'exposition,
    l'appelant peut les passer en bytearray (acceptés) et les effacer avec _secure_erase
    ensuite. Limites de Python : bytes immuables et copiables par l'interpréteur, copies
    internes des bibliothèques de chiffrement, pas de mlock, swap non contrôlé.

    Raises:
        IdentityBindingError: ancienne identité invalide
        ValueError: tailles de clés incorrectes, rotation vers soi-même, ou clés privées
            ne correspondant pas aux clés publiques (auto-contrôle de l'attestation produite)
    """
    from aiss.crypto import dilithium

    previous_id, previous_pk_ed, previous_pk_pq = _aiss21_identity_keys(previous_identity)
    new_agent_id = derive_agent_id_aiss21(new_public_key_ed, new_public_key_pq)
    if new_agent_id == previous_id:
        raise ValueError("Rotation vers soi-même refusée : new_agent_id == previous_agent_id")

    unsigned = {
        "version": "AISS-2.1",
        "type": "key_rotation",
        "previous_agent_id": previous_id,
        "previous_public_key_classical": _b64_prefixed(previous_pk_ed),
        "previous_public_key_pq": _b64_prefixed(previous_pk_pq),
        "new_agent_id": new_agent_id,
        "new_public_key_classical": _b64_prefixed(new_public_key_ed),
        "new_public_key_pq": _b64_prefixed(new_public_key_pq),
        "rotation_timestamp": int(time.time()) if rotation_timestamp is None
        else int(rotation_timestamp),
    }
    message = _domain_signed_message(_ROTATION_DOMAIN_PREFIX, unsigned)
    signers = {
        "previous_classical": lambda: ed25519.sign(previous_private_key_ed, message),
        "previous_post_quantum": lambda: dilithium.sign(previous_private_key_pq, message),
        "new_classical": lambda: ed25519.sign(new_private_key_ed, message),
        "new_post_quantum": lambda: dilithium.sign(new_private_key_pq, message),
    }
    attestation = dict(unsigned)
    attestation["signatures"] = {
        name: {"algorithm": algorithm, "signature": _b64_prefixed(signers[name]())}
        for name, algorithm in _ROTATION_SIGNATURES
    }
    if not verify_rotation_attestation_hybrid(attestation, previous_identity):
        raise ValueError(
            "Attestation de rotation invalide : les clés privées ne correspondent pas "
            "aux clés publiques"
        )
    return attestation


def _check_rotation_attestation(attestation: Any, previous_identity: Any) -> None:
    from aiss.crypto import dilithium
    from aiss.exceptions import InvalidSignatureError

    if not isinstance(attestation, dict):
        raise IdentityBindingError("attestation absente ou invalide")
    if attestation.get("version") != "AISS-2.1" or attestation.get("type") != "key_rotation":
        raise IdentityBindingError("version ou type d'attestation inattendu")
    if not isinstance(attestation.get("rotation_timestamp"), int) \
            or isinstance(attestation.get("rotation_timestamp"), bool):
        raise IdentityBindingError("rotation_timestamp invalide")

    previous_id, previous_pk_ed, previous_pk_pq = _aiss21_identity_keys(previous_identity)
    if attestation.get("previous_agent_id") != previous_id:
        raise IdentityBindingError("previous_agent_id différent de l'identité précédente")
    if _decode_b64_prefixed(attestation.get("previous_public_key_classical"),
                            "previous_public_key_classical", _ED25519_PK_SIZE) != previous_pk_ed:
        raise IdentityBindingError("ancienne clé classique différente de l'identité précédente")
    if _decode_b64_prefixed(attestation.get("previous_public_key_pq"),
                            "previous_public_key_pq", _MLDSA65_PK_SIZE) != previous_pk_pq:
        raise IdentityBindingError("ancienne clé PQ différente de l'identité précédente")

    new_pk_ed = _decode_b64_prefixed(attestation.get("new_public_key_classical"),
                                     "new_public_key_classical", _ED25519_PK_SIZE)
    new_pk_pq = _decode_b64_prefixed(attestation.get("new_public_key_pq"),
                                     "new_public_key_pq", _MLDSA65_PK_SIZE)
    if attestation.get("new_agent_id") != derive_agent_id_aiss21(new_pk_ed, new_pk_pq):
        raise IdentityBindingError("new_agent_id ne dérive pas des deux nouvelles clés")
    if attestation["new_agent_id"] == previous_id:
        raise IdentityBindingError("rotation vers soi-même : new_agent_id == previous_agent_id")

    signatures = attestation.get("signatures")
    if not isinstance(signatures, dict):
        raise IdentityBindingError("signatures absentes")
    message = _domain_signed_message(
        _ROTATION_DOMAIN_PREFIX, {k: v for k, v in attestation.items() if k != "signatures"})
    keys = {
        "previous_classical": previous_pk_ed, "previous_post_quantum": previous_pk_pq,
        "new_classical": new_pk_ed, "new_post_quantum": new_pk_pq,
    }
    for name, algorithm in _ROTATION_SIGNATURES:
        entry = signatures.get(name)
        if not isinstance(entry, dict) or entry.get("algorithm") != algorithm:
            raise IdentityBindingError(f"signature {name} absente ou d'algorithme inattendu")
        sig = _decode_b64_prefixed(entry.get("signature"), f"signature {name}")
        if algorithm == "Ed25519":
            try:
                ed25519.verify(keys[name], message, sig)
            except InvalidSignatureError:
                raise IdentityBindingError(f"signature {name} invalide")
        elif not dilithium.verify(keys[name], message, sig):
            raise IdentityBindingError(f"signature {name} invalide")


def verify_rotation_attestation_hybrid(
    attestation: Dict[str, Any],
    previous_identity: Dict[str, Any],
) -> bool:
    """
    Vérifie une attestation de rotation hybride : les quatre signatures, new_agent_id
    dérivé des deux nouvelles clés, anciennes clés égales à celles de `previous_identity`
    (validée par identity_binding_assurance), décodage strict ("base64:", alphabet,
    tailles 32 et 1952).

    Returns:
        True si valide, False pour toute anomalie (jamais d'exception sur un document
        malformé).

    Raises:
        CryptoBackendError: backend ML-DSA-65 absent (vérification impossible)
    """
    from aiss.exceptions import InvalidSignatureError
    try:
        _check_rotation_attestation(attestation, previous_identity)
    except (IdentityBindingError, InvalidSignatureError, KeyError, TypeError,
            ValueError, AttributeError):
        return False
    return True


# ─── AISS-2.1 : rotation ancrée dans la chaîne (RFC §12.2) ────────────────────

def create_rotation_event_aiss21(
    previous_identity: Dict[str, Any],
    previous_private_key_ed: bytes,
    previous_private_key_pq: bytes,
    new_private_key_ed: bytes,
    new_public_key_ed: bytes,
    new_private_key_pq: bytes,
    new_public_key_pq: bytes,
    previous_hash: str,
    rotation_timestamp: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Événement AISS-2.1 de rotation, dernier événement de l'ANCIENNE chaîne.

    Signé en hybride par les anciennes clés (stamp_event_aiss2_hybrid, licence Pro
    requise comme pour tout événement hybride) sous l'agent_id de l'ancien agent. Son
    payload contient event_type "key_rotation" et l'attestation à quatre signatures de
    create_rotation_attestation_hybrid. La genèse de la nouvelle chaîne s'y ancre :

        old_chain: E1 → ... → En → ROTATION   (previous_hash = hash de En)
        new_chain: genèse(previous_hash = hash(ROTATION)) → ...

        rot  = create_rotation_event_aiss21(..., previous_hash=hash_de_En)
        gen  = stamp_genesis_event_aiss2_hybrid(..., public_key_pq=new_pub_pq,
                   rotation_previous_hash=compute_event_hash(rot))

    Args:
        previous_hash: hash du dernier événement de l'ancienne chaîne

    Raises:
        IdentityBindingError, ValueError: voir create_rotation_attestation_hybrid
    """
    from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid

    if not isinstance(previous_hash, str) or not previous_hash:
        raise ValueError("previous_hash (hash du dernier événement de l'ancienne chaîne) requis")
    attestation = create_rotation_attestation_hybrid(
        previous_identity, previous_private_key_ed, previous_private_key_pq,
        new_private_key_ed, new_public_key_ed, new_private_key_pq, new_public_key_pq,
        rotation_timestamp,
    )
    return stamp_event_aiss2_hybrid(
        previous_private_key_ed,
        previous_private_key_pq,
        attestation["previous_agent_id"],
        {"event_type": "key_rotation", "attestation": attestation},
        previous_hash=previous_hash,
        tsa_stamp_after=False,
    )


def _check_rotation_chain(old_events: Any, previous_identity: Any, new_genesis: Any) -> None:
    from aiss.chain import compute_event_hash
    from aiss.stamp_aiss2 import verify_aiss2_hybrid
    from aiss.verify import verify_chain

    if not isinstance(old_events, list) or not old_events:
        raise IdentityBindingError("ancienne chaîne absente")
    if not isinstance(new_genesis, dict):
        raise IdentityBindingError("genèse absente ou invalide")
    last = old_events[-1]
    if not isinstance(last, dict) or last.get("version") != "AISS-2.1":
        raise IdentityBindingError("le dernier événement doit être un événement AISS-2.1")
    payload = last.get("payload")
    if not isinstance(payload, dict) or payload.get("event_type") != "key_rotation":
        raise IdentityBindingError("le dernier événement n'est pas un événement de rotation")
    attestation = payload.get("attestation")
    if not verify_rotation_attestation_hybrid(attestation, previous_identity):
        raise IdentityBindingError("attestation de rotation invalide")
    if last.get("agent_id") != attestation["previous_agent_id"]:
        raise IdentityBindingError("agent_id de l'événement de rotation incohérent")

    verify_chain(old_events, previous_identity)

    if new_genesis.get("previous_hash") != compute_event_hash(last):
        raise IdentityBindingError("la genèse n'est pas ancrée sur l'événement de rotation")
    if new_genesis.get("agent_id") != attestation["new_agent_id"]:
        raise IdentityBindingError("agent_id de la genèse différent de new_agent_id")
    new_pk_ed = _decode_b64_prefixed(attestation["new_public_key_classical"],
                                     "new_public_key_classical", _ED25519_PK_SIZE)
    new_pk_pq = _decode_b64_prefixed(attestation["new_public_key_pq"],
                                     "new_public_key_pq", _MLDSA65_PK_SIZE)
    if new_genesis.get("version") != "AISS-2.1":
        raise IdentityBindingError("la genèse doit être un événement AISS-2.1")
    verify_aiss2_hybrid(new_genesis, new_pk_ed, new_pk_pq)


def verify_rotation_chain(
    old_events: List[Dict[str, Any]],
    previous_identity: Dict[str, Any],
    new_genesis: Dict[str, Any],
) -> bool:
    """
    Vérifie une rotation hybride ancrée dans la chaîne :

    - le dernier événement de `old_events` est un événement de rotation AISS-2.1 dont
      l'attestation est valide contre `previous_identity` (aucun événement ne peut donc
      suivre la rotation dans l'ancienne chaîne) ;
    - l'ancienne chaîne se vérifie (verify_chain) ;
    - new_genesis.previous_hash == compute_event_hash(événement de rotation) ;
    - new_genesis.agent_id == attestation.new_agent_id ;
    - la genèse est un événement AISS-2.1 correctement signé par les nouvelles clés
      de l'attestation.

    Returns:
        True si tout est valide, False pour toute anomalie (jamais d'exception sur un
        document malformé).

    Raises:
        CryptoBackendError: backend ML-DSA-65 absent (vérification impossible)
    """
    from aiss.exceptions import AISSError, CryptoBackendError
    try:
        _check_rotation_chain(old_events, previous_identity, new_genesis)
    except CryptoBackendError:
        raise
    except (IdentityBindingError, AISSError, KeyError, TypeError, ValueError, AttributeError):
        return False
    return True


def list_agent_identities() -> list:
    """
    Liste tous les agents enregistrés avec leurs identités.

    Returns:
        Liste de dicts {agent_name, agent_id, tier, created_at, last_seen}
    """
    from aiss.agent_registry import list_agents
    return list_agents()


def _retire_plaintext_key(
    agent_name: str,
    plain_path: Path,
    enc_path: Path,
    new_passphrase: str,
    original_key: bytes,
) -> None:
    """Supprime la clé en clair une fois le fichier chiffré installé ET relu.

    Le fichier chiffré est relu et déchiffré, puis comparé à la clé d'origine. Si égal,
    le fichier en clair est écrasé par des zéros, synchronisé (fsync), puis supprimé (plus
    de .bak). Si la suppression échoue : avertissement dans les logs, l'opération réussit.
    Si la relecture échoue ou diffère : le fichier en clair n'est pas touché, le fichier
    chiffré installé par cet appel est retiré (il masquerait sinon la clé en clair) et
    l'erreur est relevée.

    Limite : l'écrasement ne garantit pas l'effacement physique (journalisation du système
    de fichiers, SSD et wear-leveling, copies de sauvegarde, snapshots).
    """
    import os
    import secrets
    from aiss.key_store import load_encrypted_key, KeyFileCorruptedError

    try:
        reread = bytearray(load_encrypted_key(enc_path, new_passphrase))
        try:
            same = secrets.compare_digest(bytes(reread), bytes(original_key))
        finally:
            _erase_all([reread])
        if not same:
            raise KeyFileCorruptedError("la clé relue diffère de la clé d'origine")
    except BaseException as exc:
        try:
            os.unlink(str(enc_path))
        except OSError:
            pass
        logger.error(
            f"[Identity] Vérification du fichier chiffré de '{agent_name}' échouée "
            f"({exc}) : clé en clair conservée"
        )
        raise

    try:
        size = plain_path.stat().st_size
        with open(plain_path, "r+b") as fh:
            fh.write(b"\x00" * size)
            fh.flush()
            os.fsync(fh.fileno())
        os.unlink(str(plain_path))
    except OSError as exc:
        logger.warning(
            f"[Identity] Clé en clair de '{agent_name}' non supprimée ({exc}) : "
            f"supprimez {plain_path} manuellement"
        )


def secure_agent_key(
    agent_name: str,
    new_passphrase: str,
    old_passphrase: Optional[str] = None,
    base_dir: Optional[str] = None,
    old_passphrase_pq: Optional[str] = None,
) -> bool:
    """
    Chiffre (ou rechiffre) la clé privée d'un agent avec une passphrase.

    Utilisé par `piqrypt identity secure` pour protéger une clé
    précédemment stockée en clair.

    Aucune ancienne clé n'est supprimée avant que la nouvelle soit écrite : le
    nouveau fichier est écrit dans un temporaire (O_EXCL, fsync) puis installé par
    os.replace. Clé en clair : le fichier chiffré est écrit avant que l'ancien
    soit supprimé (relu, comparé, écrasé par des zéros, puis effacé : plus de .bak).

    Identité hybride (private_pq.key.enc présent) : les DEUX clés sont déchiffrées
    avec old_passphrase avant toute écriture (si l'une ne s'ouvre pas, rien n'est
    modifié) ; les deux temporaires sont écrits, puis la clé PQ est remplacée, puis
    la clé Ed25519 (si ce dernier remplacement échoue, la clé PQ d'origine est
    restaurée). La nouvelle passphrase suit alors la règle des identités hybrides
    (8 caractères minimum).

    Args:
        agent_name:     Nom de l'agent
        new_passphrase: Nouvelle passphrase
        old_passphrase: Ancienne passphrase de la clé Ed25519 (si elle est chiffrée)
        base_dir:       Répertoire racine optionnel (tests/CI)
        old_passphrase_pq: Ancienne passphrase de la clé ML-DSA-65 d'une identité
            hybride (défaut : old_passphrase). Utile quand la clé PQ a été créée par
            une mise à niveau avec une passphrase différente de celle de la clé Ed25519.
            Une clé PQ qui refuse la passphrase lève PQKeyPassphraseError
            (sous-classe d'InvalidPassphraseError), sans rien avoir modifié.

    Returns:
        True si succès

    Zéroïsation au mieux : les clés déchiffrées sont tenues dans des bytearray effacés
    dans un bloc finally. Cela réduit la fenêtre d'exposition sans la supprimer : bytes
    Python immuables et copiables par l'interpréteur, copies internes des bibliothèques
    de chiffrement, pas de mlock, swap non contrôlé.
    """
    buffers: list = []
    try:
        return _secure_agent_key_impl(
            agent_name, new_passphrase, old_passphrase, base_dir, buffers,
            old_passphrase if old_passphrase_pq is None else old_passphrase_pq)
    finally:
        _erase_all(buffers)


def _secure_agent_key_impl(
    agent_name: str,
    new_passphrase: str,
    old_passphrase: Optional[str],
    base_dir: Optional[str],
    _buffers: list,
    old_passphrase_pq: Optional[str],
) -> bool:
    """Corps de secure_agent_key ; _buffers recueille les clés à effacer."""
    import os
    from aiss.agent_registry import get_agent_dir
    from aiss.key_store import (
        InvalidPassphraseError, PQKeyPassphraseError,
        is_encrypted, load_plaintext_key, load_encrypted_key, load_encrypted_pq_key,
        encrypt_private_key, encrypt_pq_private_key,
    )

    if base_dir is not None:
        agent_dir = Path(base_dir) / "agents" / agent_name
    else:
        agent_dir = get_agent_dir(agent_name)
    enc_path   = agent_dir / "private.key.enc"
    plain_path = agent_dir / "private.key.json"
    pq_path    = agent_dir / "private_pq.key.enc"

    key_path = enc_path if enc_path.exists() else plain_path

    if not key_path.exists():
        raise FileNotFoundError(f"Clé introuvable pour '{agent_name}'")

    hybrid = pq_path.exists()
    ed_encrypted = is_encrypted(key_path)
    if ed_encrypted and old_passphrase is None:
        raise ValueError(
            "La clé Ed25519 est chiffrée : old_passphrase (passphrase actuelle) requise"
        )
    if hybrid:
        _validate_hybrid_passphrase(new_passphrase)
        if old_passphrase_pq is None:
            raise ValueError(
                "Identité hybride : l'ancienne passphrase est requise (clé ML-DSA-65 chiffrée)"
            )

    # 1) Tout déchiffrer avant la moindre écriture.
    if ed_encrypted:
        raw_key = load_encrypted_key(key_path, old_passphrase)
    else:
        raw_key = load_plaintext_key(key_path)
    raw_key = bytearray(raw_key)
    _buffers.append(raw_key)
    pq_blob = None
    if hybrid:
        original_pq = pq_path.read_bytes()
        try:
            raw_pq = load_encrypted_pq_key(pq_path, old_passphrase_pq)
        except InvalidPassphraseError as exc:
            raise PQKeyPassphraseError(
                f"Clé ML-DSA-65 de '{agent_name}' : passphrase refusée ({exc})"
            ) from exc
        except Exception as exc:
            raise type(exc)(
                f"Clé ML-DSA-65 de '{agent_name}' illisible avec l'ancienne passphrase "
                f"(les deux clés doivent partager la même) : {exc}"
            ) from exc
        raw_pq = bytearray(raw_pq)
        _buffers.append(raw_pq)
        pq_blob = encrypt_pq_private_key(raw_pq, new_passphrase)
    ed_blob = encrypt_private_key(raw_key, new_passphrase)

    # 2) Écrire les temporaires, puis installer (PQ d'abord, Ed25519 ensuite).
    staged = []
    try:
        if hybrid:
            staged.append(_stage_bytes(pq_path, pq_blob, 0o600))
        staged.append(_stage_bytes(enc_path, ed_blob, 0o600))
        if hybrid:
            os.replace(str(staged[0]), str(pq_path))
            try:
                os.replace(str(staged[1]), str(enc_path))
            except BaseException:
                try:
                    _atomic_write_bytes(pq_path, original_pq, 0o600)
                except BaseException:
                    logger.error(
                        f"[Identity] Restauration de la clé PQ de '{agent_name}' impossible"
                    )
                raise
        else:
            os.replace(str(staged[0]), str(enc_path))
    except BaseException:
        for t in staged:
            try:
                os.unlink(str(t))
            except OSError:
                pass
        raise

    if not ed_encrypted:
        try:
            _retire_plaintext_key(agent_name, plain_path, enc_path, new_passphrase, raw_key)
        except BaseException:
            if hybrid:
                # La clé PQ a déjà été rechiffrée : on restaure l'originale pour que
                # l'ancienne passphrase l'ouvre à nouveau (comme au second os.replace).
                try:
                    _atomic_write_bytes(pq_path, original_pq, 0o600)
                except BaseException:
                    logger.error(
                        f"[Identity] Restauration de la clé PQ de '{agent_name}' impossible"
                    )
            raise

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
