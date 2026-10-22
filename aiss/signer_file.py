# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
Signataires qui lisent les fichiers de clés chiffrés de key_store.py, sans changer de format :
private.key.enc (v1, Ed25519) et private_pq.key.enc (v2, ML-DSA-65).

Le fichier est déchiffré une fois, à la construction ; la clé est ensuite tenue dans un
bytearray effacé à close() (voir les limites dans aiss.signer : bytes immuables, copies des
bibliothèques de chiffrement, pas de mlock, swap non contrôlé). Une passphrase incorrecte ou un
fichier corrompu lève l'exception de key_store (InvalidPassphraseError, KeyFileCorruptedError)
à la construction : échec fermé.
"""
import base64
import binascii
import json
from pathlib import Path
from typing import Optional

from aiss.key_store import load_encrypted_key, load_encrypted_pq_key
from aiss.signer import (
    ED25519_PUBLIC_KEY_SIZE, ML_DSA_65_PUBLIC_KEY_SIZE, HybridSigner,
    InMemoryEd25519Signer, InMemoryMlDsa65Signer, SignerError, _erase,
)


class EncryptedFileEd25519Signer(InMemoryEd25519Signer):
    """Signataire Ed25519 construit depuis un fichier private.key.enc (format v1)."""

    def __init__(self, path, passphrase: str):
        buffer = bytearray(load_encrypted_key(Path(path), passphrase))
        try:
            super().__init__(buffer)
        finally:
            _erase(buffer)


class EncryptedFileMlDsa65Signer(InMemoryMlDsa65Signer):
    """Signataire ML-DSA-65 construit depuis un fichier private_pq.key.enc (format v2)."""

    def __init__(self, path, passphrase: str, public_key: bytes):
        buffer = bytearray(load_encrypted_pq_key(Path(path), passphrase))
        try:
            super().__init__(buffer, public_key)
        finally:
            _erase(buffer)


def _strict_prefixed(value, what: str, size: int) -> bytes:
    if not isinstance(value, str) or not value.startswith("base64:"):
        raise SignerError(f"{what}: 'base64:' prefix is mandatory")
    try:
        raw = base64.b64decode(value[7:], validate=True)
    except (binascii.Error, ValueError):
        raise SignerError(f"{what}: invalid base64")
    if len(raw) != size:
        raise SignerError(f"{what}: {len(raw)} bytes instead of {size}")
    return raw


def load_hybrid_signer(
    agent_dir,
    passphrase: str,
    passphrase_pq: Optional[str] = None,
    verify_after_sign: bool = True,
) -> HybridSigner:
    """
    HybridSigner d'une identité hybride (native ou mise à niveau) stockée dans `agent_dir`.

    Lit private.key.enc, private_pq.key.enc et identity.json (clés publiques). La clé publique
    Ed25519 déduite de la clé privée doit correspondre à identity.json, sinon SignerError.

    Args:
        agent_dir:     dossier de l'agent (~/.piqrypt/agents/<nom>/)
        passphrase:    passphrase de la clé Ed25519
        passphrase_pq: passphrase de la clé ML-DSA-65 (défaut : passphrase)
    """
    agent_dir = Path(agent_dir)
    try:
        identity = json.loads((agent_dir / "identity.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SignerError(f"identity.json unreadable: {exc}") from exc
    if not isinstance(identity, dict):
        raise SignerError("identity.json must be an object")
    public_pq = _strict_prefixed(identity.get("public_key_pq"), "public_key_pq",
                                 ML_DSA_65_PUBLIC_KEY_SIZE)
    if "public_key_classical" in identity:
        expected_ed = _strict_prefixed(identity["public_key_classical"], "public_key_classical",
                                       ED25519_PUBLIC_KEY_SIZE)
    else:
        try:
            expected_ed = base64.b64decode(identity.get("public_key"), validate=True)
        except (binascii.Error, ValueError, TypeError):
            raise SignerError("public_key: invalid base64")

    classical = EncryptedFileEd25519Signer(agent_dir / "private.key.enc", passphrase)
    try:
        if classical.public_key() != expected_ed:
            raise SignerError("Ed25519 key does not match identity.json")
        post_quantum = EncryptedFileMlDsa65Signer(
            agent_dir / "private_pq.key.enc",
            passphrase if passphrase_pq is None else passphrase_pq,
            public_pq,
        )
    except BaseException:
        classical.close()
        raise
    return HybridSigner(classical, post_quantum, verify_after_sign=verify_after_sign)


__all__ = ["EncryptedFileEd25519Signer", "EncryptedFileMlDsa65Signer", "load_hybrid_signer"]
