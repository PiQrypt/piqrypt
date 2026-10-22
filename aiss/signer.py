# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute -- see root LICENSE for details.

"""
Signer interface (chantier F : préparation du niveau 3, HSM / KMS / PKCS#11).

Un Signer signe un message avec UNE clé privée qu'il ne divulgue jamais. Le message M' est
construit par l'appelant (domaine, étiquette, JCS), jamais par le Signer. Un HybridSigner
réunit un Signer Ed25519 et un Signer ML-DSA-65 : il rend les DEUX signatures ou lève
SignerError, jamais une signature seule.

Ce module ne dépend que de aiss.crypto et aiss.exceptions (MIT). Les signataires qui lisent
des fichiers chiffrés sont dans aiss.signer_file (Elastic-2.0).

Limites de Python (zéroïsation au mieux) : les signataires en mémoire tiennent la clé dans un
bytearray effacé à close(), mais les bytes sont immuables et copiables par l'interpréteur,
les bibliothèques de chiffrement gardent leurs copies internes, il n'y a pas de mlock et le
swap n'est pas contrôlé. L'effacement réduit la fenêtre d'exposition, il ne la supprime pas.
"""

from abc import ABC, abstractmethod
from typing import NamedTuple, Optional, Tuple

from aiss.exceptions import AISSError

ED25519 = "Ed25519"
ML_DSA_65 = "ML-DSA-65"

ED25519_PUBLIC_KEY_SIZE = 32
ED25519_PRIVATE_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64
ML_DSA_65_PUBLIC_KEY_SIZE = 1952
ML_DSA_65_PRIVATE_KEY_SIZE = 4032
ML_DSA_65_SIGNATURE_SIZE = 3309

_SIGNATURE_SIZES = {ED25519: ED25519_SIGNATURE_SIZE, ML_DSA_65: ML_DSA_65_SIGNATURE_SIZE}
_PUBLIC_KEY_SIZES = {ED25519: ED25519_PUBLIC_KEY_SIZE, ML_DSA_65: ML_DSA_65_PUBLIC_KEY_SIZE}


class SignerError(AISSError):
    """Un signataire a échoué, ou a rendu une signature inutilisable (échec fermé)."""


def _erase(buffer: Optional[bytearray]) -> None:
    if buffer is not None:
        for i in range(len(buffer)):
            buffer[i] = 0


class Signer(ABC):
    """
    Signataire d'un seul algorithme.

    Exigences pour toute implémentation (voir docs/SIGNER.md) :
      - la clé privée n'est jamais exposée (ni attribut public, ni méthode, ni repr) ;
      - sign(message) signe exactement les octets reçus : ML-DSA-65 pure (FIPS 204), contexte
        vide, Ed25519 (RFC 8032) ; elle rend la signature brute de la taille de l'algorithme ;
      - public_key() est stable pour la durée de vie de l'objet ;
      - toute défaillance lève une exception (échec fermé), jamais une signature partielle,
        vide ou de mauvaise taille ; après close(), sign() lève.
    """

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """"Ed25519" ou "ML-DSA-65"."""

    @abstractmethod
    def public_key(self) -> bytes:
        """Clé publique brute (32 octets pour Ed25519, 1952 pour ML-DSA-65)."""

    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        """Signature brute de `message` (64 octets pour Ed25519, 3309 pour ML-DSA-65)."""

    def close(self) -> None:
        """Libère les ressources (efface la clé en mémoire, ferme la session distante)."""

    def __enter__(self) -> "Signer":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False


class _InMemorySigner(Signer):
    """Base des signataires en mémoire : clé privée dans un bytearray effacé à close()."""

    _ALGORITHM = ""
    _PRIVATE_KEY_SIZE = 0

    def __init__(self, private_key, public_key: bytes):
        if len(private_key) != self._PRIVATE_KEY_SIZE:
            raise SignerError(
                f"{self._ALGORITHM} private key must be {self._PRIVATE_KEY_SIZE} bytes, "
                f"got {len(private_key)}"
            )
        if len(public_key) != _PUBLIC_KEY_SIZES[self._ALGORITHM]:
            raise SignerError(
                f"{self._ALGORITHM} public key must be {_PUBLIC_KEY_SIZES[self._ALGORITHM]} "
                f"bytes, got {len(public_key)}"
            )
        self._key: Optional[bytearray] = bytearray(private_key)
        self._public = bytes(public_key)

    @property
    def algorithm(self) -> str:
        return self._ALGORITHM

    def public_key(self) -> bytes:
        return self._public

    def _require_open(self) -> bytearray:
        if self._key is None:
            raise SignerError(f"{self._ALGORITHM} signer is closed")
        return self._key

    def close(self) -> None:
        _erase(self._key)
        self._key = None

    def __repr__(self) -> str:
        state = "closed" if self._key is None else "open"
        return f"<{type(self).__name__} {self._ALGORITHM} {state}>"

    def __getstate__(self):
        raise TypeError(f"{type(self).__name__} holds a private key and cannot be pickled or copied")


class InMemoryEd25519Signer(_InMemorySigner):
    """Signataire Ed25519 dont la clé privée (32 octets) est en mémoire (bytearray)."""

    _ALGORITHM = ED25519
    _PRIVATE_KEY_SIZE = ED25519_PRIVATE_KEY_SIZE

    def __init__(self, private_key, public_key: Optional[bytes] = None):
        if public_key is None:
            public_key = self._derive_public_key(private_key)
        super().__init__(private_key, public_key)

    @staticmethod
    def _derive_public_key(private_key) -> bytes:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        if len(private_key) != ED25519_PRIVATE_KEY_SIZE:
            raise SignerError(f"Ed25519 private key must be {ED25519_PRIVATE_KEY_SIZE} bytes")
        key = Ed25519PrivateKey.from_private_bytes(bytes(private_key))
        return key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, message: bytes) -> bytes:
        from aiss.crypto import ed25519
        return ed25519.sign(bytes(self._require_open()), message)


class InMemoryMlDsa65Signer(_InMemorySigner):
    """Signataire ML-DSA-65 dont la clé privée (4032 octets) est en mémoire (bytearray).

    La clé publique (1952 octets) est fournie : elle ne se déduit pas de la clé privée."""

    _ALGORITHM = ML_DSA_65
    _PRIVATE_KEY_SIZE = ML_DSA_65_PRIVATE_KEY_SIZE

    def __init__(self, private_key, public_key: bytes):
        super().__init__(private_key, public_key)

    def sign(self, message: bytes) -> bytes:
        from aiss.crypto import dilithium
        if dilithium is None:
            raise SignerError("ML-DSA-65 backend not installed")
        return dilithium.sign(self._require_open(), message)


class HybridSignature(NamedTuple):
    """Les deux signatures brutes d'un même message."""
    classical: bytes
    post_quantum: bytes


class HybridSigner:
    """
    Réunit un Signer Ed25519 et un Signer ML-DSA-65.

    sign(message) rend les DEUX signatures ou lève SignerError. Il contrôle les longueurs
    (64 et 3309 octets) et, par défaut (verify_after_sign=True), vérifie chaque signature
    avec la clé publique du signataire avant de la rendre : un HSM ou un pont distant
    défaillant ne peut pas faire émettre un événement non vérifiable.
    """

    def __init__(self, classical: Signer, post_quantum: Signer, verify_after_sign: bool = True):
        if getattr(classical, "algorithm", None) != ED25519:
            raise SignerError(f"classical signer must be {ED25519}")
        if getattr(post_quantum, "algorithm", None) != ML_DSA_65:
            raise SignerError(f"post-quantum signer must be {ML_DSA_65}")
        self.classical = classical
        self.post_quantum = post_quantum
        self.verify_after_sign = verify_after_sign

    def public_keys(self) -> Tuple[bytes, bytes]:
        """(clé publique Ed25519, clé publique ML-DSA-65)"""
        return (self._public_key(self.classical), self._public_key(self.post_quantum))

    @staticmethod
    def _public_key(signer: Signer) -> bytes:
        try:
            key = signer.public_key()
        except Exception as exc:
            raise SignerError(f"{signer.algorithm} public_key() failed: {exc}") from exc
        if not isinstance(key, (bytes, bytearray)) or len(key) != _PUBLIC_KEY_SIZES[signer.algorithm]:
            raise SignerError(
                f"{signer.algorithm} public key must be {_PUBLIC_KEY_SIZES[signer.algorithm]} bytes"
            )
        return bytes(key)

    @staticmethod
    def _sign_one(signer: Signer, message: bytes) -> bytes:
        algorithm = signer.algorithm
        try:
            signature = signer.sign(message)
        except SignerError:
            raise
        except Exception as exc:
            raise SignerError(f"{algorithm} signer failed: {exc}") from exc
        if not isinstance(signature, (bytes, bytearray)):
            raise SignerError(f"{algorithm} signer returned {type(signature).__name__}, not bytes")
        if len(signature) != _SIGNATURE_SIZES[algorithm]:
            raise SignerError(
                f"{algorithm} signature must be {_SIGNATURE_SIZES[algorithm]} bytes, "
                f"got {len(signature)}"
            )
        return bytes(signature)

    @staticmethod
    def _verify_one(algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> None:
        try:
            if algorithm == ED25519:
                from aiss.crypto import ed25519
                ok = ed25519.verify(public_key, message, signature)
            else:
                from aiss.crypto import dilithium
                if dilithium is None:
                    raise SignerError("ML-DSA-65 backend not installed")
                ok = dilithium.verify(public_key, message, signature)
        except SignerError:
            raise
        except Exception as exc:
            raise SignerError(f"{algorithm} signature does not verify: {exc}") from exc
        if not ok:
            raise SignerError(f"{algorithm} signature does not verify under the signer's public key")

    def sign(self, message: bytes) -> HybridSignature:
        classical_key = self._public_key(self.classical)
        post_quantum_key = self._public_key(self.post_quantum)
        classical = self._sign_one(self.classical, message)
        post_quantum = self._sign_one(self.post_quantum, message)
        if self.verify_after_sign:
            self._verify_one(ED25519, classical_key, message, classical)
            self._verify_one(ML_DSA_65, post_quantum_key, message, post_quantum)
        return HybridSignature(classical, post_quantum)

    def close(self) -> None:
        errors = []
        for signer in (self.classical, self.post_quantum):
            try:
                signer.close()
            except Exception as exc:  # fermer les deux dans tous les cas
                errors.append(exc)
        if errors:
            raise SignerError(f"closing a signer failed: {errors[0]}") from errors[0]

    def __enter__(self) -> "HybridSigner":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False

    def __repr__(self) -> str:
        return f"<HybridSigner {self.classical!r} {self.post_quantum!r}>"


__all__ = [
    "Signer", "HybridSigner", "HybridSignature", "SignerError",
    "InMemoryEd25519Signer", "InMemoryMlDsa65Signer",
    "ED25519", "ML_DSA_65",
]
