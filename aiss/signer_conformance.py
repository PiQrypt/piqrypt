# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute -- see root LICENSE for details.

"""
Contrôles de conformité réutilisables pour une implémentation de Signer (HSM, KMS, PKCS#11,
pont distant).

    from aiss.signer_conformance import assert_signer_conforms
    assert_signer_conforms(lambda: MyHsmSigner(slot=3, pin=...))

`factory` est un appelable sans argument qui rend un Signer neuf à chaque appel : la
vérification de l'échec fermé ferme une instance. Ces contrôles couvrent les exigences
vérifiables de l'extérieur (tailles, clé publique stable, signature vérifiable par la
bibliothèque, échec fermé). Ils ne prouvent PAS que la clé privée ne peut pas être exportée
ni que le module est conforme à quoi que ce soit : ce n'est ni une certification ni un audit.
"""
from typing import Callable, List, Sequence

from aiss.signer import (
    ED25519, ML_DSA_65, HybridSigner, Signer,
    _PUBLIC_KEY_SIZES, _SIGNATURE_SIZES,
)

DEFAULT_MESSAGES = (b"", b"M' conformance message", bytes(range(256)) * 20)
_SECRET_WORDS = ("private", "secret", "seed")


def _verify(algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    if algorithm == ED25519:
        from aiss.crypto import ed25519
        from aiss.exceptions import InvalidSignatureError
        try:
            return bool(ed25519.verify(public_key, message, signature))
        except InvalidSignatureError:
            return False
    from aiss.crypto import dilithium
    return bool(dilithium.verify(public_key, message, signature))


def check_signer(factory: Callable[[], Signer], messages: Sequence[bytes] = DEFAULT_MESSAGES) -> List[str]:
    """Liste des manquements d'un Signer (liste vide = aucun manquement constaté)."""
    problems: List[str] = []

    def guard(label: str, fn):
        try:
            return fn()
        except Exception as exc:
            problems.append(f"{label} raised {type(exc).__name__}: {exc}")
            return None

    signer = guard("factory()", factory)
    if signer is None:
        return problems
    try:
        algorithm = guard("algorithm", lambda: signer.algorithm)
        if algorithm not in (ED25519, ML_DSA_65):
            problems.append(f"algorithm must be {ED25519!r} or {ML_DSA_65!r}, got {algorithm!r}")
            return problems

        public_keys = [guard("public_key()", signer.public_key) for _ in range(3)]
        public_key = public_keys[0]
        if not isinstance(public_key, (bytes, bytearray)) \
                or len(public_key) != _PUBLIC_KEY_SIZES[algorithm]:
            problems.append(f"public_key() must return {_PUBLIC_KEY_SIZES[algorithm]} bytes")
            return problems
        if any(k != public_key for k in public_keys):
            problems.append("public_key() is not stable")

        exposed = [n for n in dir(signer) if not n.startswith("_")
                   and any(w in n.lower() for w in _SECRET_WORDS)]
        if exposed:
            problems.append(f"public attributes suggest a private key is exposed: {exposed}")

        for message in messages:
            signature = guard(f"sign({len(message)}-byte message)", lambda m=message: signer.sign(m))
            if signature is None:
                continue
            if not isinstance(signature, (bytes, bytearray)):
                problems.append(f"sign() must return bytes, got {type(signature).__name__}")
                continue
            if len(signature) != _SIGNATURE_SIZES[algorithm]:
                problems.append(
                    f"signature must be {_SIGNATURE_SIZES[algorithm]} bytes, got {len(signature)}")
                continue
            ok = guard("library verification", lambda: _verify(
                algorithm, bytes(public_key), message, bytes(signature)))
            if not ok:
                hint = (" (ML-DSA-65 must be pure FIPS 204 with an empty context)"
                        if algorithm == ML_DSA_65 else "")
                problems.append(
                    f"signature of a {len(message)}-byte message does not verify with the "
                    f"library{hint}")
    finally:
        guard("close()", signer.close)

    # Échec fermé : après close(), sign() doit lever (jamais rendre une signature).
    closed = guard("factory()", factory)
    if closed is not None:
        with closed:
            pass
        try:
            result = closed.sign(b"after close")
        except Exception:
            pass
        else:
            problems.append(f"sign() after close() must raise, returned {type(result).__name__}")
    return problems


def check_hybrid_signer(factory: Callable[[], HybridSigner]) -> List[str]:
    """Contrôles d'un HybridSigner : les deux signatures, vérifiables, ou une exception."""
    problems: List[str] = []
    signer = factory()
    try:
        ed_key, pq_key = signer.public_keys()
        for message in DEFAULT_MESSAGES:
            try:
                signature = signer.sign(message)
            except Exception as exc:
                problems.append(f"sign({len(message)}-byte message) raised {type(exc).__name__}: {exc}")
                continue
            if len(signature.classical) != _SIGNATURE_SIZES[ED25519] \
                    or len(signature.post_quantum) != _SIGNATURE_SIZES[ML_DSA_65]:
                problems.append("hybrid signature has a wrong component size")
            elif not _verify(ED25519, ed_key, message, signature.classical) \
                    or not _verify(ML_DSA_65, pq_key, message, signature.post_quantum):
                problems.append("a hybrid signature component does not verify with the library")
    finally:
        signer.close()
    closed = factory()
    with closed:
        pass
    try:
        closed.sign(b"after close")
    except Exception:
        pass
    else:
        problems.append("sign() after close() must raise")
    return problems


def assert_signer_conforms(factory: Callable[[], Signer]) -> None:
    problems = check_signer(factory)
    assert not problems, "Signer does not conform:\n- " + "\n- ".join(problems)


def assert_hybrid_signer_conforms(factory: Callable[[], HybridSigner]) -> None:
    problems = check_hybrid_signer(factory)
    assert not problems, "HybridSigner does not conform:\n- " + "\n- ".join(problems)


__all__ = ["check_signer", "check_hybrid_signer", "assert_signer_conforms",
           "assert_hybrid_signer_conforms", "DEFAULT_MESSAGES"]
