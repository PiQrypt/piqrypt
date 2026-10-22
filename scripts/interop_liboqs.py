#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Interopérabilité ML-DSA-65 : liboqs (module `oqs`) contre dilithium-py, sur les vecteurs
AISS-2.1 (test_vectors_aiss21/). Lancé par .github/workflows/interop-liboqs.yml.

Contrôles :
  1. liboqs signe les messages M' de hash_and_message.json, puis dilithium-py ET liboqs vérifient ;
  2. dilithium-py signe les mêmes M' (déterministe, contexte vide), puis liboqs vérifie ;
  3. un message altéré est rejeté par les deux ;
  4. toutes les vérifications des vecteurs sont rejouées avec liboqs comme vérificateur
     ML-DSA-65 (verify_standalone.py, dont le vérificateur PQ est remplacé par liboqs) :
     les verdicts doivent rester conformes au champ "valid".

Ne dépend pas de `aiss`. Nécessite : liboqs-python (oqs), dilithium-py, rfc8785, base58,
cryptography.  Usage : python scripts/interop_liboqs.py [--vectors DIR]
"""
import argparse
import importlib.util
import json
import os
import sys

import oqs
from dilithium_py.ml_dsa import ML_DSA_65

ALGORITHM = "ML-DSA-65"
AGENTS = ("A", "C")


def oqs_sign(secret_key, message):
    with oqs.Signature(ALGORITHM, secret_key) as signer:
        return signer.sign(message)


def oqs_verify(public_key, message, signature):
    with oqs.Signature(ALGORITHM) as verifier:
        return bool(verifier.verify(message, signature, public_key))


def dilithium_sign(secret_key, message):
    return ML_DSA_65.sign(secret_key, message, ctx=b"", deterministic=True)


def dilithium_verify(public_key, message, signature):
    return bool(ML_DSA_65.verify(public_key, message, signature))


def load_json(vectors_dir, name):
    with open(os.path.join(vectors_dir, name), encoding="utf-8") as fh:
        return json.load(fh)


def load_standalone(vectors_dir):
    path = os.path.join(vectors_dir, "verify_standalone.py")
    spec = importlib.util.spec_from_file_location("verify_standalone", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OqsAsMlDsa:
    """Remplace ML_DSA_65 dans verify_standalone : la vérification passe par liboqs."""

    @staticmethod
    def verify(public_key, message, signature):
        return oqs_verify(public_key, message, signature)


def run(vectors_dir):
    failures = []

    def check(label, ok):
        print(f"{'OK  ' if ok else 'FAIL'} {label}")
        if not ok:
            failures.append(label)

    enabled = oqs.get_enabled_sig_mechanisms()
    print(f"liboqs-python: {getattr(oqs, 'oqs_python_version', lambda: '?')()}, "
          f"liboqs: {getattr(oqs, 'oqs_version', lambda: '?')()}")
    check(f"{ALGORITHM} enabled in liboqs", ALGORITHM in enabled)
    if failures:
        return failures

    keys = load_json(vectors_dir, "keys.json")
    agents = {**keys["agents"], **keys["helpers"]}
    messages = [(v["id"], bytes.fromhex(v["signed_message_hex"]))
                for v in load_json(vectors_dir, "hash_and_message.json")["vectors"]]

    for name in AGENTS:
        pk = bytes.fromhex(agents[name]["ml_dsa_65"]["public_key"])
        sk = bytes.fromhex(agents[name]["ml_dsa_65"]["private_key"])
        for vid, msg in messages:
            tag = f"agent {name} / {vid}"
            sig_oqs = oqs_sign(sk, msg)
            check(f"{tag}: liboqs signs, dilithium-py verifies", dilithium_verify(pk, msg, sig_oqs))
            check(f"{tag}: liboqs signs, liboqs verifies", oqs_verify(pk, msg, sig_oqs))
            sig_py = dilithium_sign(sk, msg)
            check(f"{tag}: dilithium-py signs, liboqs verifies", oqs_verify(pk, msg, sig_py))
            tampered = msg[:-1] + bytes([msg[-1] ^ 1])
            check(f"{tag}: tampered message rejected by liboqs", not oqs_verify(pk, tampered, sig_py))
            check(f"{tag}: tampered message rejected by dilithium-py",
                  not dilithium_verify(pk, tampered, sig_oqs))

    standalone = load_standalone(vectors_dir)
    standalone.ML_DSA_65 = OqsAsMlDsa
    results = standalone.all_verdicts(vectors_dir)
    for key, (got, expected) in sorted(results.items()):
        if got != expected:
            check(f"vector {key} with liboqs verifier: verdict={got} expected={expected}", False)
    check(f"all {len(results)} vectors keep their verdict with liboqs as ML-DSA-65 verifier",
          all(got == expected for got, expected in results.values()))
    return failures


def main(argv=None):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--vectors", default=os.path.join(root, "test_vectors_aiss21"))
    args = ap.parse_args(argv)
    failures = run(args.vectors)
    print(f"\n{'FAILED' if failures else 'PASSED'}: {len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
