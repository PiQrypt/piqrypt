#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Génère les vecteurs de test AISS-2.1 (dossier test_vectors_aiss21/).

Entièrement déterministe : graines fixes, nonces et timestamps explicites, ML-DSA-65 en
deterministic=True avec le contexte vide (mêmes paramètres que aiss/crypto : sign(sk, M')
sans contexte). Deux exécutions produisent des fichiers identiques octet pour octet.

Ce script n'importe rien de `aiss` : il ne dépend que de la bibliothèque standard,
rfc8785, base58, cryptography et dilithium-py.

TEST ONLY : toutes les clés produites ici sont publiques par construction.

Usage : python scripts/gen_aiss21_vectors.py [--out DIR]
"""
import argparse
import base64
import hashlib
import json
import os
import struct
import sys

import base58
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dilithium_py.ml_dsa import ML_DSA_65

SPEC = "AISS-2.1"

DOMAIN_EVENT = b"PiQrypt-AISS-2.1\x00"
DOMAIN_BINDING = b"PiQrypt-AISS-2.1-binding\x00"
DOMAIN_ROTATION = b"PiQrypt-AISS-2.1-rotation\x00"
DOMAIN_GENESIS = b"PiQrypt-AISS-2.1-genesis\x00"
DOMAIN_AGENT_ID = b"PiQrypt-AISS-2.1-agent-id\x00"
ALGO_LABEL = b"Ed25519+ML-DSA-65"

BASE_TS = 1_800_000_000
DETACHED = ("signatures", "trusted_timestamp")


# ─── primitives ──────────────────────────────────────────────────────────────

def jcs(obj):
    return rfc8785.dumps(obj)


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def sha512_hex(b):
    return hashlib.sha512(b).hexdigest()


def b64p(raw):
    return "base64:" + base64.b64encode(raw).decode("ascii")


def b64plain(raw):
    return base64.b64encode(raw).decode("ascii")


def derive_seed(label):
    return hashlib.sha256(b"PiQrypt AISS-2.1 test vectors / " + label.encode("ascii")).digest()


def det_nonce(label):
    h = hashlib.sha256(b"nonce / " + label.encode("ascii")).hexdigest()
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"


def agent_id_aiss21(ed_pub, pq_pub):
    data = (DOMAIN_AGENT_ID + struct.pack(">I", len(ed_pub)) + ed_pub
            + struct.pack(">I", len(pq_pub)) + pq_pub)
    return base58.b58encode(hashlib.sha512(data).digest()).decode("ascii")[:32]


def agent_id_aiss1(ed_pub):
    return base58.b58encode(hashlib.sha256(ed_pub).digest()).decode("ascii")[:32]


def signed_message(domain_prefix, unsigned_doc):
    """M' = préfixe de domaine || len(étiquette) || étiquette || 0x00 || JCS(document)"""
    return domain_prefix + bytes([len(ALGO_LABEL)]) + ALGO_LABEL + b"\x00" + jcs(unsigned_doc)


def unsigned(doc):
    return {k: v for k, v in doc.items() if k not in DETACHED}


def event_hash(event):
    if event.get("version") == SPEC:
        return sha512_hex(jcs(unsigned(event)))
    body = {k: v for k, v in event.items() if k not in ("signature", "trusted_timestamp")}
    return sha256_hex(jcs(body))


def genesis_hash(agent_id):
    return sha512_hex(DOMAIN_GENESIS + agent_id.encode("ascii"))


class Agent:
    def __init__(self, name, aiss1=False):
        self.name = name
        self.ed_seed = derive_seed(name + "/ed25519")
        self.pq_seed = derive_seed(name + "/ml-dsa-65")
        self._ed = Ed25519PrivateKey.from_private_bytes(self.ed_seed)
        self.ed_pub = self._ed.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.pq_pk, self.pq_sk = ML_DSA_65.key_derive(self.pq_seed)
        self.id21 = agent_id_aiss21(self.ed_pub, self.pq_pk)
        self.id1 = agent_id_aiss1(self.ed_pub)
        self.agent_id = self.id1 if aiss1 else self.id21

    def sign_ed(self, message):
        return self._ed.sign(message)

    def sign_pq(self, message):
        return ML_DSA_65.sign(self.pq_sk, message, ctx=b"", deterministic=True)

    def dual_signatures(self, message):
        return {
            "classical": {"algorithm": "Ed25519", "signature": b64p(self.sign_ed(message))},
            "post_quantum": {"algorithm": "ML-DSA-65", "signature": b64p(self.sign_pq(message))},
        }

    def keys_hex(self):
        return {"ed25519": self.ed_pub.hex(), "ml_dsa_65": self.pq_pk.hex()}


A = Agent("A")                 # hybride native
B = Agent("B", aiss1=True)     # identité AISS-1 mise à niveau (agent_id inchangé)
C = Agent("C")                 # cible de rotation
D = Agent("D")                 # étranger (négatifs)
E = Agent("E")                 # seconde cible de rotation (rotations concurrentes)

PENDING_TS = {"status": "pending"}


# ─── événements ──────────────────────────────────────────────────────────────

def event21(agent, ts_offset, nonce_label, payload, previous_hash, version=SPEC, agent_id=None):
    body = {
        "version": version,
        "agent_id": agent_id or agent.agent_id,
        "timestamp": BASE_TS + ts_offset,
        "nonce": det_nonce(nonce_label),
        "payload": payload,
        "previous_hash": previous_hash,
    }
    event = dict(body)
    event["signatures"] = agent.dual_signatures(signed_message(DOMAIN_EVENT, body))
    event["trusted_timestamp"] = dict(PENDING_TS)
    return event


def event1(agent, ts_offset, nonce_label, payload, previous_hash):
    body = {
        "version": "AISS-1.0",
        "agent_id": agent.agent_id,
        "timestamp": BASE_TS + ts_offset,
        "nonce": det_nonce(nonce_label),
        "payload": payload,
        "previous_hash": previous_hash,
    }
    event = dict(body)
    event["signature"] = b64plain(agent.sign_ed(jcs(body)))
    return event


def native_chain(agent, n_regular, tag):
    """genèse + n événements AISS-2.1 chaînés en SHA-512"""
    events = [event21(agent, 0, f"{tag}/0", {"action": "genesis", "seq": 0},
                      genesis_hash(agent.agent_id))]
    for i in range(1, n_regular + 1):
        events.append(event21(agent, 10 * i, f"{tag}/{i}", {"action": "step", "seq": i},
                              event_hash(events[-1])))
    return events


# ─── identités ───────────────────────────────────────────────────────────────

def identity_native(agent):
    return {
        "version": SPEC,
        "agent_id": agent.id21,
        "public_key_classical": b64p(agent.ed_pub),
        "public_key_pq": b64p(agent.pq_pk),
        "algorithms": ["Ed25519", "ML-DSA-65"],
        "created_at": BASE_TS - 1000,
    }


def binding_for(agent):
    body = {
        "version": SPEC,
        "type": "identity_binding",
        "agent_id": agent.agent_id,
        "public_key_classical": b64p(agent.ed_pub),
        "public_key_pq": b64p(agent.pq_pk),
        "binding_assurance": "classical_only",
        "created_at": BASE_TS - 500,
    }
    doc = dict(body)
    doc["signatures"] = agent.dual_signatures(signed_message(DOMAIN_BINDING, body))
    return doc


def identity_upgraded(agent):
    return {
        "version": "AISS-1.0",
        "agent_id": agent.id1,
        "public_key": b64plain(agent.ed_pub),
        "algorithm": "Ed25519",
        "created_at": BASE_TS - 1000,
        "public_key_pq": b64p(agent.pq_pk),
        "binding": binding_for(agent),
    }


# ─── rotation ────────────────────────────────────────────────────────────────

def rotation_attestation(prev, prev_agent_id, new, rotation_ts=BASE_TS + 100, new_agent_id=None):
    body = {
        "version": SPEC,
        "type": "key_rotation",
        "previous_agent_id": prev_agent_id,
        "previous_public_key_classical": b64p(prev.ed_pub),
        "previous_public_key_pq": b64p(prev.pq_pk),
        "new_agent_id": new_agent_id or new.id21,
        "new_public_key_classical": b64p(new.ed_pub),
        "new_public_key_pq": b64p(new.pq_pk),
        "rotation_timestamp": rotation_ts,
    }
    msg = signed_message(DOMAIN_ROTATION, body)
    prev_sigs = prev.dual_signatures(msg)
    new_sigs = new.dual_signatures(msg)
    doc = dict(body)
    doc["signatures"] = {
        "previous_classical": prev_sigs["classical"],
        "previous_post_quantum": prev_sigs["post_quantum"],
        "new_classical": new_sigs["classical"],
        "new_post_quantum": new_sigs["post_quantum"],
    }
    return doc


def rotation_event(prev, prev_agent_id, attestation, previous_hash, ts_offset, label):
    return event21(prev, ts_offset, label,
                   {"event_type": "key_rotation", "attestation": attestation},
                   previous_hash, agent_id=prev_agent_id)


# ─── fichiers ────────────────────────────────────────────────────────────────

def doc(description, **extra):
    d = {"description": description, "spec_version": SPEC}
    d.update(extra)
    return d


def vec(vid, description, valid, reason=None, **fields):
    v = {"id": vid, "description": description, "valid": valid}
    if not valid:
        assert reason, vid
        v["reason"] = reason
    v.update(fields)
    return v


def build_keys():
    def entry(a, role):
        return {
            "role": role,
            "agent_id": a.agent_id,
            "agent_id_aiss21": a.id21,
            "agent_id_aiss1": a.id1,
            "ed25519": {"seed": a.ed_seed.hex(), "public_key": a.ed_pub.hex(),
                        "private_key": a.ed_seed.hex(), "note": "TEST ONLY"},
            "ml_dsa_65": {"seed": a.pq_seed.hex(), "public_key": a.pq_pk.hex(),
                          "private_key": a.pq_sk.hex(), "note": "TEST ONLY"},
        }
    return doc(
        "Clés de test AISS-2.1. TEST ONLY : ces clés sont publiques, ne jamais les utiliser "
        "ailleurs. Graines = SHA-256 d'une étiquette fixe ; Ed25519 : clé privée = graine de 32 "
        "octets ; ML-DSA-65 : (pk, sk) = ML_DSA_65.key_derive(graine de 32 octets).",
        agents={
            "A": entry(A, "hybride native : agent_id dérivé des deux clés"),
            "B": entry(B, "identité AISS-1 mise à niveau : agent_id = dérivation AISS-1 (inchangé)"),
            "C": entry(C, "cible de rotation (hybride native)"),
        },
        helpers={
            "D": entry(D, "étranger : sert aux vecteurs négatifs"),
            "E": entry(E, "seconde cible de rotation (rotations concurrentes)"),
        },
    )


def build_agent_id():
    vectors = []
    for name, ag in (("A", A), ("B", B), ("C", C), ("D", D)):
        vectors.append(vec(
            f"derive_{name}", f"agent_id AISS-2.1 dérivé des clés de l'agent {name}", True,
            ed25519_public_key=ag.ed_pub.hex(), ml_dsa_65_public_key=ag.pq_pk.hex(),
            expected_agent_id=ag.id21))
    cases = [
        ("ed25519_31_bytes", "clé Ed25519 de 31 octets", A.ed_pub[:-1], A.pq_pk,
         "Ed25519 public key must be 32 bytes"),
        ("ed25519_33_bytes", "clé Ed25519 de 33 octets", A.ed_pub + b"\x00", A.pq_pk,
         "Ed25519 public key must be 32 bytes"),
        ("ml_dsa_65_1951_bytes", "clé ML-DSA-65 de 1951 octets", A.ed_pub, A.pq_pk[:-1],
         "ML-DSA-65 public key must be 1952 bytes"),
        ("ml_dsa_65_1953_bytes", "clé ML-DSA-65 de 1953 octets", A.ed_pub, A.pq_pk + b"\x00",
         "ML-DSA-65 public key must be 1952 bytes"),
    ]
    for vid, desc, ed, pq, reason in cases:
        vectors.append(vec(vid, desc, False, reason,
                           ed25519_public_key=ed.hex(), ml_dsa_65_public_key=pq.hex(),
                           expected_agent_id=None))
    return doc(
        "derive_agent_id_aiss21 : Base58(SHA-512(b'PiQrypt-AISS-2.1-agent-id\\x00' || "
        "len32(pk_ed) || pk_ed || len32(pk_pq) || pk_pq))[0:32], longueurs en big-endian sur 4 "
        "octets. Tailles imposées : 32 (Ed25519) et 1952 (ML-DSA-65).",
        vectors=vectors)


def hash_vectors():
    cases = []

    def body(payload, prev, ts, label):
        return {"version": SPEC, "agent_id": A.agent_id, "timestamp": BASE_TS + ts,
                "nonce": det_nonce(label), "payload": payload, "previous_hash": prev}

    cases.append(("ascii_minimal", "événement minimal, charge utile ASCII",
                  body({"action": "ping"}, genesis_hash(A.agent_id), 1, "h1")))
    cases.append(("non_ascii", "caractères non ASCII, échappements, ordre des clés UTF-16",
                  body({"é": "café", "日本語": "テスト", "emoji": "\U0001F600",
                        "\U0001F600": "clé hors plan de base", "￿": "U+FFFF",
                        "ctrl": "a\tb\n\u0001\"\\/", "z": "last", "a": "first"},
                       event_hash(event21(A, 0, "h1p", {"x": 1}, genesis_hash(A.agent_id))), 2, "h2")))
    cases.append(("nested_objects", "objets et tableaux imbriqués, clés non triées, valeurs mixtes",
                  body({"z": {"y": [3, 2, {"b": None, "a": [True, False, {}]}], "x": []},
                        "m": [[1, [2, [3]]], {"k2": 1, "k1": 2}],
                        "floats": [1.5, 100.0, 0.000001, 1e21], "empty": {}},
                       genesis_hash(A.agent_id), 3, "h3")))
    cases.append(("large_integers", "entiers jusqu'aux bornes sûres de JCS (±(2^53-1))",
                  body({"max": 9007199254740991, "min": -9007199254740991, "zero": 0,
                        "big": 4294967296000, "neg": -123456789012345},
                       genesis_hash(A.agent_id), 4, "h4")))
    e5 = body({"action": "detached fields are ignored"}, genesis_hash(A.agent_id), 5, "h5")
    e5["signatures"] = {"classical": {"algorithm": "Ed25519", "signature": "base64:PLACEHOLDER"},
                        "post_quantum": {"algorithm": "ML-DSA-65", "signature": "base64:PLACEHOLDER"}}
    e5["trusted_timestamp"] = {"status": "granted", "token": "base64:AAAA", "hash_algorithm": "sha512",
                               "imprint": "00" * 64, "nonce": "1", "authority": "tsa.example",
                               "url": "https://tsa.example/tsr"}
    cases.append(("detached_fields_excluded",
                  "signatures et trusted_timestamp sont exclus du JCS, du message et du hash", e5))
    vectors = []
    for vid, desc, event in cases:
        j = jcs(unsigned(event))
        vectors.append(vec(vid, desc, True, event=event, jcs_hex=j.hex(),
                           signed_message_hex=signed_message(DOMAIN_EVENT, unsigned(event)).hex(),
                           sha512=sha512_hex(j)))
    return doc(
        "Pour chaque événement : octets JCS (RFC 8785) de l'événement privé de 'signatures' et "
        "'trusted_timestamp', message signé M' (préfixe de domaine b'PiQrypt-AISS-2.1\\x00', "
        "longueur de l'étiquette sur 1 octet, étiquette 'Ed25519+ML-DSA-65', 0x00, JCS), et "
        "hash de chaîne SHA-512 (hex minuscules, 128 caractères).",
        vectors=vectors)


def build_events():
    keys = A.keys_hex()
    genesis = event21(A, 0, "ev/0", {"action": "genesis"}, genesis_hash(A.agent_id))
    regular = event21(A, 10, "ev/1", {"action": "step", "note": "café 日本語"}, event_hash(genesis))
    other = event21(A, 20, "ev/2", {"action": "other"}, event_hash(regular))
    vectors = []

    def add(vid, desc, valid, event, reason=None, signer_keys=None):
        vectors.append(vec(vid, desc, valid, reason, agent="A",
                           verification_keys=signer_keys or keys, event=event))

    add("valid_genesis", "événement genèse valide", True, genesis)
    add("valid_regular", "événement ordinaire valide (charge utile non ASCII)", True, regular)

    def clone(e):
        return json.loads(json.dumps(e))

    e = clone(regular); e["payload"]["action"] = "tampered"
    add("payload_modified", "charge utile modifiée après signature", False, e,
        "signature does not cover the modified payload")
    e = clone(regular); e["signatures"]["classical"] = clone(other["signatures"]["classical"])
    add("classical_signature_swapped", "signature classique d'un autre événement", False, e,
        "Ed25519 signature belongs to another event")
    e = clone(regular); e["signatures"]["post_quantum"] = clone(other["signatures"]["post_quantum"])
    add("pq_signature_swapped", "signature PQ d'un autre événement", False, e,
        "ML-DSA-65 signature belongs to another event")
    e = clone(regular); del e["signatures"]["post_quantum"]
    add("pq_signature_missing", "signature post-quantique absente", False, e,
        "both signatures are mandatory")
    e = clone(regular); del e["signatures"]["classical"]
    add("classical_signature_missing", "signature classique absente", False, e,
        "both signatures are mandatory")
    e = clone(regular); e["signatures"]["classical"]["signature"] = e["signatures"]["classical"]["signature"][7:]
    add("classical_prefix_missing", "préfixe 'base64:' absent (signature classique)", False, e,
        "'base64:' prefix is mandatory")
    e = clone(regular); e["signatures"]["post_quantum"]["signature"] = e["signatures"]["post_quantum"]["signature"][7:]
    add("pq_prefix_missing", "préfixe 'base64:' absent (signature PQ)", False, e,
        "'base64:' prefix is mandatory")
    s = regular["signatures"]["classical"]["signature"]
    e = clone(regular); e["signatures"]["classical"]["signature"] = s[:20] + "\n" + s[20:]
    add("classical_base64_not_strict", "base64 non strict (retour à la ligne injecté)", False, e,
        "base64 must be decoded strictly")
    s = regular["signatures"]["post_quantum"]["signature"]
    e = clone(regular); e["signatures"]["post_quantum"]["signature"] = s[:30] + "!" + s[31:]
    add("pq_base64_not_strict", "base64 non strict (caractère hors alphabet)", False, e,
        "base64 must be decoded strictly")
    e = event21(A, 30, "ev/v210", {"action": "version"}, event_hash(regular), version="AISS-2.10")
    add("version_aiss_2_10", "version 'AISS-2.10' correctement signée", False, e,
        "version must equal 'AISS-2.1' exactly")
    e = event21(A, 30, "ev/v20", {"action": "version"}, event_hash(regular), version="AISS-2.0")
    add("version_aiss_2_0_with_2_1_signatures", "version 'AISS-2.0' portant des signatures AISS-2.1",
        False, e, "AISS-2.0 events use a different signature format")
    e = event21(D, 10, "ev/foreign", {"action": "step"}, event_hash(genesis), agent_id=A.agent_id)
    add("signed_by_other_keys", "événement de l'agent A signé par les clés de D", False, e,
        "signatures do not verify under the agent's keys")
    e = clone(regular); e["payload"]["n"] = 2 ** 53
    add("integer_out_of_range",
        "entier hors de +/-(2^53-1) dans la charge utile (signature valide copiée : le verdict "
        "est invalide quelle que soit la signature)", False, e,
        "integers outside +/-(2^53-1) cannot be canonicalized (RFC 8785)")
    return doc(
        "Vérification d'un événement AISS-2.1 isolé : version exactement 'AISS-2.1', deux "
        "signatures obligatoires au format 'base64:' strict (Ed25519 puis ML-DSA-65) sur le même "
        "message M'. 'verification_keys' donne les clés publiques en hexadécimal.",
        vectors=vectors)


def build_chains():
    vectors = []
    identity_a = identity_native(A)
    identity_b = identity_upgraded(B)

    chain_a = native_chain(A, 3, "chA")
    vectors.append(vec("native_chain", "chaîne native : genèse + 3 événements", True,
                       identity=identity_a, events=chain_a))

    b1 = event1(B, 0, "chB/1", {"action": "legacy-1"}, sha256_hex(B.ed_pub))
    b2 = event1(B, 10, "chB/2", {"action": "legacy-2"}, event_hash(b1))
    b3 = event21(B, 20, "chB/3", {"action": "hybrid-1"}, event_hash(b2))
    b4 = event21(B, 30, "chB/4", {"action": "hybrid-2"}, event_hash(b3))
    assert len(b3["previous_hash"]) == 64 and len(b4["previous_hash"]) == 128
    vectors.append(vec("upgraded_mixed_chain",
                       "identité mise à niveau : 2 événements AISS-1 puis 2 événements AISS-2.1 "
                       "(previous_hash SHA-256 de 64 caractères pour le premier AISS-2.1)",
                       True, identity=identity_b, events=[b1, b2, b3, b4]))
    vectors.append(vec("upgraded_pure_aiss1_chain", "identité mise à niveau : chaîne AISS-1 seule",
                       True, identity=identity_b, events=[b1, b2]))

    b5 = event1(B, 40, "chB/5", {"action": "legacy-after"}, event_hash(b4))
    vectors.append(vec("aiss1_after_aiss21_upgraded", "AISS-1 après le premier AISS-2.1 (mise à niveau)",
                       False, "no AISS-1 event may follow the first AISS-2.1 event",
                       identity=identity_b, events=[b1, b2, b3, b4, b5]))
    a_legacy = event1(A, 20, "chA/legacy", {"action": "legacy"}, event_hash(chain_a[1]))
    vectors.append(vec("aiss1_in_native_chain", "événement AISS-1 dans une chaîne native", False,
                       "a native hybrid identity only accepts AISS-2.1 events",
                       identity=identity_a, events=chain_a[:2] + [a_legacy]))
    foreign = event21(D, 20, "chA/foreign", {"action": "step", "seq": 2}, event_hash(chain_a[1]))
    vectors.append(vec("foreign_agent_id", "événement d'un autre agent dans la chaîne", False,
                       "event agent_id differs from the identity's agent_id",
                       identity=identity_a, events=chain_a[:2] + [foreign]))
    vectors.append(vec("event_removed", "événement supprimé au milieu de la chaîne", False,
                       "previous_hash does not match the preceding event",
                       identity=identity_a, events=[chain_a[0], chain_a[2], chain_a[3]]))

    att_c = rotation_attestation(A, A.agent_id, C)
    att_e = rotation_attestation(A, A.agent_id, E)
    rot_c = rotation_event(A, A.agent_id, att_c, event_hash(chain_a[1]), 20, "chA/rotC")
    rot_e = rotation_event(A, A.agent_id, att_e, event_hash(chain_a[1]), 21, "chA/rotE")
    vectors.append(vec("concurrent_rotations", "deux rotations concurrentes sur le même previous_hash",
                       False, "previous_hash of the second rotation does not match the hash of the first",
                       identity=identity_a, events=chain_a[:2] + [rot_c, rot_e]))
    return doc(
        "Chaînes d'événements avec leur identité. Règles : signatures, previous_hash = hash de "
        "l'événement précédent (SHA-512 pour AISS-2.1, SHA-256 pour AISS-1), horodatages non "
        "décroissants, aucun fork, nonces uniques, agent_id des événements égal à celui de "
        "l'identité, anti-downgrade (native : AISS-2.1 uniquement ; mise à niveau : plus d'AISS-1 "
        "après le premier AISS-2.1).",
        vectors=vectors)


def build_identities():
    vectors = []
    native = identity_native(A)
    upgraded = identity_upgraded(B)
    vectors.append(vec("native", "identité hybride native", True, expected_assurance="hybrid",
                       identity=native))
    vectors.append(vec("upgraded", "identité mise à niveau avec liaison signée", True,
                       expected_assurance="classical_only", identity=upgraded))

    def clone(d):
        return json.loads(json.dumps(d))

    def neg(vid, desc, identity, reason):
        vectors.append(vec(vid, desc, False, reason, expected_assurance=None, identity=identity))

    d = clone(upgraded); d["binding"]["created_at"] += 1
    neg("binding_altered", "liaison altérée (created_at)", d, "binding signatures do not verify")
    d = clone(upgraded); d["public_key_pq"] = b64p(D.pq_pk)
    neg("upgraded_pq_key_replaced", "clé PQ de l'identité remplacée (liaison intacte)", d,
        "identity.public_key_pq differs from the binding's")
    d = clone(native); d["public_key_pq"] = b64p(D.pq_pk)
    neg("native_pq_key_replaced", "clé PQ remplacée dans une identité native", d,
        "agent_id does not derive from the two keys")
    d = clone(upgraded); d["public_key"] = b64plain(D.ed_pub)
    neg("public_key_altered", "clé historique public_key altérée", d,
        "binding's classical key differs from public_key")
    d = clone(native); d["binding"] = clone(upgraded["binding"])
    neg("ambiguous_native_with_binding", "public_key_classical avec binding (ambigu)", d,
        "ambiguous: public_key_classical cannot be combined with binding")
    d = clone(native); d["public_key"] = b64plain(A.ed_pub)
    neg("ambiguous_native_with_public_key", "public_key_classical avec public_key (ambigu)", d,
        "ambiguous: public_key_classical cannot be combined with public_key")
    d = clone(native); d["agent_id"] = D.id21
    neg("native_agent_id_not_derived", "agent_id natif qui ne dérive pas des clés", d,
        "agent_id does not derive from the two keys")
    d = clone(upgraded); d["agent_id"] = D.id1
    neg("upgraded_agent_id_mismatch", "agent_id d'une identité mise à niveau différent de la liaison", d,
        "binding.agent_id differs from identity.agent_id")
    return doc(
        "Validité d'une identité AISS-2.1. 'expected_assurance' : 'hybrid' (agent_id dérivé des "
        "deux clés) ou 'classical_only' (identité AISS-1 avec liaison valide signée par les deux "
        "clés), null pour une identité invalide. Un document portant public_key_classical avec "
        "binding ou public_key est ambigu et rejeté.",
        vectors=vectors)


def build_rotation():
    vectors = []
    identity_a = identity_native(A)
    identity_b = identity_upgraded(B)

    def clone(d):
        return json.loads(json.dumps(d))

    att_a = rotation_attestation(A, A.agent_id, C)
    att_b = rotation_attestation(B, B.agent_id, C)
    vectors.append(vec("attestation_from_native", "attestation à quatre signatures : A vers C", True,
                       type="attestation", previous_identity=identity_a, attestation=att_a))
    vectors.append(vec("attestation_from_upgraded", "attestation à quatre signatures : B (mise à niveau) vers C",
                       True, type="attestation", previous_identity=identity_b, attestation=att_b))

    d = clone(att_a); del d["signatures"]["previous_post_quantum"]
    vectors.append(vec("attestation_signature_removed", "signature previous_post_quantum absente", False,
                       "all four signatures are mandatory", type="attestation",
                       previous_identity=identity_a, attestation=d))
    d = clone(att_a); d["rotation_timestamp"] += 1
    vectors.append(vec("attestation_field_altered", "rotation_timestamp altéré", False,
                       "signatures do not cover the altered field", type="attestation",
                       previous_identity=identity_a, attestation=d))
    vectors.append(vec("attestation_wrong_previous_identity", "attestation de A vérifiée contre l'identité D",
                       False, "previous keys differ from the previous identity", type="attestation",
                       previous_identity=identity_native(D), attestation=att_a))
    att_self = rotation_attestation(A, A.agent_id, A)
    vectors.append(vec("attestation_to_self", "rotation vers soi-même (new_agent_id == previous_agent_id)",
                       False, "new_agent_id equals previous_agent_id", type="attestation",
                       previous_identity=identity_a, attestation=att_self))

    old = native_chain(A, 1, "rot")  # genèse + 1 événement
    rot = rotation_event(A, A.agent_id, att_a, event_hash(old[-1]), 20, "rot/rotation")
    new_genesis = event21(C, 30, "rot/newgen", {"action": "genesis_after_rotation"}, event_hash(rot))
    vectors.append(vec("chained_rotation", "rotation chaînée complète : ancienne chaîne, rotation, nouvelle genèse",
                       True, type="chain", previous_identity=identity_a,
                       old_events=old + [rot], new_genesis=new_genesis))

    late = event21(A, 25, "rot/late", {"action": "after rotation"}, event_hash(rot))
    vectors.append(vec("event_after_rotation", "événement ajouté après la rotation dans l'ancienne chaîne",
                       False, "the rotation event must be the last event of the old chain",
                       type="chain", previous_identity=identity_a,
                       old_events=old + [rot, late], new_genesis=new_genesis))
    wrong_anchor = event21(C, 30, "rot/wronganchor", {"action": "genesis_after_rotation"},
                           genesis_hash(C.agent_id))
    vectors.append(vec("wrong_anchor", "genèse non ancrée sur l'événement de rotation", False,
                       "genesis previous_hash differs from the rotation event hash", type="chain",
                       previous_identity=identity_a, old_events=old + [rot], new_genesis=wrong_anchor))
    forged = event21(D, 30, "rot/forgedgen", {"action": "genesis_after_rotation"}, event_hash(rot),
                     agent_id=C.agent_id)
    vectors.append(vec("genesis_signed_by_other_keys", "genèse de C signée par les clés de D", False,
                       "genesis is not signed by the new keys of the attestation", type="chain",
                       previous_identity=identity_a, old_events=old + [rot], new_genesis=forged))
    rot_self = rotation_event(A, A.agent_id, att_self, event_hash(old[-1]), 20, "rot/self")
    gen_self = event21(A, 30, "rot/selfgen", {"action": "genesis_after_rotation"}, event_hash(rot_self))
    vectors.append(vec("chain_rotation_to_self", "rotation chaînée vers soi-même", False,
                       "new_agent_id equals previous_agent_id", type="chain",
                       previous_identity=identity_a, old_events=old + [rot_self], new_genesis=gen_self))
    return doc(
        "Rotation hybride. 'attestation' : quatre signatures (previous_classical, "
        "previous_post_quantum, new_classical, new_post_quantum) sur un même message à préfixe de "
        "domaine b'PiQrypt-AISS-2.1-rotation\\x00' ; new_agent_id dérivé des deux nouvelles clés ; "
        "anciennes clés égales à celles de l'identité précédente ; rotation vers soi-même refusée. "
        "'chain' : le dernier événement de l'ancienne chaîne est la rotation, la nouvelle genèse "
        "a pour previous_hash le hash de cet événement, pour agent_id new_agent_id, et est signée "
        "par les nouvelles clés.",
        vectors=vectors)


def build_all():
    return {
        "keys.json": build_keys(),
        "agent_id.json": build_agent_id(),
        "hash_and_message.json": hash_vectors(),
        "events.json": build_events(),
        "chains.json": build_chains(),
        "identities.json": build_identities(),
        "rotation.json": build_rotation(),
    }


def write_all(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    for name, content in build_all().items():
        with open(os.path.join(out_dir, name), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(content, fh, indent=1, sort_keys=True, ensure_ascii=True)
            fh.write("\n")


def main(argv=None):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--out", default=os.path.join(root, "test_vectors_aiss21"))
    args = ap.parse_args(argv)
    write_all(args.out)
    print(f"vecteurs écrits dans {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
