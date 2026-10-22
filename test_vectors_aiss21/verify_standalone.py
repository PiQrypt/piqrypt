#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Independent verifier for the AISS-2.1 test vectors.

Imports NOTHING from `aiss` or `piqrypt`. Allowed dependencies: the standard library,
rfc8785, base58, cryptography and dilithium-py. It re-implements, from the format described
in README.md, the agent_id derivation, the signed message M', the chain hash, event
verification, chain rules (including anti-downgrade), identity bindings and key rotation, and
prints one verdict per vector.

Usage:  python verify_standalone.py [--vectors DIR]
Exit status: 0 when every verdict equals the vector's "valid" field, 1 otherwise.
"""
import argparse
import base64
import binascii
import hashlib
import json
import os
import struct
import sys

import base58
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from dilithium_py.ml_dsa import ML_DSA_65

SPEC_VERSION = "AISS-2.1"
LABEL = b"Ed25519+ML-DSA-65"
DOMAIN_EVENT = b"PiQrypt-AISS-2.1\x00"
DOMAIN_BINDING = b"PiQrypt-AISS-2.1-binding\x00"
DOMAIN_ROTATION = b"PiQrypt-AISS-2.1-rotation\x00"
DOMAIN_AGENT_ID = b"PiQrypt-AISS-2.1-agent-id\x00"
ED_SIZE, PQ_SIZE = 32, 1952


class Reject(Exception):
    """The document violates a rule of the format."""


# ─── encodings ───────────────────────────────────────────────────────────────

def strict_b64(value, what, size=None):
    """'base64:' prefix mandatory, strict alphabet (no whitespace), exact size."""
    if not isinstance(value, str) or not value.startswith("base64:"):
        raise Reject(f"{what}: 'base64:' prefix is mandatory")
    try:
        raw = base64.b64decode(value[7:], validate=True)
    except (binascii.Error, ValueError):
        raise Reject(f"{what}: invalid base64")
    if size is not None and len(raw) != size:
        raise Reject(f"{what}: {len(raw)} bytes instead of {size}")
    return raw


def plain_b64(value, what, size=None):
    if not isinstance(value, str):
        raise Reject(f"{what}: string expected")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise Reject(f"{what}: invalid base64")
    if size is not None and len(raw) != size:
        raise Reject(f"{what}: {len(raw)} bytes instead of {size}")
    return raw


def jcs(obj):
    try:
        return rfc8785.dumps(obj)
    except Exception as exc:
        raise Reject(f"not canonicalizable: {exc}")


def message(domain, document):
    """M' = domain || len(label) || label || 0x00 || JCS(document)"""
    return domain + bytes([len(LABEL)]) + LABEL + b"\x00" + jcs(document)


def without(document, *fields):
    return {k: v for k, v in document.items() if k not in fields}


# ─── identifiers and hashes ──────────────────────────────────────────────────

def agent_id_aiss21(ed_pub, pq_pub):
    if len(ed_pub) != ED_SIZE:
        raise Reject("Ed25519 public key must be 32 bytes")
    if len(pq_pub) != PQ_SIZE:
        raise Reject("ML-DSA-65 public key must be 1952 bytes")
    data = (DOMAIN_AGENT_ID + struct.pack(">I", len(ed_pub)) + ed_pub
            + struct.pack(">I", len(pq_pub)) + pq_pub)
    return base58.b58encode(hashlib.sha512(data).digest()).decode("ascii")[:32]


def agent_id_aiss1(ed_pub):
    return base58.b58encode(hashlib.sha256(ed_pub).digest()).decode("ascii")[:32]


def event_hash(event):
    if event.get("version") == SPEC_VERSION:
        return hashlib.sha512(jcs(without(event, "signatures", "trusted_timestamp"))).hexdigest()
    return hashlib.sha256(jcs(without(event, "signature", "trusted_timestamp"))).hexdigest()


# ─── signatures ──────────────────────────────────────────────────────────────

def verify_ed(pub, msg, sig):
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
    except (InvalidSignature, ValueError):
        raise Reject("Ed25519 signature invalid")


def verify_pq(pub, msg, sig):
    try:
        ok = ML_DSA_65.verify(pub, msg, sig)
    except Exception:
        ok = False
    if not ok:
        raise Reject("ML-DSA-65 signature invalid")


def verify_dual(entry_classical, entry_pq, ed_pub, pq_pub, msg, names=("classical", "post_quantum")):
    if not isinstance(entry_classical, dict) or not isinstance(entry_pq, dict):
        raise Reject("both signatures are mandatory")
    verify_ed(ed_pub, msg, strict_b64(entry_classical.get("signature"), f"{names[0]} signature"))
    verify_pq(pq_pub, msg, strict_b64(entry_pq.get("signature"), f"{names[1]} signature"))


def verify_event21(event, ed_pub, pq_pub):
    if not isinstance(event, dict) or event.get("version") != SPEC_VERSION:
        raise Reject("version must equal 'AISS-2.1' exactly")
    sigs = event.get("signatures")
    if not isinstance(sigs, dict):
        raise Reject("signatures missing")
    msg = message(DOMAIN_EVENT, without(event, "signatures", "trusted_timestamp"))
    verify_dual(sigs.get("classical"), sigs.get("post_quantum"), ed_pub, pq_pub, msg)


def verify_event1(event, ed_pub):
    sig = plain_b64(event.get("signature"), "AISS-1 signature")
    verify_ed(ed_pub, jcs(without(event, "signature", "trusted_timestamp")), sig)


# ─── identities ──────────────────────────────────────────────────────────────

def identity_form(identity):
    if not isinstance(identity, dict):
        raise Reject("identity must be an object")
    if "public_key_classical" in identity:
        if "binding" in identity or "public_key" in identity:
            raise Reject("ambiguous identity")
        return "native"
    if "binding" in identity or "public_key_pq" in identity:
        return "upgraded"
    return "classical"


def check_binding(identity):
    binding = identity.get("binding")
    if not isinstance(binding, dict):
        raise Reject("binding missing")
    if (binding.get("version") != SPEC_VERSION or binding.get("type") != "identity_binding"
            or binding.get("binding_assurance") != "classical_only"):
        raise Reject("unexpected binding header")
    agent_id = identity.get("agent_id")
    if not isinstance(agent_id, str) or binding.get("agent_id") != agent_id:
        raise Reject("binding.agent_id differs from identity.agent_id")
    ed_pub = strict_b64(binding.get("public_key_classical"), "binding classical key", ED_SIZE)
    pq_pub = strict_b64(binding.get("public_key_pq"), "binding PQ key", PQ_SIZE)
    if plain_b64(identity.get("public_key"), "public_key", ED_SIZE) != ed_pub:
        raise Reject("binding's classical key differs from public_key")
    if "public_key_pq" in identity and strict_b64(
            identity["public_key_pq"], "public_key_pq", PQ_SIZE) != pq_pub:
        raise Reject("identity.public_key_pq differs from the binding's")
    if agent_id_aiss1(ed_pub) != agent_id:
        raise Reject("agent_id does not derive from the classical key")
    sigs = binding.get("signatures")
    if not isinstance(sigs, dict):
        raise Reject("binding signatures missing")
    classical, post_quantum = sigs.get("classical"), sigs.get("post_quantum")
    if not isinstance(classical, dict) or not isinstance(post_quantum, dict):
        raise Reject("both binding signatures are mandatory")
    if classical.get("algorithm") != "Ed25519" or post_quantum.get("algorithm") != "ML-DSA-65":
        raise Reject("unexpected signature algorithm")
    verify_dual(classical, post_quantum, ed_pub, pq_pub,
                message(DOMAIN_BINDING, without(binding, "signatures")))
    return ed_pub, pq_pub


def resolve_identity(identity):
    """Returns (form, ed_pub, pq_pub, assurance); raises Reject on any invalid identity."""
    form = identity_form(identity)
    if form == "native":
        ed_pub = strict_b64(identity.get("public_key_classical"), "public_key_classical", ED_SIZE)
        pq_pub = strict_b64(identity.get("public_key_pq"), "public_key_pq", PQ_SIZE)
        if agent_id_aiss21(ed_pub, pq_pub) != identity.get("agent_id"):
            raise Reject("agent_id does not derive from the two keys")
        return form, ed_pub, pq_pub, "hybrid"
    if form == "upgraded":
        ed_pub, pq_pub = check_binding(identity)
        return form, ed_pub, pq_pub, "classical_only"
    ed_pub = plain_b64(identity.get("public_key"), "public_key", ED_SIZE)
    if agent_id_aiss1(ed_pub) != identity.get("agent_id"):
        raise Reject("agent_id does not derive from the key")
    return form, ed_pub, None, None


# ─── chains ──────────────────────────────────────────────────────────────────

def verify_chain(events, identity):
    if not isinstance(events, list) or not events:
        raise Reject("empty chain")
    form, ed_pub, pq_pub, _ = resolve_identity(identity)
    agent_id = identity["agent_id"]
    seen_aiss21 = False
    for i, event in enumerate(events):
        if not isinstance(event, dict):
            raise Reject(f"event {i} is not an object")
        version = event.get("version")
        is_21 = version == SPEC_VERSION
        if form != "classical":
            if event.get("agent_id") != agent_id:
                raise Reject(f"event {i}: agent_id differs from the identity's")
            if form == "native" and not is_21:
                raise Reject(f"event {i}: native identity accepts AISS-2.1 events only")
            if form == "upgraded":
                if seen_aiss21 and not is_21:
                    raise Reject(f"event {i}: downgrade after the first AISS-2.1 event")
                seen_aiss21 = seen_aiss21 or is_21
        if is_21:
            if pq_pub is None:
                raise Reject(f"event {i}: AISS-2.1 event without a PQ key")
            verify_event21(event, ed_pub, pq_pub)
        elif isinstance(version, str) and version.startswith("AISS-1"):
            verify_event1(event, ed_pub)
        else:
            raise Reject(f"event {i}: unsupported version {version!r}")
    for i in range(1, len(events)):
        if events[i].get("previous_hash") != event_hash(events[i - 1]):
            raise Reject(f"event {i}: previous_hash does not match the preceding event")
        if events[i].get("timestamp", 0) < events[i - 1].get("timestamp", 0):
            raise Reject(f"event {i}: timestamp decreases")
    previous_hashes = [e.get("previous_hash") for e in events if e.get("previous_hash")]
    if len(previous_hashes) != len(set(previous_hashes)):
        raise Reject("fork: two events share the same previous_hash")
    nonces = set()
    for i, event in enumerate(events):
        key = (event.get("agent_id"), event.get("nonce"))
        if not event.get("nonce") or key in nonces:
            raise Reject(f"event {i}: nonce empty or reused")
        nonces.add(key)
    return True


# ─── rotation ────────────────────────────────────────────────────────────────

ROTATION_SIGNATURES = (
    ("previous_classical", "Ed25519"),
    ("previous_post_quantum", "ML-DSA-65"),
    ("new_classical", "Ed25519"),
    ("new_post_quantum", "ML-DSA-65"),
)


def check_attestation(att, previous_identity):
    if not isinstance(att, dict):
        raise Reject("attestation must be an object")
    if att.get("version") != SPEC_VERSION or att.get("type") != "key_rotation":
        raise Reject("unexpected attestation header")
    ts = att.get("rotation_timestamp")
    if not isinstance(ts, int) or isinstance(ts, bool):
        raise Reject("rotation_timestamp must be an integer")
    _, prev_ed, prev_pq, _ = resolve_identity(previous_identity)
    if prev_pq is None:
        raise Reject("previous identity has no PQ key")
    if att.get("previous_agent_id") != previous_identity.get("agent_id"):
        raise Reject("previous_agent_id differs from the previous identity")
    if strict_b64(att.get("previous_public_key_classical"), "previous classical key", ED_SIZE) != prev_ed:
        raise Reject("previous classical key differs from the previous identity")
    if strict_b64(att.get("previous_public_key_pq"), "previous PQ key", PQ_SIZE) != prev_pq:
        raise Reject("previous PQ key differs from the previous identity")
    new_ed = strict_b64(att.get("new_public_key_classical"), "new classical key", ED_SIZE)
    new_pq = strict_b64(att.get("new_public_key_pq"), "new PQ key", PQ_SIZE)
    if att.get("new_agent_id") != agent_id_aiss21(new_ed, new_pq):
        raise Reject("new_agent_id does not derive from the two new keys")
    if att["new_agent_id"] == att["previous_agent_id"]:
        raise Reject("rotation to self")
    sigs = att.get("signatures")
    if not isinstance(sigs, dict):
        raise Reject("signatures missing")
    msg = message(DOMAIN_ROTATION, without(att, "signatures"))
    keys = {"previous_classical": prev_ed, "previous_post_quantum": prev_pq,
            "new_classical": new_ed, "new_post_quantum": new_pq}
    for name, algorithm in ROTATION_SIGNATURES:
        entry = sigs.get(name)
        if not isinstance(entry, dict) or entry.get("algorithm") != algorithm:
            raise Reject(f"signature {name} missing or with an unexpected algorithm")
        sig = strict_b64(entry.get("signature"), f"signature {name}")
        (verify_ed if algorithm == "Ed25519" else verify_pq)(keys[name], msg, sig)
    return new_ed, new_pq


def check_rotation_chain(old_events, previous_identity, new_genesis):
    if not isinstance(old_events, list) or not old_events or not isinstance(new_genesis, dict):
        raise Reject("malformed rotation chain")
    last = old_events[-1]
    if not isinstance(last, dict) or last.get("version") != SPEC_VERSION:
        raise Reject("the last event must be an AISS-2.1 event")
    payload = last.get("payload")
    if not isinstance(payload, dict) or payload.get("event_type") != "key_rotation":
        raise Reject("the last event is not a rotation event")
    attestation = payload.get("attestation")
    new_ed, new_pq = check_attestation(attestation, previous_identity)
    if last.get("agent_id") != attestation["previous_agent_id"]:
        raise Reject("rotation event agent_id differs from previous_agent_id")
    verify_chain(old_events, previous_identity)
    if new_genesis.get("previous_hash") != event_hash(last):
        raise Reject("genesis is not anchored on the rotation event")
    if new_genesis.get("agent_id") != attestation["new_agent_id"]:
        raise Reject("genesis agent_id differs from new_agent_id")
    verify_event21(new_genesis, new_ed, new_pq)
    return True


# ─── vectors ─────────────────────────────────────────────────────────────────

def verdict(filename, v):
    """True when the vector is valid under the format, False when rejected."""
    try:
        if filename == "agent_id.json":
            got = agent_id_aiss21(bytes.fromhex(v["ed25519_public_key"]),
                                  bytes.fromhex(v["ml_dsa_65_public_key"]))
            return got == v["expected_agent_id"]
        if filename == "hash_and_message.json":
            body = without(v["event"], "signatures", "trusted_timestamp")
            j = jcs(body)
            return (j.hex() == v["jcs_hex"]
                    and (DOMAIN_EVENT + bytes([len(LABEL)]) + LABEL + b"\x00" + j).hex()
                    == v["signed_message_hex"]
                    and event_hash(v["event"]) == v["sha512"])
        if filename == "events.json":
            keys = v["verification_keys"]
            verify_event21(v["event"], bytes.fromhex(keys["ed25519"]),
                           bytes.fromhex(keys["ml_dsa_65"]))
            return True
        if filename == "chains.json":
            return verify_chain(v["events"], v["identity"])
        if filename == "identities.json":
            assurance = resolve_identity(v["identity"])[3]
            return assurance is not None and assurance == v["expected_assurance"]
        if filename == "rotation.json":
            if v["type"] == "attestation":
                check_attestation(v["attestation"], v["previous_identity"])
                return True
            return check_rotation_chain(v["old_events"], v["previous_identity"], v["new_genesis"])
        raise ValueError(f"no rule for {filename}")
    except Reject:
        return False


VECTOR_FILES = ["agent_id.json", "hash_and_message.json", "events.json",
                "chains.json", "identities.json", "rotation.json"]


def all_verdicts(vectors_dir):
    """{'file:id': (verdict, expected)} for every vector."""
    results = {}
    for name in VECTOR_FILES:
        with open(os.path.join(vectors_dir, name), encoding="utf-8") as fh:
            for v in json.load(fh)["vectors"]:
                results[f"{name}:{v['id']}"] = (verdict(name, v), v["valid"])
    return results


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="Independent verifier for the AISS-2.1 vectors")
    ap.add_argument("--vectors", default=here, help="directory holding the JSON vector files")
    args = ap.parse_args(argv)
    results = all_verdicts(args.vectors)
    mismatches = 0
    for key, (got, expected) in sorted(results.items()):
        ok = got == expected
        mismatches += not ok
        print(f"{'OK      ' if ok else 'MISMATCH'} {key}: verdict={'valid' if got else 'invalid'} "
              f"expected={'valid' if expected else 'invalid'}")
    print(f"{len(results) - mismatches}/{len(results)} vectors match")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
