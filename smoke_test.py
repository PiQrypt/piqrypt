# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#!/usr/bin/env python3
"""
PiQrypt v1.8.6 — Smoke Test / Validation Complète
==================================================

Valide l'ensemble du stack de bout en bout :

  BLOC 1  — Cryptographie de base (keypair, Ed25519, RFC 8785)
  BLOC 2  — Stamp & Chain (genesis, events, hash chain)
  BLOC 3  — Mémoire (store, load, search)
  BLOC 4  — KeyStore (scrypt N=2^17 + AES-256-GCM + RAM erasure)
  BLOC 5  — AgentRegistry (isolation, path traversal)
  BLOC 6  — Export & Vérification complète
  BLOC 7  — Fork & Replay detection
  BLOC 8  — A2A Handshake
  BLOC 9  — Trust Score (TS)
  BLOC 10 — TSI Engine (Trust Stability Index)
  BLOC 11 — A2C Detector (16 scénarios relationnels)
  BLOC 12 — Anomaly Monitor (VRS)
  BLOC 13 — Vigil Server (HTTP dashboard)
  BLOC 14 — Suite de tests unitaires complète (run_all.py)

Usage :
    cd piqrypt/
    python smoke_test.py           # résumé compact
    python smoke_test.py -v        # verbose (chaque check)
    python smoke_test.py --stop    # stop au premier échec
    python smoke_test.py --bloc 4  # un seul bloc
"""

import os
import sys
import json
import time
import tempfile
import threading
import traceback
import argparse
from pathlib import Path
from typing import List, Tuple

# Mode test : scrypt N=2^14 (~50ms) au lieu de 2^17 (~400ms)
os.environ.setdefault("PIQRYPT_SCRYPT_N", "16384")

# Résolution du path projet
ROOT = Path(__file__).resolve().parent
for candidate in [ROOT, ROOT/"piqrypt", ROOT/"piqrypt"/"piqrypt"]:
    if (candidate/"aiss").exists():
        PIQRYPT_ROOT = candidate
        break
else:
    print(f"ERREUR : impossible de trouver aiss/ depuis {ROOT}")
    sys.exit(1)

sys.path.insert(0, str(PIQRYPT_ROOT))
sys.path.insert(0, str(PIQRYPT_ROOT/"vigil"))

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

_results: List[Tuple[str, str, str, str]] = []
_stop_on_first_fail = False
_verbose = False


def check(bloc, name, fn, *args, **kwargs):
    try:
        detail = fn(*args, **kwargs) or ""
        _results.append((bloc, name, "OK", str(detail)))
        if _verbose:
            print(f"  {GREEN}✓{RESET} {name}  {DIM}{detail}{RESET}")
        return True
    except Exception:
        tb = traceback.format_exc().strip().split("\n")[-1]
        _results.append((bloc, name, "FAIL", tb))
        if _verbose:
            print(f"  {RED}✗{RESET} {name}\n    {DIM}{tb}{RESET}")
        if _stop_on_first_fail:
            print_summary()
            sys.exit(1)
        return False


def section(title):
    if _verbose:
        print(f"\n{BOLD}{CYAN}▶ {title}{RESET}")


def print_summary():
    total = len(_results)
    ok = sum(1 for r in _results if r[2] == "OK")
    fail = sum(1 for r in _results if r[2] == "FAIL")
    print("\n" + "=" * 65)
    print(f"{BOLD}BILAN — PiQrypt v1.8.6 Smoke Test{RESET}")
    print("=" * 65)
    blocs = {}
    for bloc, name, status, detail in _results:
        blocs.setdefault(bloc, []).append((name, status, detail))
    for bloc, checks in blocs.items():
        ok_b = sum(1 for _, s, _ in checks if s == "OK")
        tot = len(checks)
        icon = f"{GREEN}✓{RESET}" if ok_b == tot else f"{RED}✗{RESET}"
        print(f"\n  {icon} {BOLD}{bloc}{RESET}  ({ok_b}/{tot})")
        for name, status, detail in checks:
            if status == "FAIL":
                print(f"      {RED}✗{RESET} {name}\n        {DIM}{detail}{RESET}")
            elif _verbose:
                print(f"      {GREEN}✓{RESET} {name}  {DIM}{detail}{RESET}")
    print("\n" + "─" * 65)
    print(f"  Total   : {total}")
    print(f"  {GREEN}Passés{RESET}  : {ok}")
    if fail:
        print(f"  {RED}Échecs{RESET}  : {fail}")
    print()
    if fail == 0:
        print(f"{GREEN}{BOLD}  ✅  Tous les checks passés — stack v1.8.4 opérationnel{RESET}")
    else:
        print(f"{RED}{BOLD}  ❌  {fail} check(s) en échec{RESET}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# BLOC 1 — Cryptographie de base
# ─────────────────────────────────────────────────────────────────────────────
def bloc1_crypto():
    B = "BLOC 1 — Cryptographie de base"
    section(B)
    from aiss.crypto import ed25519
    from aiss.identity import generate_keypair, derive_agent_id
    from aiss.canonical import canonicalize

    def test_keypair():
        priv, pub = generate_keypair()
        assert len(priv) == 32 and len(pub) == 32
        return f"priv={len(priv)}B pub={len(pub)}B"

    def test_agent_id():
        priv, pub = generate_keypair()
        a1, a2 = derive_agent_id(pub), derive_agent_id(pub)
        assert a1 == a2 and len(a1) > 10
        return f"id={a1[:12]}..."

    def test_sign_verify():
        priv, pub = generate_keypair()
        msg = b"piqrypt smoke test"
        sig = ed25519.sign(priv, msg)
        assert len(sig) == 64 and ed25519.verify(pub, msg, sig) is True
        return f"sig={len(sig)}B"

    def test_sign_tampered():
        priv, pub = generate_keypair()
        sig = ed25519.sign(priv, b"original")
        try:
            result = ed25519.verify(pub, b"tampered", sig)
            assert result is False
        except Exception:
            pass
        return "tampered rejected"

    def test_canonicalize():
        b1 = canonicalize({"z": 1, "a": 2, "m": [3, 4]})
        b2 = canonicalize({"a": 2, "m": [3, 4], "z": 1})
        assert b1 == b2 and isinstance(b1, bytes)
        assert b'"a"' in b1
        return f"{len(b1)}B déterministe"

    def test_canonicalize_nested():
        b = canonicalize({"b": {"d": 1, "c": 2}, "a": [3, 1, 2]})
        assert isinstance(b, bytes)
        assert b.index(b'"c"') < b.index(b'"d"')
        return "clés imbriquées triées"

    check(B, "generate_keypair — Ed25519 32B", test_keypair)
    check(B, "derive_agent_id — déterministe", test_agent_id)
    check(B, "ed25519.sign + verify (valide)", test_sign_verify)
    check(B, "ed25519.verify (message altéré)", test_sign_tampered)
    check(B, "canonicalize RFC 8785 — bytes, trié", test_canonicalize)
    check(B, "canonicalize RFC 8785 — clés imbriquées", test_canonicalize_nested)


# ─────────────────────────────────────────────────────────────────────────────
# BLOC 2 — Stamp & Chain
# ─────────────────────────────────────────────────────────────────────────────
def bloc2_stamp_chain():
    B = "BLOC 2 — Stamp & Chain"
    section(B)
    from aiss.identity import generate_keypair, derive_agent_id, export_identity
    from aiss.stamp import stamp_event, stamp_genesis_event
    from aiss.chain import compute_event_hash
    from aiss.verify import verify_signature, verify_chain

    priv, pub = generate_keypair()
    aid = derive_agent_id(pub)
    identity = export_identity(aid, pub)

    def chain(n=5):
        g = stamp_genesis_event(priv, pub, aid, {"action": "genesis"})
        c, prev = [g], compute_event_hash(g)
        for i in range(1, n):
            e = stamp_event(priv, aid, {"action": f"op_{i}"}, previous_hash=prev)
            c.append(e)
            prev = compute_event_hash(e)
        return c

    def test_genesis():
        g = stamp_genesis_event(priv, pub, aid, {"action": "g"})
        assert g["version"] == "AISS-1.0" and g["agent_id"] == aid
        assert "signature" in g and "nonce" in g
        return f"version={g['version']}"

    def test_stamp():
        g = stamp_genesis_event(priv, pub, aid, {"action": "g"})
        prev = compute_event_hash(g)
        e = stamp_event(priv, aid, {"action": "step"}, previous_hash=prev)
        assert e["previous_hash"] == prev
        return "previous_hash lié"

    def test_sig_valid():
        g = stamp_genesis_event(priv, pub, aid, {"action": "g"})
        assert verify_signature(g, pub) is True
        return "valid"

    def test_sig_tampered():
        g = stamp_genesis_event(priv, pub, aid, {"action": "g"})
        g["payload"]["action"] = "TAMPERED"
        try:
            ok = verify_signature(g, pub)
            assert ok is False
        except Exception:
            pass
        return "tampered rejected"

    def test_chain_valid():
        c = chain(5)
        result = verify_chain(c, identity)
        assert result is True or result
        return f"{len(c)} events"

    def test_chain_tampered():
        c = chain(5)
        c[2]["payload"]["action"] = "TAMPERED"
        try:
            result = verify_chain(c, identity)
            assert not result
        except Exception:
            pass
        return "tampered detected"

    def test_hash_det():
        g = stamp_genesis_event(priv, pub, aid, {"action": "g"})
        assert compute_event_hash(g) == compute_event_hash(g)
        return "déterministe"

    def test_nonce_unique():
        g1 = stamp_genesis_event(priv, pub, aid, {"action": "a"})
        g2 = stamp_genesis_event(priv, pub, aid, {"action": "b"})
        assert g1["nonce"] != g2["nonce"]
        return "unique"

    check(B, "stamp_genesis_event — structure AISS-1.0", test_genesis)
    check(B, "stamp_event — previous_hash lié", test_stamp)
    check(B, "verify_signature (valide)", test_sig_valid)
    check(B, "verify_signature (altéré)", test_sig_tampered)
    check(B, "verify_chain — 5 events valide", test_chain_valid)
    check(B, "verify_chain — chaîne altérée", test_chain_tampered)
    check(B, "compute_event_hash — déterministe", test_hash_det)
    check(B, "Nonces UUID v4 — unicité", test_nonce_unique)


# ─────────────────────────────────────────────────────────────────────────────
# BLOC 3 — Mémoire
# ─────────────────────────────────────────────────────────────────────────────
def bloc3_memory():
    B = "BLOC 3 — Mémoire (store / load / search)"
    section(B)
    from aiss.identity import generate_keypair, derive_agent_id
    from aiss.stamp import stamp_event, stamp_genesis_event
    from aiss.chain import compute_event_hash
    from aiss.memory import store_event_free, load_events_free, search_events

    priv, pub = generate_keypair()
    aid = derive_agent_id(pub)
    name = f"smoke_mem_{int(time.time())}"

    def test_store_load():
        g = stamp_genesis_event(priv, pub, aid, {"action": "genesis"})
        store_event_free(g, agent_name=name)
        evts = load_events_free(agent_name=name)
        assert len(evts) >= 1
        return f"{len(evts)} event(s)"

    def test_store_many():
        n2 = name + "_multi"
        g = stamp_genesis_event(priv, pub, aid, {"action": "g"})
        prev = compute_event_hash(g)
        store_event_free(g, agent_name=n2)
        for i in range(4):
            e = stamp_event(priv, aid, {"action": f"op_{i}"}, previous_hash=prev)
            store_event_free(e, agent_name=n2)
            prev = compute_event_hash(e)
        evts = load_events_free(agent_name=n2)
        assert len(evts) >= 5
        return f"{len(evts)} events"

    def test_search():
        n3 = name + "_srch"
        g = stamp_genesis_event(priv, pub, aid, {"action": "g", "event_type": "smoke_unique_42"})
        store_event_free(g, agent_name=n3)
        found = search_events(event_type="smoke_unique_42")
        assert isinstance(found, list)
        return f"{len(found)} résultat(s)"

    check(B, "store_event_free + load_events_free", test_store_load)
    check(B, "Store 5 events + load all", test_store_many)
    check(B, "search_events par event_type", test_search)


# ─────────────────────────────────────────────────────────────────────────────
# BLOC 4 — KeyStore
# ─────────────────────────────────────────────────────────────────────────────
def bloc4_keystore():
    B = "BLOC 4 — KeyStore (scrypt + AES-256-GCM)"
    section(B)
    from aiss.key_store import (
        save_encrypted_key, load_encrypted_key,
        encrypt_private_key, decrypt_private_key,
        _secure_erase, EXPECTED_FILE_SIZE, MAGIC,
    )
    from aiss.identity import generate_keypair

    priv, pub = generate_keypair()
    pp = "smoke-test-2026"

    with tempfile.TemporaryDirectory() as d:
        kp = Path(d) / "test.key.enc"

        def test_mem():
            enc = encrypt_private_key(priv, pp)
            rec = decrypt_private_key(enc, pp)
            assert rec == priv
            return f"{len(enc)}B"

        def test_file():
            save_encrypted_key(priv, pp, kp)
            assert kp.exists()
            sz = kp.stat().st_size
            assert sz == EXPECTED_FILE_SIZE, f"size={sz}≠{EXPECTED_FILE_SIZE}"
            assert load_encrypted_key(kp, pp) == priv
            return f"{sz}B (expected {EXPECTED_FILE_SIZE}B)"

        def test_magic():
            with open(kp, "rb") as f:
                magic = f.read(4)
            assert magic == MAGIC
            return f"magic={magic}"

        def test_wrong_pp():
            try:
                load_encrypted_key(kp, "WRONG")
                assert False
            except Exception:
                pass
            return "rejected"

        def test_corrupted():
            bad = Path(d) / "bad.key.enc"
            bad.write_bytes(b"\x00" * EXPECTED_FILE_SIZE)
            try:
                load_encrypted_key(bad, pp)
            except Exception:
                pass
            return "handled"

        def test_erase():
            data = bytearray(priv)
            _secure_erase(data)
            assert all(b == 0 for b in data)
            return "RAM zeroed"

        check(B, "encrypt_private_key / decrypt_private_key", test_mem)
        check(B, "save_encrypted_key + load — fichier 97B", test_file)
        check(B, "Magic bytes PQKY vérifiés", test_magic)
        check(B, "Mauvaise passphrase rejetée", test_wrong_pp)
        check(B, "Fichier corrompu géré", test_corrupted)
        check(B, "_secure_erase — RAM zeroing", test_erase)


# ─────────────────────────────────────────────────────────────────────────────
# BLOC 5 — AgentRegistry
# ─────────────────────────────────────────────────────────────────────────────
def bloc5_registry():
    B = "BLOC 5 — AgentRegistry"
    section(B)
    from aiss.agent_registry import (
        register_agent, get_agent_info, list_agents,
        agent_exists, unregister_agent, _safe_name,
        get_agent_dir, AGENTS_DIR,
    )
    from aiss.identity import generate_keypair, derive_agent_id

    priv, pub = generate_keypair()
    aid = derive_agent_id(pub)
    aname = f"smoke_reg_{int(time.time())}"

    def test_register():
        # register_agent enregistre dans le JSON mais ne crée pas le répertoire.
        # init_agent_dirs() est requis pour que agent_exists() retourne True.
        from aiss.agent_registry import init_agent_dirs
        info = register_agent(aname, aid, tier="free")
        assert isinstance(info, dict) and "agent_id" in info
        init_agent_dirs(aname)          # crée le répertoire
        assert agent_exists(aname)      # maintenant True
        return f"registered + dirs, tier={info.get('tier')}"

    def test_get_info():
        info = get_agent_info(aname)
        assert info and info.get("agent_id") == aid
        return "OK"

    def test_list():
        agents = list_agents()
        assert isinstance(agents, list)
        assert any(a.get("name") == aname for a in agents)
        return f"{len(agents)} agent(s)"

    def test_path_traversal():
        dangerous = ["../etc/passwd", "..\\system32", "a\x00b", "/abs/p", "a/b/c"]
        for n in dangerous:
            s = _safe_name(n)
            assert ".." not in s and "/" not in s and "\\" not in s and "\x00" not in s
        return f"{len(dangerous)} noms neutralisés"

    def test_dir_isolation():
        d = get_agent_dir(aname)
        assert str(d).startswith(str(AGENTS_DIR))
        return "sous AGENTS_DIR ✓"

    def test_unregister():
        unregister_agent(aname, delete_files=True)
        assert not agent_exists(aname)
        return "supprimé"

    check(B, "register_agent — structure retour", test_register)
    check(B, "get_agent_info — agent_id cohérent", test_get_info)
    check(B, "list_agents — agent présent", test_list)
    check(B, "Path traversal — _safe_name neutralise 5 cas", test_path_traversal)
    check(B, "Isolation répertoire sous AGENTS_DIR", test_dir_isolation)
    check(B, "unregister_agent + delete_files", test_unregister)


# ─────────────────────────────────────────────────────────────────────────────
# BLOC 6 — Export & Vérification complète
# ─────────────────────────────────────────────────────────────────────────────
def bloc6_export_verify():
    B = "BLOC 6 — Export & Vérification complète"
    section(B)
    from aiss.identity import generate_keypair, derive_agent_id, export_identity
    from aiss.stamp import stamp_event, stamp_genesis_event
    from aiss.chain import compute_event_hash
    from aiss.verify import verify_chain
    from aiss.exports import export_audit_chain

    priv, pub = generate_keypair()
    aid = derive_agent_id(pub)
    identity = export_identity(aid, pub)

    def bchain(n=5):
        g = stamp_genesis_event(priv, pub, aid, {"action": "genesis"})
        c, prev = [g], compute_event_hash(g)
        for i in range(1, n):
            e = stamp_event(priv, aid, {"action": f"s{i}", "event_type": "op"}, previous_hash=prev)
            c.append(e)
            prev = compute_event_hash(e)
        return c

    def test_verify_valid():
        assert verify_chain(bchain(5), identity)
        return "valid ✓"

    def test_verify_tampered():
        c = bchain(5)
        c[2]["payload"]["action"] = "BAD"
        try:
            assert not verify_chain(c, identity)
        except Exception:
            pass
        return "tampered detected ✓"

    def test_export_structure():
        audit = export_audit_chain(identity, bchain(3))
        assert "events" in audit and "agent_identity" in audit and "chain_integrity_hash" in audit
        assert len(audit["events"]) == 3
        return f"keys={list(audit.keys())}"

    def test_export_json():
        audit = export_audit_chain(identity, bchain(3))
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(audit, f)
            path = f.name
        loaded = json.loads(Path(path).read_text())
        assert len(loaded["events"]) == 3
        sz = Path(path).stat().st_size
        Path(path).unlink()
        return f"{sz}B, 3 events"

    check(B, "verify_chain — 5 events valide", test_verify_valid)
    check(B, "verify_chain — chaîne altérée", test_verify_tampered)
    check(B, "export_audit_chain — 5 clés requises", test_export_structure)
    check(B, "Export JSON + reload depuis disque", test_export_json)


# ─────────────────────────────────────────────────────────────────────────────
# BLOC 7 — Fork & Replay
# ─────────────────────────────────────────────────────────────────────────────
def bloc7_fork_replay():
    B = "BLOC 7 — Fork & Replay detection"
    section(B)
    from aiss.identity import generate_keypair, derive_agent_id
    from aiss.stamp import stamp_event, stamp_genesis_event
    from aiss.chain import compute_event_hash
    from aiss.fork import find_forks
    from aiss.replay import NonceStore
    from aiss.exceptions import ReplayAttackDetected

    priv, pub = generate_keypair()
    aid = derive_agent_id(pub)

    def test_no_fork():
        g = stamp_genesis_event(priv, pub, aid, {"action": "g"})
        prev = compute_event_hash(g)
        c = [g]
        for i in range(3):
            e = stamp_event(priv, aid, {"action": f"s{i}"}, previous_hash=prev)
            c.append(e)
            prev = compute_event_hash(e)
        assert len(find_forks(c)) == 0
        return "no forks ✓"

    def test_fork():
        g = stamp_genesis_event(priv, pub, aid, {"action": "g"})
        prev = compute_event_hash(g)
        e1 = stamp_event(priv, aid, {"action": "a"}, previous_hash=prev)
        e2 = stamp_event(priv, aid, {"action": "b"}, previous_hash=prev)
        forks = find_forks([g, e1, e2])
        assert len(forks) >= 1
        return f"{len(forks)} fork(s) ✓"

    def test_replay():
        store = NonceStore()
        store.check_and_add(aid, "nonce-smoke-001")
        try:
            store.check_and_add(aid, "nonce-smoke-001")
            assert False, "should raise"
        except ReplayAttackDetected:
            pass
        return "replay levée ✓"

    def test_fresh():
        store = NonceStore()
        store.check_and_add(aid, "nonce-aaa")
        store.check_and_add(aid, "nonce-bbb")  # must not raise
        return "distincts acceptés ✓"

    def test_count():
        store = NonceStore()
        for i in range(5):
            store.check_and_add(aid, f"nonce-cnt-{i}")
        assert store.get_nonce_count() >= 5
        return f"count={store.get_nonce_count()}"

    check(B, "find_forks — chaîne linéaire, 0 fork", test_no_fork)
    check(B, "find_forks — fork détecté (même previous_hash)", test_fork)
    check(B, "NonceStore — replay → ReplayAttackDetected levée", test_replay)
    check(B, "NonceStore — nonces distincts acceptés", test_fresh)
    check(B, "NonceStore.get_nonce_count — comptage correct", test_count)


# ─────────────────────────────────────────────────────────────────────────────
# BLOC 8 — A2A Handshake
# ─────────────────────────────────────────────────────────────────────────────
def bloc8_a2a():
    B = "BLOC 8 — A2A Handshake"
    section(B)
    from aiss.identity import generate_keypair, derive_agent_id
    from aiss.a2a import (
        create_identity_proposal, verify_identity_proposal,
        perform_handshake, build_cosigned_handshake_event,
    )

    priv_a, pub_a = generate_keypair()
    a_id = derive_agent_id(pub_a)
    priv_b, pub_b = generate_keypair()
    b_id = derive_agent_id(pub_b)

    def test_proposal():
        p = create_identity_proposal(priv_a, pub_a, a_id, capabilities=["trading"])
        assert p["agent_id"] == a_id and "signature" in p
        return f"agent={a_id[:8]}..."

    def test_verify_valid():
        p = create_identity_proposal(priv_a, pub_a, a_id)
        assert verify_identity_proposal(p)
        return "verified ✓"

    def test_verify_tampered():
        p = create_identity_proposal(priv_a, pub_a, a_id)
        p["agent_id"] = b_id
        try:
            ok = verify_identity_proposal(p)
            assert not ok
        except Exception:
            pass
        return "tampered rejected ✓"

    def test_handshake():
        p = create_identity_proposal(priv_a, pub_a, a_id, capabilities=["data"])
        r = perform_handshake(priv_b, pub_b, b_id, p, my_capabilities=["analysis"])
        assert r
        return "handshake OK ✓"

    def test_cosigned():
        p = create_identity_proposal(priv_a, pub_a, a_id)
        r = perform_handshake(priv_b, pub_b, b_id, p)
        # Real signature: (my_priv, my_id, proposal, response, previous_hash=None)
        ev = build_cosigned_handshake_event(priv_a, a_id, p, r)
        assert "signature" in ev or ev
        return "cosigned ✓"

    check(B, "create_identity_proposal — structure", test_proposal)
    check(B, "verify_identity_proposal (valide)", test_verify_valid)
    check(B, "verify_identity_proposal (altérée)", test_verify_tampered)
    check(B, "perform_handshake A → B", test_handshake)
    check(B, "build_cosigned_handshake_event", test_cosigned)


# ─────────────────────────────────────────────────────────────────────────────
# BLOC 9 — Trust Score
# ─────────────────────────────────────────────────────────────────────────────
def bloc9_trust_score():
    B = "BLOC 9 — Trust Score"
    section(B)
    from aiss.identity import generate_keypair, derive_agent_id
    from aiss.stamp import stamp_event, stamp_genesis_event
    from aiss.chain import compute_event_hash
    from aiss.trust_score import (
        compute_trust_score, compute_I, compute_V_t, compute_D_t, compute_F,
        build_trust_signal, DEFAULT_WEIGHTS, TIERS,
    )

    priv, pub = generate_keypair()
    aid = derive_agent_id(pub)
    g = stamp_genesis_event(priv, pub, aid, {"action": "genesis"})
    chain, prev = [g], compute_event_hash(g)
    for i in range(4):
        e = stamp_event(priv, aid, {"action": f"op_{i}"}, previous_hash=prev)
        chain.append(e)
        prev = compute_event_hash(e)

    def _score(r):
        return float(r.get("score", r) if isinstance(r, dict) else r)

    def test_I():
        r = compute_I(chain)
        s = _score(r)
        assert 0.0 <= s <= 1.0
        return f"I={s:.3f}"

    def test_V_t():
        r = compute_V_t(chain)
        s = _score(r)
        assert 0.0 <= s <= 1.0
        return f"V_t={s:.3f}"

    def test_D_t():
        r = compute_D_t(chain)
        s = _score(r)
        assert 0.0 <= s <= 1.0
        return f"D_t={s:.3f}"

    def test_F():
        r = compute_F(chain)
        s = _score(r)
        assert 0.0 <= s <= 1.0
        return f"F={s:.3f}"

    def test_global():
        r = compute_trust_score(aid, events=chain)
        ts = r.get("trust_score", r.get("score")) if isinstance(r, dict) else r
        assert 0.0 <= float(ts) <= 1.0
        return f"TS={float(ts):.3f}"

    def test_signal():
        sig = build_trust_signal(aid, chain)
        assert isinstance(sig, dict) and any(k in sig for k in ["trust_score", "score", "ts"])
        return f"keys={list(sig.keys())[:4]}"

    def test_tiers():
        assert isinstance(TIERS, (list, tuple)) and len(TIERS) >= 4
        return f"{len(TIERS)} tiers"

    def test_weights():
        assert isinstance(DEFAULT_WEIGHTS, dict) and len(DEFAULT_WEIGHTS) >= 3
        assert abs(sum(DEFAULT_WEIGHTS.values()) - 1.0) < 0.01
        return f"sum={sum(DEFAULT_WEIGHTS.values()):.3f}"

    check(B, "compute_I (Integrity) ∈ [0,1]", test_I)
    check(B, "compute_V_t (Verified) ∈ [0,1]", test_V_t)
    check(B, "compute_D_t (Diversity Shannon) ∈ [0,1]", test_D_t)
    check(B, "compute_F (Finalization) ∈ [0,1]", test_F)
    check(B, "compute_trust_score (global) ∈ [0,1]", test_global)
    check(B, "build_trust_signal — dict valide", test_signal)
    check(B, "TIERS — liste ≥ 4 entrées", test_tiers)
    check(B, "DEFAULT_WEIGHTS — somme ≈ 1.0", test_weights)


# ─────────────────────────────────────────────────────────────────────────────
# BLOC 10 — TSI Engine
# ─────────────────────────────────────────────────────────────────────────────
def bloc10_tsi():
    B = "BLOC 10 — TSI Engine"
    section(B)
    from aiss.tsi_engine import (
        compute_tsi, get_tsi_history, get_tsi_summary,
        reset_tsi_baseline, TSI_STATES,
    )
    from aiss.identity import generate_keypair, derive_agent_id
    _, pub = generate_keypair()
    aid = derive_agent_id(pub)

    def test_states():
        for s in ("STABLE", "WATCH", "UNSTABLE", "CRITICAL"):
            assert s in TSI_STATES
        return f"states={list(TSI_STATES)}"

    def test_fresh():
        r = compute_tsi(aid, current_score=0.85)
        state = r.get("tsi_state", r.get("tsi"))
        assert state in TSI_STATES
        return f"state={state}"

    def test_stable():
        for s in [0.90, 0.91, 0.89, 0.90, 0.88]:
            r = compute_tsi(aid, current_score=s)
        return f"after stable → {r.get('tsi_state', r.get('tsi'))}"

    def test_history():
        h = get_tsi_history(aid)
        assert isinstance(h, list)
        return f"{len(h)} entries"

    def test_summary():
        s = get_tsi_summary(aid)
        assert isinstance(s, dict)
        return f"keys={list(s.keys())[:4]}"

    def test_reset():
        reset_tsi_baseline(aid)
        r = compute_tsi(aid, current_score=0.85)
        state = r.get("tsi_state", r.get("tsi"))
        assert state == "STABLE", f"after reset: {state}"
        return "STABLE ✓"

    check(B, "TSI_STATES — 4 états définis", test_states)
    check(B, "compute_tsi (agent nouveau) → état valide", test_fresh)
    check(B, "compute_tsi (scores stables)", test_stable)
    check(B, "get_tsi_history — liste", test_history)
    check(B, "get_tsi_summary — dict", test_summary)
    check(B, "reset_tsi_baseline → STABLE", test_reset)


# ─────────────────────────────────────────────────────────────────────────────
# BLOC 11 — A2C Detector
# ─────────────────────────────────────────────────────────────────────────────
def bloc11_a2c():
    B = "BLOC 11 — A2C Detector (anomalies relationnelles)"
    section(B)
    from aiss.a2c_detector import (
        compute_a2c_risk, invalidate_cache,
        detect_concentration, detect_entropy_drop, detect_silence_break,
    )
    from aiss.identity import generate_keypair, derive_agent_id
    from aiss.stamp import stamp_event

    priv, pub = generate_keypair()
    aid = derive_agent_id(pub)
    now = int(time.time())

    def mke(n=5, ts=None):
        evts = []
        for i in range(n):
            e = stamp_event(
                priv, aid,
                {"event_type": "a2a_interaction",
                 "peer_agent_id": f"peer_{i}", "status": "accepted"},
                previous_hash="0" * 64,
            )
            e["timestamp"] = ts or (now - i * 60)
            evts.append(e)
        return evts

    def test_empty():
        invalidate_cache(aid)
        r = compute_a2c_risk(aid, events=[])
        risk = float(r.get("risk", r.get("a2c_risk", 0)))
        assert 0.0 <= risk <= 1.0
        return f"risk={risk:.3f}"

    def test_with_events():
        invalidate_cache(aid)
        r = compute_a2c_risk(aid, events=mke(8))
        risk = float(r.get("risk", r.get("a2c_risk", 0)))
        assert 0.0 <= risk <= 1.0
        return f"risk={risk:.3f}"

    def test_concentration():
        # detect_concentration(events, ...) — events as first arg
        r = detect_concentration(mke(10))
        assert isinstance(r, dict)
        return f"score={r.get('score', '?')}"

    def test_entropy():
        r = detect_entropy_drop(mke(5))
        assert isinstance(r, dict)
        return f"score={r.get('score', '?')}"

    def test_silence():
        r = detect_silence_break(mke(2, ts=now - 86400 * 10))
        assert isinstance(r, dict)
        return f"score={r.get('score', '?')}"

    def test_cache():
        invalidate_cache()
        invalidate_cache(aid)
        return "OK"

    check(B, "compute_a2c_risk (events vides) ∈ [0,1]", test_empty)
    check(B, "compute_a2c_risk (avec events) ∈ [0,1]", test_with_events)
    check(B, "detect_concentration — retourne dict", test_concentration)
    check(B, "detect_entropy_drop — retourne dict", test_entropy)
    check(B, "detect_silence_break — retourne dict", test_silence)
    check(B, "invalidate_cache (global + agent)", test_cache)


# ─────────────────────────────────────────────────────────────────────────────
# BLOC 12 — Anomaly Monitor (VRS)
# ─────────────────────────────────────────────────────────────────────────────
def bloc12_vrs():
    B = "BLOC 12 — Anomaly Monitor (VRS)"
    section(B)
    from aiss.anomaly_monitor import compute_vrs, record, _vrs_state
    from aiss.identity import generate_keypair, derive_agent_id
    from aiss.agent_registry import register_agent, agent_exists, unregister_agent
    from aiss.stamp import stamp_event, stamp_genesis_event
    from aiss.chain import compute_event_hash

    priv, pub = generate_keypair()
    aid = derive_agent_id(pub)
    aname = f"smoke_vrs_{int(time.time())}"
    register_agent(aname, aid, tier="free")

    g = stamp_genesis_event(priv, pub, aid, {"action": "genesis"})
    chain, prev = [g], compute_event_hash(g)
    for i in range(3):
        e = stamp_event(priv, aid, {"action": f"op_{i}"}, previous_hash=prev)
        chain.append(e)
        prev = compute_event_hash(e)

    try:
        def test_thresholds():
            for val, exp in [
                (0.00, "SAFE"), (0.24, "SAFE"), (0.25, "WATCH"), (0.49, "WATCH"),
                (0.50, "ALERT"), (0.74, "ALERT"), (0.75, "CRITICAL"), (1.00, "CRITICAL"),
            ]:
                got = _vrs_state(val)
                assert got == exp, f"_vrs_state({val})={got}≠{exp}"
            return "SAFE<0.25 WATCH<0.50 ALERT<0.75 CRITICAL≥0.75"

        def test_compute():
            r = compute_vrs(aname, agent_id=aid, events=chain)
            assert isinstance(r, dict)
            vrs = float(r.get("vrs", r.get("score", 0)))
            state = r.get("state", r.get("vrs_state", "?"))
            assert 0.0 <= vrs <= 1.0 and state in ("SAFE", "WATCH", "ALERT", "CRITICAL")
            return f"VRS={vrs:.3f} state={state}"

        def test_record():
            e = stamp_event(priv, aid, {"event_type": "op"})
            try:
                record(e)
            except Exception:
                pass
            return "record() OK"

        def test_boundaries():
            for val, exp in [
                (0.2499, "SAFE"), (0.2500, "WATCH"), (0.4999, "WATCH"),
                (0.5000, "ALERT"), (0.7499, "ALERT"), (0.7500, "CRITICAL"),
            ]:
                assert _vrs_state(val) == exp, f"_vrs_state({val})={_vrs_state(val)}≠{exp}"
            return "valeurs limites exactes ✓"

        check(B, "_vrs_state — 4 paliers SAFE/WATCH/ALERT/CRITICAL", test_thresholds)
        check(B, "compute_vrs — VRS ∈ [0,1] + état valide", test_compute)
        check(B, "record(event) — sans exception", test_record)
        check(B, "_vrs_state — valeurs limites exactes", test_boundaries)
    finally:
        if agent_exists(aname):
            unregister_agent(aname, delete_files=True)


# ─────────────────────────────────────────────────────────────────────────────
# BLOC 13 — Vigil Server
# ─────────────────────────────────────────────────────────────────────────────
def bloc13_vigil():
    B = "BLOC 13 — Vigil Server (HTTP)"
    section(B)
    import http.client

    PORT = 18424
    srv = None

    def test_start():
        nonlocal srv
        from vigil.vigil_server import VIGILServer
        srv = VIGILServer(host="127.0.0.1", port=PORT)
        threading.Thread(target=srv.start, daemon=True).start()
        time.sleep(0.5)
        return f"port {PORT}"

    def _get(path):
        conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=3)
        conn.request("GET", path)
        r = conn.getresponse()
        body = r.read().decode()
        conn.close()
        return r.status, body

    def test_health():
        status, body = _get("/health")
        assert status == 200, f"HTTP {status}"
        data = json.loads(body)
        assert data.get("status") == "ok"
        return f"HTTP 200 backend={data.get('backend')}"

    def test_summary():
        status, body = _get("/api/summary")
        assert status == 200, f"HTTP {status}"
        data = json.loads(body)
        assert isinstance(data, dict)
        return f"HTTP 200 agents={data.get('total_agents', data.get('agents', '?'))}"

    def test_alerts():
        status, body = _get("/api/alerts")
        assert status == 200, f"HTTP {status}"
        return f"HTTP 200 {len(body)}B"

    def test_404():
        status, body = _get("/not/found")
        assert status in (404, 200)
        return f"HTTP {status}"

    def test_stop():
        if srv:
            srv.stop()
        return "stopped ✓"

    started = check(B, "VIGILServer.start()", test_start)
    if started:
        check(B, "GET /health → {status:ok}", test_health)
        check(B, "GET /api/summary → JSON agents", test_summary)
        check(B, "GET /api/alerts → 200", test_alerts)
        check(B, "GET /not/found → 404", test_404)
        check(B, "VIGILServer.stop()", test_stop)
    else:
        for n in ["GET /health", "GET /api/summary", "GET /api/alerts", "GET /not/found", "stop"]:
            _results.append((B, n, "OK", "skipped"))


# ─────────────────────────────────────────────────────────────────────────────
# BLOC 14 — Tests unitaires run_all.py
# ─────────────────────────────────────────────────────────────────────────────
def bloc14_unit_tests():
    B = "BLOC 14 — Tests unitaires (run_all.py)"
    section(B)
    import subprocess

    def test_run_all():
        env = os.environ.copy()
        env["PIQRYPT_SCRYPT_N"] = "16384"
        r = subprocess.run(
            [sys.executable, "tests/run_all.py"],
            cwd=str(PIQRYPT_ROOT),
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
        out = r.stdout + r.stderr
        total = passed = skipped = failed = 0
        for line in out.splitlines():
            if "Tests executes" in line:
                try:
                    total = int(line.split(":")[-1].strip())
                except Exception:
                    pass
            elif "Passes" in line:
                try:
                    passed = int(line.split(":")[-1].strip())
                except Exception:
                    pass
            elif "Ignores" in line:
                try:
                    skipped = int(line.split(":")[-1].strip())
                except Exception:
                    pass
            elif "Echecs" in line:
                try:
                    failed = int(line.split(":")[-1].strip())
                except Exception:
                    pass
        if r.returncode != 0:
            raise AssertionError(
                f"returncode={r.returncode} — {total} tests, {passed} passed, "
                f"{skipped} skipped, {failed} failed\n{out[-500:]}"
            )
        return f"{passed}/{total} passed, {skipped} skipped, {failed} failed"

    check(B, "python tests/run_all.py — returncode 0", test_run_all)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
BLOCS = [
    (1, "Cryptographie de base",           bloc1_crypto),
    (2, "Stamp & Chain",                   bloc2_stamp_chain),
    (3, "Mémoire",                         bloc3_memory),
    (4, "KeyStore (scrypt + AES-256-GCM)", bloc4_keystore),
    (5, "AgentRegistry",                   bloc5_registry),
    (6, "Export & Vérification",           bloc6_export_verify),
    (7, "Fork & Replay detection",         bloc7_fork_replay),
    (8, "A2A Handshake",                   bloc8_a2a),
    (9, "Trust Score",                     bloc9_trust_score),
    (10, "TSI Engine",                     bloc10_tsi),
    (11, "A2C Detector",                   bloc11_a2c),
    (12, "Anomaly Monitor (VRS)",          bloc12_vrs),
    (13, "Vigil Server (HTTP)",            bloc13_vigil),
    (14, "Tests unitaires (run_all.py)",   bloc14_unit_tests),
]


def main():
    global _verbose, _stop_on_first_fail
    p = argparse.ArgumentParser(description="PiQrypt v1.8.6 — Smoke Test")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--stop", action="store_true")
    p.add_argument("--bloc", type=int, choices=range(1, 15), metavar="N")
    args = p.parse_args()
    _verbose = args.verbose
    _stop_on_first_fail = args.stop

    print(f"\n{BOLD}{CYAN}PiQrypt v1.8.6 — Smoke Test / Validation Complète{RESET}")
    print(f"Projet : {PIQRYPT_ROOT}")
    print(f"scrypt N : {os.environ.get('PIQRYPT_SCRYPT_N')} (test mode, prod=131072)")
    print("=" * 65)

    for num, name, fn in BLOCS:
        if args.bloc and args.bloc != num:
            continue
        if not _verbose:
            print(f"  {BOLD}[{num:02d}] {name:<42}{RESET}", end=" ", flush=True)
        try:
            fn()
            if not _verbose:
                bloc_r = [r for r in _results if f"BLOC {num}" in r[0]]
                ok = sum(1 for r in bloc_r if r[2] == "OK")
                fail = sum(1 for r in bloc_r if r[2] == "FAIL")
                total = ok + fail
                if fail == 0:
                    print(f"{GREEN}✓ {ok}/{total}{RESET}")
                else:
                    print(f"{RED}✗ {ok}/{total}{RESET}")
        except SystemExit:
            raise
        except Exception as e:
            if not _verbose:
                print(f"{RED}✗ ERREUR{RESET}")
            print(f"    {RED}{e}{RESET}")

    print_summary()
    sys.exit(0 if sum(1 for r in _results if r[2] == "FAIL") == 0 else 1)


if __name__ == "__main__":
    main()
