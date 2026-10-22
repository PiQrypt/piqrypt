# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests — B.5 : mise à niveau d'une identité AISS-1 vers l'AISS-2.1 (liaison signée).

Aucune licence locale requise : la mise à niveau ne passe pas par le gating Pro ;
la signature d'événements hybrides (chaîne mixte) utilise la fixture de licence Pro
des autres tests. Stockage isolé dans des répertoires temporaires.
"""
# Doit précéder tests/test_license.py (voir tests/test_aiss2_ml_dsa.py).
import nacl.signing  # noqa: F401

import base64
import contextlib
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PASSPHRASE = "correct horse battery"
PQ_PASSPHRASE = "autre passphrase PQ"


def _pq_available():
    try:
        from aiss.crypto import dilithium
        return dilithium is not None and dilithium.is_available()
    except Exception:
        return False


_SKIP = not _pq_available()
_SKIP_REASON = "ML-DSA-65 backend not installed"


def _make_license(tier: str):
    from aiss.license import License, TIERS
    lic = License.__new__(License)
    lic._tier = tier
    lic._payload = {
        "tier": tier, "license_id": f"test_{tier}",
        "agents_max": TIERS[tier]["agents_max"],
        "events_month": TIERS[tier]["events_month"], "expires_at": None,
    }
    lic._loaded_at = 0.0
    return lic


@contextlib.contextmanager
def _fast_scrypt():
    with patch("aiss.key_store._SCRYPT_N", 2 ** 10):
        yield


def _flip_b64(value: str) -> str:
    """Change un octet d'un champ "base64:..." en conservant un encodage valide."""
    raw = bytearray(base64.b64decode(value[7:], validate=True))
    raw[0] ^= 0x01
    return "base64:" + base64.b64encode(bytes(raw)).decode("ascii")


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class _UpgradeBase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.base = Path(self.tmp)
        self._scrypt = _fast_scrypt()
        self._scrypt.__enter__()

    def tearDown(self):
        self._scrypt.__exit__(None, None, None)

    def _legacy(self, name="legacy", passphrase=PASSPHRASE):
        from aiss.identity import create_agent_identity
        r = create_agent_identity(name, passphrase=passphrase, base_dir=self.tmp)
        self.agent_dir = self.base / "agents" / name
        return r

    def _upgrade(self, name="legacy", passphrase=PQ_PASSPHRASE, old=PASSPHRASE):
        from aiss.identity import upgrade_agent_identity
        return upgrade_agent_identity(name, passphrase, old, base_dir=self.tmp)

    def _identity_on_disk(self):
        return json.loads((self.agent_dir / "identity.json").read_text())


class TestBindingValidity(_UpgradeBase):

    def test_upgrade_produces_valid_binding(self):
        from aiss.identity import verify_identity_binding, identity_binding_assurance
        legacy = self._legacy()
        original = (self.agent_dir / "identity.json").read_bytes()
        r = self._upgrade()

        self.assertEqual(r["agent_id"], legacy["agent_id"])
        self.assertEqual(r["binding_assurance"], "classical_only")
        doc = self._identity_on_disk()
        self.assertEqual(doc["agent_id"], legacy["agent_id"])
        self.assertEqual(doc["public_key"], legacy["identity"]["public_key"])
        self.assertEqual(doc["version"], "AISS-1.0")
        self.assertTrue(doc["public_key_pq"].startswith("base64:"))
        self.assertTrue(verify_identity_binding(doc))
        self.assertEqual(identity_binding_assurance(doc), "classical_only")
        self.assertEqual((self.agent_dir / "identity.pre-upgrade.json").read_bytes(), original)
        self.assertTrue((self.agent_dir / "private_pq.key.enc").exists())
        self.assertTrue((self.agent_dir / "private.key.enc").exists())

        binding = doc["binding"]
        self.assertEqual(binding["type"], "identity_binding")
        self.assertEqual(binding["version"], "AISS-2.1")
        self.assertEqual(binding["binding_assurance"], "classical_only")
        self.assertTrue(binding["public_key_classical"].startswith("base64:"))
        for alg in ("classical", "post_quantum"):
            self.assertTrue(binding["signatures"][alg]["signature"].startswith("base64:"))

    def test_upgrade_of_plaintext_ed25519_key(self):
        from aiss.identity import verify_identity_binding
        self._legacy("clair", passphrase=None)
        self.assertTrue((self.agent_dir / "private.key.json").exists())
        self._upgrade("clair", old=None)
        self.assertTrue(verify_identity_binding(self._identity_on_disk()))
        self.assertTrue((self.agent_dir / "private.key.json").exists())

    def test_pq_key_reloadable_and_matches_binding(self):
        from aiss.identity import load_agent_pq_key
        self._legacy()
        self._upgrade()
        priv_pq = load_agent_pq_key("legacy", PQ_PASSPHRASE, base_dir=self.tmp)
        self.assertEqual(len(priv_pq), 4032)

    def test_ed25519_storage_unchanged(self):
        self._legacy()
        before = (self.agent_dir / "private.key.enc").read_bytes()
        self._upgrade()
        self.assertEqual((self.agent_dir / "private.key.enc").read_bytes(), before)


class TestBindingTampering(_UpgradeBase):

    def setUp(self):
        super().setUp()
        self._legacy()
        self._upgrade()
        self.doc = self._identity_on_disk()

    def _tampered(self, mutate):
        doc = copy.deepcopy(self.doc)
        mutate(doc)
        return doc

    def test_each_signed_field_is_protected(self):
        from aiss.identity import verify_identity_binding
        for field, value in self.doc["binding"].items():
            if field == "signatures":
                continue
            if isinstance(value, int):
                new = value + 1
            elif isinstance(value, str) and value.startswith("base64:"):
                new = _flip_b64(value)
            else:
                new = value + "x"
            with self.subTest(field=field):
                doc = self._tampered(lambda d: d["binding"].__setitem__(field, new))
                self.assertFalse(verify_identity_binding(doc))

    def test_extra_signed_field_is_rejected(self):
        from aiss.identity import verify_identity_binding
        doc = self._tampered(lambda d: d["binding"].__setitem__("extra", 1))
        self.assertFalse(verify_identity_binding(doc))

    def test_each_signature_is_protected(self):
        from aiss.identity import verify_identity_binding
        for alg in ("classical", "post_quantum"):
            with self.subTest(signature=alg):
                def mutate(d, alg=alg):
                    sig = d["binding"]["signatures"][alg]
                    sig["signature"] = _flip_b64(sig["signature"])
                self.assertFalse(verify_identity_binding(self._tampered(mutate)))

    def test_only_one_signature_present_is_rejected(self):
        from aiss.identity import verify_identity_binding
        for missing in ("classical", "post_quantum"):
            with self.subTest(missing=missing):
                doc = self._tampered(lambda d: d["binding"]["signatures"].pop(missing))
                self.assertFalse(verify_identity_binding(doc))
        doc = self._tampered(lambda d: d["binding"].__setitem__("signatures", {}))
        self.assertFalse(verify_identity_binding(doc))
        doc = self._tampered(lambda d: d["binding"].pop("signatures"))
        self.assertFalse(verify_identity_binding(doc))
        doc = self._tampered(
            lambda d: d["binding"]["signatures"]["classical"].__setitem__("signature", ""))
        self.assertFalse(verify_identity_binding(doc))

    def test_identity_agent_id_different_from_binding(self):
        from aiss.identity import verify_identity_binding
        doc = self._tampered(lambda d: d.__setitem__("agent_id", "A" * 32))
        self.assertFalse(verify_identity_binding(doc))

    def test_historical_public_key_different_from_binding(self):
        import aiss
        from aiss.identity import verify_identity_binding
        _, other_pub = aiss.generate_keypair()
        other = aiss.crypto.ed25519.encode_base64(other_pub)
        doc = self._tampered(lambda d: d.__setitem__("public_key", other))
        self.assertFalse(verify_identity_binding(doc))

    def test_identity_public_key_pq_different_from_binding(self):
        from aiss.identity import verify_identity_binding
        doc = self._tampered(lambda d: d.__setitem__("public_key_pq", _flip_b64(d["public_key_pq"])))
        self.assertFalse(verify_identity_binding(doc))

    def test_missing_binding_or_garbage_returns_false_without_raising(self):
        from aiss.identity import verify_identity_binding
        doc = self._tampered(lambda d: d.pop("binding"))
        for bad in (doc, {}, None, [], "texte", {"binding": "x"}, {"binding": {}}):
            with self.subTest(bad=repr(bad)[:30]):
                self.assertFalse(verify_identity_binding(bad))

    def test_prefix_and_strict_base64_enforced(self):
        from aiss.identity import verify_identity_binding
        cases = {
            "prefix absent (classique)":
                lambda d: d["binding"].__setitem__(
                    "public_key_classical", d["binding"]["public_key_classical"][7:]),
            "prefix absent (pq)":
                lambda d: d["binding"].__setitem__(
                    "public_key_pq", d["binding"]["public_key_pq"][7:]),
            "prefix absent (signature)":
                lambda d: d["binding"]["signatures"]["classical"].__setitem__(
                    "signature", d["binding"]["signatures"]["classical"]["signature"][7:]),
            "caractères hors alphabet":
                lambda d: d["binding"].__setitem__("public_key_classical", "base64:!!!!"),
            "retour à la ligne injecté":
                lambda d: d["binding"]["signatures"]["post_quantum"].__setitem__(
                    "signature",
                    "base64:" + d["binding"]["signatures"]["post_quantum"]["signature"][7:12]
                    + "\n" + d["binding"]["signatures"]["post_quantum"]["signature"][12:]),
            "taille Ed25519 31":
                lambda d: d["binding"].__setitem__(
                    "public_key_classical", "base64:" + base64.b64encode(b"\x01" * 31).decode()),
            "taille ML-DSA 1951":
                lambda d: d["binding"].__setitem__(
                    "public_key_pq", "base64:" + base64.b64encode(b"\x01" * 1951).decode()),
        }
        for label, mutate in cases.items():
            with self.subTest(case=label):
                self.assertFalse(verify_identity_binding(self._tampered(mutate)))

    def test_binding_of_another_agent_is_rejected(self):
        from aiss.identity import verify_identity_binding
        self._legacy("autre")
        other_dir = self.agent_dir
        self._upgrade("autre")
        other_binding = json.loads((other_dir / "identity.json").read_text())["binding"]
        doc = self._tampered(lambda d: d.__setitem__("binding", other_binding))
        self.assertFalse(verify_identity_binding(doc))


class TestBindingWrongKeys(_UpgradeBase):

    def _keys(self):
        import aiss
        from aiss.crypto import dilithium
        priv_ed, pub_ed = aiss.generate_keypair()
        priv_pq, pub_pq = dilithium.generate_keypair()
        return priv_ed, pub_ed, priv_pq, pub_pq

    def _identity(self, pub_ed, binding):
        import aiss
        return {
            "version": "AISS-1.0",
            "agent_id": binding["agent_id"],
            "public_key": aiss.crypto.ed25519.encode_base64(pub_ed),
            "binding": binding,
        }

    def test_consistent_binding_is_valid(self):
        import aiss
        from aiss.identity import _create_identity_binding, verify_identity_binding
        priv_ed, pub_ed, priv_pq, pub_pq = self._keys()
        aid = aiss.derive_agent_id(pub_ed)
        binding = _create_identity_binding(aid, priv_ed, pub_ed, priv_pq, pub_pq)
        self.assertTrue(verify_identity_binding(self._identity(pub_ed, binding)))

    def test_wrong_ed25519_signing_key(self):
        import aiss
        from aiss.identity import _create_identity_binding, verify_identity_binding
        priv_ed, pub_ed, priv_pq, pub_pq = self._keys()
        other_priv_ed, _, _, _ = self._keys()
        aid = aiss.derive_agent_id(pub_ed)
        binding = _create_identity_binding(aid, other_priv_ed, pub_ed, priv_pq, pub_pq)
        self.assertFalse(verify_identity_binding(self._identity(pub_ed, binding)))

    def test_wrong_mldsa_signing_key(self):
        import aiss
        from aiss.identity import _create_identity_binding, verify_identity_binding
        priv_ed, pub_ed, priv_pq, pub_pq = self._keys()
        _, _, other_priv_pq, _ = self._keys()
        aid = aiss.derive_agent_id(pub_ed)
        binding = _create_identity_binding(aid, priv_ed, pub_ed, other_priv_pq, pub_pq)
        self.assertFalse(verify_identity_binding(self._identity(pub_ed, binding)))

    def test_attacker_cannot_bind_own_keys_to_victim_agent_id(self):
        import aiss
        from aiss.identity import _create_identity_binding, verify_identity_binding
        _, victim_pub, _, _ = self._keys()
        victim_id = aiss.derive_agent_id(victim_pub)
        priv_ed, pub_ed, priv_pq, pub_pq = self._keys()
        binding = _create_identity_binding(victim_id, priv_ed, pub_ed, priv_pq, pub_pq)
        self.assertFalse(verify_identity_binding(self._identity(pub_ed, binding)))

    def test_binding_domain_is_separated_from_events(self):
        import aiss
        from aiss.identity import _create_identity_binding, verify_identity_binding
        priv_ed, pub_ed, priv_pq, pub_pq = self._keys()
        aid = aiss.derive_agent_id(pub_ed)
        with patch("aiss.identity._BINDING_DOMAIN_PREFIX", b"PiQrypt-AISS-2.1\x00"):
            binding = _create_identity_binding(aid, priv_ed, pub_ed, priv_pq, pub_pq)
        self.assertFalse(verify_identity_binding(self._identity(pub_ed, binding)))

    def test_creation_rejects_wrong_key_sizes(self):
        import aiss
        from aiss.identity import _create_identity_binding
        priv_ed, pub_ed, priv_pq, pub_pq = self._keys()
        aid = aiss.derive_agent_id(pub_ed)
        with self.assertRaises(ValueError):
            _create_identity_binding(aid, priv_ed, pub_ed[:31], priv_pq, pub_pq)
        with self.assertRaises(ValueError):
            _create_identity_binding(aid, priv_ed, pub_ed, priv_pq, pub_pq[:1951])


class TestUpgradeRefusals(_UpgradeBase):

    def test_double_upgrade_refused(self):
        from aiss.identity import IdentityBindingError
        self._legacy()
        self._upgrade()
        snapshot = {p.name: p.read_bytes() for p in self.agent_dir.iterdir() if p.is_file()}
        with self.assertRaises(IdentityBindingError):
            self._upgrade()
        self.assertEqual(
            snapshot, {p.name: p.read_bytes() for p in self.agent_dir.iterdir() if p.is_file()})

    def test_native_hybrid_identity_refused(self):
        from aiss.identity import IdentityBindingError, create_agent_identity
        create_agent_identity("natif", passphrase=PASSPHRASE, base_dir=self.tmp, hybrid=True)
        with self.assertRaises(IdentityBindingError):
            self._upgrade("natif")

    def test_orphan_pq_key_refused_and_untouched(self):
        from aiss.identity import IdentityBindingError
        self._legacy()
        orphan = self.agent_dir / "private_pq.key.enc"
        orphan.write_bytes(b"inconnu")
        with self.assertRaises(IdentityBindingError):
            self._upgrade()
        self.assertEqual(orphan.read_bytes(), b"inconnu")
        self.assertNotIn("binding", self._identity_on_disk())

    def test_existing_backup_refused(self):
        from aiss.identity import IdentityBindingError
        self._legacy()
        (self.agent_dir / "identity.pre-upgrade.json").write_text("{}")
        with self.assertRaises(IdentityBindingError):
            self._upgrade()
        self.assertFalse((self.agent_dir / "private_pq.key.enc").exists())

    def test_passphrase_required_and_min_length(self):
        self._legacy()
        for bad in (None, "", "   ", "1234567"):
            with self.subTest(passphrase=bad):
                with self.assertRaises(ValueError):
                    self._upgrade(passphrase=bad)
        self.assertFalse((self.agent_dir / "private_pq.key.enc").exists())

    def test_encrypted_ed25519_key_needs_old_passphrase(self):
        from aiss.key_store import InvalidPassphraseError
        self._legacy()
        with self.assertRaises(ValueError):
            self._upgrade(old=None)
        with self.assertRaises(InvalidPassphraseError):
            self._upgrade(old="mauvaise passphrase")
        self.assertFalse((self.agent_dir / "private_pq.key.enc").exists())
        self.assertNotIn("binding", self._identity_on_disk())

    def test_unknown_agent(self):
        with self.assertRaises(FileNotFoundError):
            self._upgrade("inconnu")

    def test_key_not_matching_identity_refused(self):
        import aiss
        from aiss.identity import IdentityBindingError
        self._legacy()
        _, other_pub = aiss.generate_keypair()
        doc = self._identity_on_disk()
        doc["public_key"] = aiss.crypto.ed25519.encode_base64(other_pub)
        (self.agent_dir / "identity.json").write_text(json.dumps(doc))
        with self.assertRaises(IdentityBindingError):
            self._upgrade()
        self.assertFalse((self.agent_dir / "private_pq.key.enc").exists())


class TestUpgradeAtomicity(_UpgradeBase):

    def _assert_unchanged_and_usable(self, original):
        from aiss.key_store import load_encrypted_key
        import aiss
        from aiss.chain import compute_event_hash
        self.assertEqual((self.agent_dir / "identity.json").read_bytes(), original)
        self.assertEqual(
            sorted(p.name for p in self.agent_dir.iterdir()),
            ["identity.json", "private.key.enc"])
        priv = load_encrypted_key(self.agent_dir / "private.key.enc", PASSPHRASE)
        doc = self._identity_on_disk()
        e1 = aiss.stamp_event(priv, doc["agent_id"], {"a": 1})
        e2 = aiss.stamp_event(priv, doc["agent_id"], {"a": 2},
                              previous_hash=compute_event_hash(e1))
        self.assertTrue(aiss.verify_chain([e1, e2], doc))

    def test_crash_between_pq_key_and_identity_json(self):
        self._legacy()
        original = (self.agent_dir / "identity.json").read_bytes()
        with patch("aiss.identity._atomic_write_json", side_effect=OSError("plantage")):
            with self.assertRaises(OSError):
                self._upgrade()
        self._assert_unchanged_and_usable(original)

    def test_crash_while_writing_backup(self):
        self._legacy()
        original = (self.agent_dir / "identity.json").read_bytes()
        with patch("aiss.identity._atomic_write_bytes", side_effect=OSError("plantage")):
            with self.assertRaises(OSError):
                self._upgrade()
        self._assert_unchanged_and_usable(original)

    def test_crash_while_writing_pq_key(self):
        self._legacy()
        original = (self.agent_dir / "identity.json").read_bytes()
        with patch("aiss.key_store.save_encrypted_pq_key", side_effect=OSError("plantage")):
            with self.assertRaises(OSError):
                self._upgrade()
        self._assert_unchanged_and_usable(original)

    def test_retry_after_crash_succeeds(self):
        from aiss.identity import verify_identity_binding
        self._legacy()
        with patch("aiss.identity._atomic_write_json", side_effect=OSError("plantage")):
            with self.assertRaises(OSError):
                self._upgrade()
        self._upgrade()
        self.assertTrue(verify_identity_binding(self._identity_on_disk()))


class TestChainsAfterUpgrade(_UpgradeBase):

    def _legacy_chain(self, n=3):
        import aiss
        from aiss.key_store import load_encrypted_key
        from aiss.chain import compute_event_hash
        r = self._legacy()
        priv = load_encrypted_key(self.agent_dir / "private.key.enc", PASSPHRASE)
        events, prev = [], None
        for i in range(n):
            ev = aiss.stamp_event(priv, r["agent_id"], {"seq": i}, previous_hash=prev)
            events.append(ev)
            prev = compute_event_hash(ev)
        return r, priv, events

    def test_existing_aiss1_chain_still_verifies(self):
        import aiss
        r, _, events = self._legacy_chain()
        self.assertTrue(aiss.verify_chain(events, r["identity"]))
        self._upgrade()
        self.assertTrue(aiss.verify_chain(events, self._identity_on_disk()))

    def test_mixed_chain_aiss1_then_aiss21_verifies(self):
        import aiss
        import aiss.license as lic_module
        from aiss.chain import compute_event_hash
        from aiss.identity import load_agent_pq_key
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid

        r, priv_ed, events = self._legacy_chain(2)
        self._upgrade()
        doc = self._identity_on_disk()
        priv_pq = load_agent_pq_key("legacy", PQ_PASSPHRASE, base_dir=self.tmp)
        pub_pq = base64.b64decode(doc["public_key_pq"][7:], validate=True)

        orig = lic_module._license
        lic_module._license = _make_license("pro")
        try:
            e3 = stamp_event_aiss2_hybrid(
                priv_ed, priv_pq, r["agent_id"], {"seq": 2},
                previous_hash=compute_event_hash(events[-1]), tsa_stamp_after=False)
            e4 = stamp_event_aiss2_hybrid(
                priv_ed, priv_pq, r["agent_id"], {"seq": 3},
                previous_hash=compute_event_hash(e3), tsa_stamp_after=False)
        finally:
            lic_module._license = orig

        self.assertEqual(len(e3["previous_hash"]), 64)   # SHA-256 de l'événement AISS-1
        self.assertEqual(len(e4["previous_hash"]), 128)  # SHA-512 de l'événement AISS-2.1
        self.assertTrue(aiss.verify_chain(events + [e3, e4], doc, public_key_pq=pub_pq))


class TestBindingAssurance(_UpgradeBase):

    def test_hybrid_native(self):
        from aiss.identity import create_agent_identity, identity_binding_assurance
        r = create_agent_identity("natif", passphrase=PASSPHRASE, base_dir=self.tmp, hybrid=True)
        self.assertEqual(identity_binding_assurance(r["identity"]), "hybrid")

    def test_hybrid_native_with_wrong_agent_id_raises(self):
        from aiss.identity import (
            IdentityBindingError, create_agent_identity, identity_binding_assurance)
        r = create_agent_identity("natif", passphrase=PASSPHRASE, base_dir=self.tmp, hybrid=True)
        doc = dict(r["identity"], agent_id="B" * 32)
        with self.assertRaises(IdentityBindingError):
            identity_binding_assurance(doc)

    def test_classical_only_after_upgrade(self):
        from aiss.identity import identity_binding_assurance
        self._legacy()
        self._upgrade()
        self.assertEqual(identity_binding_assurance(self._identity_on_disk()), "classical_only")

    def test_pure_aiss1_identity_raises(self):
        from aiss.identity import IdentityBindingError, identity_binding_assurance
        r = self._legacy()
        with self.assertRaises(IdentityBindingError):
            identity_binding_assurance(r["identity"])

    def test_tampered_binding_raises(self):
        from aiss.identity import IdentityBindingError, identity_binding_assurance
        self._legacy()
        self._upgrade()
        doc = self._identity_on_disk()
        doc["binding"]["created_at"] += 1
        with self.assertRaises(IdentityBindingError):
            identity_binding_assurance(doc)

    def test_declared_assurance_is_never_trusted(self):
        from aiss.identity import IdentityBindingError, identity_binding_assurance
        r = self._legacy()
        for claimed in ("hybrid", "classical_only"):
            doc = dict(r["identity"], binding_assurance=claimed)
            with self.subTest(claimed=claimed):
                with self.assertRaises(IdentityBindingError):
                    identity_binding_assurance(doc)

    def test_garbage_raises(self):
        from aiss.identity import IdentityBindingError, identity_binding_assurance
        for bad in (None, [], "x", {}):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(IdentityBindingError):
                    identity_binding_assurance(bad)


def _cli_env(home: Path, **extra):
    env = dict(os.environ)
    for var in ("PIQRYPT_LICENSE_KEY", "AISS2_LICENSE_KEY", "PIQRYPT_PASSPHRASE",
                "PIQRYPT_AGENT_NAME"):
        env.pop(var, None)
    env.update({
        "USERPROFILE": str(home), "HOME": str(home),
        "PIQRYPT_HOME": str(home / ".piqrypt"),
        "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
    })
    env.update(extra)
    return env


def _cli(args, home, **extra_env):
    return subprocess.run(
        [sys.executable, "-m", "cli.main"] + args,
        cwd=str(REPO_ROOT), env=_cli_env(home, **extra_env),
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180,
    )


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestUpgradeCLI(unittest.TestCase):

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.agent_dir = self.home / ".piqrypt" / "agents" / "clilegacy"

    def _create_legacy(self):
        r = _cli(["identity", "create", "--non-interactive", "--name", "clilegacy"],
                 self.home, PIQRYPT_PASSPHRASE=PASSPHRASE)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_upgrade_non_interactive_then_second_upgrade_refused(self):
        from aiss.identity import verify_identity_binding
        self._create_legacy()
        agent_id = json.loads((self.agent_dir / "identity.json").read_text())["agent_id"]

        r = _cli(["identity", "upgrade", "--name", "clilegacy", "--non-interactive"],
                 self.home, PIQRYPT_PASSPHRASE=PASSPHRASE)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        doc = json.loads((self.agent_dir / "identity.json").read_text())
        self.assertEqual(doc["agent_id"], agent_id)
        self.assertTrue(verify_identity_binding(doc))
        self.assertTrue((self.agent_dir / "private_pq.key.enc").exists())
        self.assertTrue((self.agent_dir / "identity.pre-upgrade.json").exists())

        again = _cli(["identity", "upgrade", "--name", "clilegacy", "--non-interactive"],
                     self.home, PIQRYPT_PASSPHRASE=PASSPHRASE)
        self.assertNotEqual(again.returncode, 0)
        self.assertEqual(json.loads((self.agent_dir / "identity.json").read_text()), doc)

        # Conséquence assumée du garde-fou : cmd_stamp refuse désormais cette identité.
        stamp = _cli(["stamp", str(self.agent_dir / "identity.json"), "--payload", '{"a": 1}'],
                     self.home)
        self.assertNotEqual(stamp.returncode, 0)

    def test_upgrade_requires_passphrase_in_non_interactive(self):
        self._create_legacy()
        r = _cli(["identity", "upgrade", "--name", "clilegacy", "--non-interactive"], self.home)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("binding", json.loads((self.agent_dir / "identity.json").read_text()))

    def test_upgrade_unknown_agent_fails(self):
        r = _cli(["identity", "upgrade", "--name", "fantome", "--non-interactive"],
                 self.home, PIQRYPT_PASSPHRASE=PASSPHRASE)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
