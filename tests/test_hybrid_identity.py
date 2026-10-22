# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests — B.1 : création d'identité hybride AISS-2.1 (Ed25519 + ML-DSA-65).

Aucune licence locale requise : la création ne passe pas par le gating Pro ;
la signature d'un événement hybride utilise la fixture de licence Pro des autres
tests (sans secret). Le stockage est isolé dans des répertoires temporaires.
"""
# Doit précéder tests/test_license.py (voir tests/test_aiss2_ml_dsa.py).
import nacl.signing  # noqa: F401

import base64
import contextlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PASSPHRASE = "correct horse battery"


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


def _b64(field: str) -> bytes:
    assert field.startswith("base64:")
    return base64.b64decode(field[7:], validate=True)


@contextlib.contextmanager
def _fast_scrypt():
    """N=2^10 pour les clés v1 et v2 : mêmes chemins de code, tests rapides."""
    with patch("aiss.key_store._SCRYPT_N", 2 ** 10):
        yield


@contextlib.contextmanager
def _isolated_registry(root: Path):
    """Redirige le registre et les dossiers d'agents vers `root`."""
    import aiss.agent_registry as reg
    with patch.object(reg, "PIQRYPT_DIR", root / ".piqrypt"), \
            patch.object(reg, "AGENTS_DIR", root / ".piqrypt" / "agents"), \
            patch.object(reg, "REGISTRY_FILE", root / ".piqrypt" / "registry.json"):
        yield reg


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestCreateHybridIdentity(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.base = Path(self.tmp)
        self._scrypt = _fast_scrypt()
        self._scrypt.__enter__()

    def tearDown(self):
        self._scrypt.__exit__(None, None, None)

    def _create(self, name="hyb", passphrase=PASSPHRASE, **kw):
        from aiss.identity import create_agent_identity
        return create_agent_identity(
            agent_name=name, passphrase=passphrase, base_dir=self.tmp, hybrid=True, **kw
        )

    def test_creation(self):
        from aiss.identity import derive_agent_id_aiss21
        r = self._create()
        self.assertTrue(r["hybrid"])
        self.assertTrue(r["encrypted"])
        for key in ("agent_name", "agent_id", "identity", "key_path", "tier", "created_at"):
            self.assertIn(key, r)
        agent_dir = self.base / "agents" / "hyb"
        self.assertEqual(Path(r["key_path"]), agent_dir / "private.key.enc")
        self.assertEqual(Path(r["pq_key_path"]), agent_dir / "private_pq.key.enc")
        doc = json.loads((agent_dir / "identity.json").read_text())
        self.assertEqual(doc["version"], "AISS-2.1")
        self.assertEqual(doc["agent_id"], r["agent_id"])
        self.assertEqual(
            r["agent_id"], derive_agent_id_aiss21(_b64(doc["public_key_classical"]),
                                                  _b64(doc["public_key_pq"])))
        self.assertEqual(len(_b64(doc["public_key_pq"])), 1952)
        self.assertEqual(sorted(p.name for p in agent_dir.iterdir()),
                         ["identity.json", "private.key.enc", "private_pq.key.enc"])

    def test_reload_both_keys_and_hybrid_signature(self):
        from aiss.key_store import load_encrypted_key
        from aiss.identity import load_agent_pq_key
        from aiss.stamp_aiss2 import stamp_genesis_event_aiss2_hybrid, verify_aiss2_hybrid
        import aiss.license as lic_module
        r = self._create()
        doc = r["identity"]
        priv_ed = load_encrypted_key(Path(r["key_path"]), PASSPHRASE)
        priv_pq = load_agent_pq_key("hyb", PASSPHRASE, base_dir=self.tmp)
        self.assertEqual(len(priv_ed), 32)
        self.assertEqual(len(priv_pq), 4032)
        pub_ed, pub_pq = _b64(doc["public_key_classical"]), _b64(doc["public_key_pq"])

        orig = lic_module._license
        lic_module._license = _make_license("pro")
        try:
            event = stamp_genesis_event_aiss2_hybrid(
                priv_ed, priv_pq, pub_ed, r["agent_id"], {"action": "genesis_b1"},
                public_key_pq=pub_pq, tsa_stamp_after=False,
            )
            self.assertTrue(verify_aiss2_hybrid(event, pub_ed, pub_pq))
        finally:
            lic_module._license = orig

    def test_wrong_passphrase_on_reload(self):
        from aiss.identity import load_agent_pq_key
        from aiss.key_store import InvalidPassphraseError
        self._create()
        with self.assertRaises(InvalidPassphraseError):
            load_agent_pq_key("hyb", "mauvaise passphrase", base_dir=self.tmp)

    def test_two_keys_have_distinct_salts(self):
        r = self._create()
        v1 = Path(r["key_path"]).read_bytes()
        v2 = Path(r["pq_key_path"]).read_bytes()
        self.assertNotEqual(v1[5:37], v2[10:26])  # sel v1 (32 o) vs sel v2 (16 o)

    def test_passphrase_required_and_min_length(self):
        for bad in (None, "", "   ", "1234567", 12345678):
            with self.subTest(passphrase=bad):
                with self.assertRaises(ValueError):
                    self._create(name="refuse", passphrase=bad)
                self.assertFalse((self.base / "agents" / "refuse").exists())

    def test_passphrase_of_exactly_8_characters_accepted(self):
        self.assertTrue(self._create(name="huit", passphrase="12345678")["hybrid"])

    def test_existing_agent_is_not_overwritten(self):
        r = self._create()
        before = Path(r["key_path"]).read_bytes()
        with self.assertRaises(FileExistsError):
            self._create()
        self.assertEqual(Path(r["key_path"]).read_bytes(), before)

    def test_cleanup_after_failure_writing_pq_key(self):
        with patch("aiss.key_store.save_encrypted_pq_key", side_effect=OSError("disque plein")):
            with self.assertRaises(OSError):
                self._create(name="echec")
        self.assertFalse((self.base / "agents" / "echec").exists())
        self.assertFalse((self.base / "agents").exists())

    def test_cleanup_after_failure_writing_identity_json(self):
        with patch("aiss.identity._atomic_write_json", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                self._create(name="echec2")
        self.assertFalse((self.base / "agents" / "echec2").exists())

    def test_cleanup_keeps_what_the_call_did_not_create(self):
        agent_dir = self.base / "agents" / "existant"
        agent_dir.mkdir(parents=True)
        (agent_dir / "notes.txt").write_text("à moi")
        with patch("aiss.key_store.save_encrypted_pq_key", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                self._create(name="existant")
        self.assertEqual([p.name for p in agent_dir.iterdir()], ["notes.txt"])

    def test_registry_registration_and_cleanup(self):
        from aiss.identity import create_agent_identity
        with _isolated_registry(self.base) as reg:
            r = create_agent_identity("reg", passphrase=PASSPHRASE, hybrid=True)
            self.assertEqual(reg.get_agent_info("reg")["agent_id"], r["agent_id"])
            self.assertTrue((reg.get_agent_dir("reg") / "private_pq.key.enc").exists())
            self.assertTrue((reg.get_agent_dir("reg") / "events" / "plain").is_dir())

            with patch("aiss.key_store.save_encrypted_pq_key", side_effect=OSError("boom")):
                with self.assertRaises(OSError):
                    create_agent_identity("reg2", passphrase=PASSPHRASE, hybrid=True)
            self.assertIsNone(reg.get_agent_info("reg2"))
            self.assertFalse(reg.get_agent_dir("reg2").exists())

    def test_non_regression_without_hybrid(self):
        from aiss.identity import create_agent_identity
        r = create_agent_identity("classique", passphrase=PASSPHRASE, base_dir=self.tmp)
        self.assertEqual(
            sorted(r), ["agent_id", "agent_name", "created_at", "encrypted",
                        "identity", "key_path", "tier"])
        self.assertNotIn("hybrid", r)
        self.assertNotIn("pq_key_path", r)
        self.assertIn("public_key", r["identity"])
        self.assertNotIn("public_key_pq", r["identity"])
        agent_dir = self.base / "agents" / "classique"
        self.assertFalse((agent_dir / "private_pq.key.enc").exists())
        self.assertEqual(len(r["agent_id"]), 32)


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
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
    )


@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestHybridCLI(unittest.TestCase):

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())

    def test_create_hybrid_non_interactive_then_stamp_is_refused(self):
        out = self.home / "agent.json"
        r = _cli(["identity", "create", "--hybrid", "--non-interactive",
                  "--name", "clihyb", "--output", str(out)],
                 self.home, PIQRYPT_PASSPHRASE=PASSPHRASE)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        agent_dir = self.home / ".piqrypt" / "agents" / "clihyb"
        self.assertTrue((agent_dir / "private.key.enc").exists())
        self.assertTrue((agent_dir / "private_pq.key.enc").exists())
        self.assertIn("public_key_pq", json.loads(out.read_text())["identity"])

        s = _cli(["stamp", str(out), "--payload", '{"a": 1}'], self.home)
        self.assertNotEqual(s.returncode, 0)
        self.assertIn("hybride", s.stderr)
        self.assertNotIn("Event stamped", s.stdout)

    def test_hybrid_non_interactive_requires_passphrase(self):
        r = _cli(["identity", "create", "--hybrid", "--non-interactive", "--name", "sanspp"],
                 self.home)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((self.home / ".piqrypt" / "agents" / "sanspp").exists())

    def test_hybrid_short_passphrase_refused(self):
        r = _cli(["identity", "create", "--hybrid", "--non-interactive", "--name", "court"],
                 self.home, PIQRYPT_PASSPHRASE="court")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((self.home / ".piqrypt" / "agents" / "court").exists())

    def test_create_without_flag_is_unchanged(self):
        r = _cli(["identity", "create", "--non-interactive", "--name", "classiquecli"],
                 self.home, PIQRYPT_PASSPHRASE="court")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        agent_dir = self.home / ".piqrypt" / "agents" / "classiquecli"
        self.assertTrue((agent_dir / "private.key.enc").exists())
        self.assertFalse((agent_dir / "private_pq.key.enc").exists())
        self.assertNotIn("public_key_pq", json.loads((agent_dir / "identity.json").read_text()))


class TestStampGuard(unittest.TestCase):
    """Garde-fou de cmd_stamp, indépendant du backend PQ (documents JSON seuls)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def _args(self, path):
        return Namespace(identity_file=str(path), payload='{"a": 1}',
                         previous_hash=None, output=None)

    def _run(self, doc):
        from cli.main import cmd_stamp
        path = self.tmp / "id.json"
        path.write_text(json.dumps(doc))
        with self.assertRaises(SystemExit) as ctx:
            cmd_stamp(self._args(path))
        return ctx.exception.code

    def test_refuses_identity_with_nested_public_key_pq(self):
        code = self._run({"identity": {"agent_id": "x", "public_key_pq": "base64:AA=="},
                          "private_key": "AAAA"})
        self.assertEqual(code, 1)

    def test_refuses_identity_with_top_level_public_key_pq(self):
        code = self._run({"agent_id": "x", "public_key_pq": "base64:AA==",
                          "private_key": "AAAA"})
        self.assertEqual(code, 1)

    def test_classic_identity_still_stamps(self):
        import aiss
        from cli.main import cmd_stamp
        priv, pub = aiss.generate_keypair()
        agent_id = aiss.derive_agent_id(pub)
        doc = {"identity": aiss.export_identity(agent_id, pub),
               "private_key": aiss.crypto.ed25519.encode_base64(priv)}
        path = self.tmp / "classic.json"
        path.write_text(json.dumps(doc))
        out = self.tmp / "event.json"
        args = self._args(path)
        args.output = str(out)
        cmd_stamp(args)
        event = json.loads(out.read_text())
        self.assertEqual(event["version"], "AISS-1.0")
        self.assertEqual(event["agent_id"], agent_id)


if __name__ == "__main__":
    unittest.main()
