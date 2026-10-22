# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""Tests — `piqrypt identity rotate` : refus des identités portant une clé ML-DSA-65."""
import nacl.signing  # noqa: F401

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _cli(args, home):
    env = dict(os.environ)
    env.update({
        "USERPROFILE": str(home), "HOME": str(home),
        "PIQRYPT_HOME": str(Path(home) / ".piqrypt"),
        "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
    })
    return subprocess.run(
        [sys.executable, "-c", "import sys; from cli.main import main; sys.exit(main())"] + args,
        cwd=str(REPO_ROOT), env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120)


class TestIdentityRotateCli(unittest.TestCase):

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())

    def _classic_file(self):
        import aiss
        priv, pub = aiss.generate_keypair()
        doc = {"identity": aiss.export_identity(aiss.derive_agent_id(pub), pub),
               "private_key": aiss.crypto.ed25519.encode_base64(priv)}
        path = self.home / "old.json"
        path.write_text(json.dumps(doc))
        return path, doc

    def test_classic_rotation_still_works(self):
        path, _ = self._classic_file()
        out = self.home / "new.json"
        r = _cli(["identity", "rotate", str(path), str(out), "--output", str(out)], self.home)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        data = json.loads(out.read_text())
        self.assertIn("rotation_attestation", data)
        self.assertNotIn("public_key_pq", data["identity"])

    def test_identity_with_public_key_pq_is_refused(self):
        path, doc = self._classic_file()
        for label, variant in {
            "imbriquée": dict(doc, identity=dict(doc["identity"], public_key_pq="base64:AA==")),
            "à la racine": dict(doc, public_key_pq="base64:AA=="),
        }.items():
            with self.subTest(form=label):
                path.write_text(json.dumps(variant))
                out = self.home / f"new_{label[:3]}.json"
                r = _cli(["identity", "rotate", str(path), str(out), "--output", str(out)],
                         self.home)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("create_rotation_event_aiss21", r.stderr)
                self.assertIn("public_key_pq", r.stderr)
                self.assertFalse(out.exists())
                self.assertNotIn("Traceback", r.stderr)


if __name__ == "__main__":
    unittest.main()
