# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests — vérificateur indépendant des vecteurs AISS-2.1.

Son verdict doit être identique à celui de la bibliothèque pour CHAQUE vecteur et conforme au
champ "valid" : c'est la garde contre « l'implémentation définit la spécification ». Tout écart
est un défaut à signaler, pas à masquer.
"""
import nacl.signing  # noqa: F401

import ast
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VECTORS_DIR = REPO_ROOT / "test_vectors_aiss21"
VERIFIER = VECTORS_DIR / "verify_standalone.py"
ALLOWED_IMPORTS = {"argparse", "base64", "binascii", "hashlib", "json", "os", "struct", "sys",
                   "base58", "rfc8785", "cryptography", "dilithium_py"}


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _deps_available():
    try:
        import base58, rfc8785, dilithium_py  # noqa: F401
        return True
    except ImportError:
        return False


def _pq_available():
    try:
        from aiss.crypto import dilithium
        return dilithium is not None and dilithium.is_available()
    except Exception:
        return False


class TestVerifierIsIndependent(unittest.TestCase):

    def test_only_allowed_imports(self):
        tree = ast.parse(VERIFIER.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        self.assertEqual(imported - ALLOWED_IMPORTS, set())
        self.assertFalse({"aiss", "piqrypt"} & imported)

    @pytest.mark.skipif(not _deps_available(), reason="base58 / rfc8785 / dilithium-py absents")
    def test_runs_with_aiss_and_piqrypt_imports_blocked(self):
        code = (
            "import sys, runpy; sys.modules['aiss'] = None; sys.modules['piqrypt'] = None; "
            f"sys.argv = ['verify_standalone.py', '--vectors', r'{VECTORS_DIR}']; "
            f"runpy.run_path(r'{VERIFIER}', run_name='__main__')"
        )
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-2000:])
        self.assertIn("vectors match", r.stdout)
        self.assertNotIn("MISMATCH", r.stdout)


@pytest.mark.skipif(not _deps_available(), reason="base58 / rfc8785 / dilithium-py absents")
class TestVerdictsAgree(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.standalone = _load(VERIFIER, "verify_standalone_under_test")
        cls.results = cls.standalone.all_verdicts(str(VECTORS_DIR))

    def test_standalone_verdict_matches_valid_field(self):
        bad = [k for k, (got, expected) in self.results.items() if got != expected]
        self.assertGreater(len(self.results), 50)
        self.assertEqual(bad, [])

    @pytest.mark.skipif(not _pq_available(), reason="ML-DSA-65 backend not installed")
    def test_standalone_verdict_equals_library_verdict_for_every_vector(self):
        vectors = _load(REPO_ROOT / "tests" / "test_vectors_aiss21.py", "vectors_lib_adapters")
        differences = []
        for name, adapter in vectors.ADAPTERS.items():
            for v in vectors.load(name)["vectors"]:
                lib = adapter(v)
                standalone = self.results[f"{name}:{v['id']}"][0]
                if lib != standalone:
                    differences.append(f"{name}:{v['id']} bibliothèque={lib} indépendant={standalone}")
        self.assertEqual(differences, [], "\n".join(differences))


if __name__ == "__main__":
    unittest.main()
