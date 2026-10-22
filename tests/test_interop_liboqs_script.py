# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests — scripts/interop_liboqs.py (logique du script) et workflow interop-liboqs.yml.

liboqs n'est pas installé ici : le module `oqs` est remplacé par un double écrit sur
dilithium-py. Ces tests valident la logique du script et la forme du workflow, PAS
l'interopérabilité réelle avec liboqs, qui n'a jamais été exercée.
"""
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "interop_liboqs.py"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "interop-liboqs.yml"
VECTORS_DIR = REPO_ROOT / "test_vectors_aiss21"


def _deps_available():
    try:
        import base58, rfc8785, dilithium_py  # noqa: F401
        return True
    except ImportError:
        return False


def _fake_oqs(sign_broken=False):
    from dilithium_py.ml_dsa import ML_DSA_65

    class Signature:
        def __init__(self, alg, secret_key=None):
            self.alg, self.secret_key = alg, secret_key

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def sign(self, message):
            sig = ML_DSA_65.sign(self.secret_key, message, ctx=b"", deterministic=False)
            return sig[:-1] + bytes([sig[-1] ^ 1]) if sign_broken else sig

        def verify(self, message, signature, public_key):
            return ML_DSA_65.verify(public_key, message, signature)

    module = types.ModuleType("oqs")
    module.Signature = Signature
    module.get_enabled_sig_mechanisms = lambda: ["ML-DSA-65"]
    module.oqs_python_version = lambda: "fake"
    module.oqs_version = lambda: "fake"
    return module


def _load_script(fake):
    with patch.dict(sys.modules, {"oqs": fake}):
        spec = importlib.util.spec_from_file_location("interop_liboqs_under_test", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(not _deps_available(), reason="base58 / rfc8785 / dilithium-py absents")
class TestInteropScriptLogic(unittest.TestCase):

    def test_passes_when_both_implementations_agree(self):
        module = _load_script(_fake_oqs())
        self.assertEqual(module.run(str(VECTORS_DIR)), [])

    def test_fails_when_the_other_implementation_disagrees(self):
        module = _load_script(_fake_oqs(sign_broken=True))
        failures = module.run(str(VECTORS_DIR))
        self.assertTrue(any("liboqs signs" in f for f in failures))

    def test_fails_when_the_algorithm_is_not_enabled(self):
        fake = _fake_oqs()
        fake.get_enabled_sig_mechanisms = lambda: ["ML-KEM-768"]
        module = _load_script(fake)
        self.assertEqual(len(module.run(str(VECTORS_DIR))), 1)


class TestWorkflowShape(unittest.TestCase):

    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_manual_trigger_only(self):
        on_block = self.text.split("\non:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("workflow_dispatch:", on_block)
        for trigger in ("push", "pull_request", "schedule"):
            self.assertNotIn(trigger, on_block)

    def test_versions_are_pinned_and_read_only(self):
        self.assertIn('LIBOQS_VERSION: "0.16.0"', self.text)
        self.assertIn('LIBOQS_PYTHON_VERSION: "0.16.0.1"', self.text)
        self.assertIn("contents: read", self.text)
        self.assertIn('--branch "${LIBOQS_VERSION}"', self.text)
        self.assertIn('--branch "${LIBOQS_PYTHON_VERSION}"', self.text)
        for floating in ("PYOQS_VERSION", "@main", "--branch main", "--branch master"):
            self.assertNotIn(floating, self.text)

    def test_clones_are_checked_against_the_pinned_commits(self):
        self.assertIn('LIBOQS_COMMIT: "5a1a854b0dc9f2141bdc771c555ee60c37950183"', self.text)
        self.assertIn('LIBOQS_PYTHON_COMMIT: "62385cd99ababa2a4875257232c68dccda256e3b"', self.text)
        self.assertEqual(self.text.count("rev-parse HEAD"), 2)
        self.assertIn('= "${LIBOQS_COMMIT}"', self.text)
        self.assertIn('= "${LIBOQS_PYTHON_COMMIT}"', self.text)
        self.assertEqual(self.text.count("exit 1"), 2)

    def test_python_dependencies_are_pinned_to_exact_versions(self):
        import re
        pip_lines = [l.strip() for l in self.text.splitlines() if l.strip().startswith(("pip install", "python -m pip install"))]
        self.assertGreaterEqual(len(pip_lines), 3)
        for line in pip_lines:
            self.assertNotRegex(line, r"[<>~]=?|--upgrade")
        joined = " ".join(pip_lines)
        for pin in ("pip==26.2.2", "cryptography==50.0.2", "rfc8785==0.1.4",
                    "base58==2.1.1", "dilithium-py==1.5.1"):
            self.assertIn(pin, joined)
        self.assertTrue(re.search(r"pip install \./liboqs-python", joined))

    def test_runs_the_interop_script(self):
        self.assertIn("python scripts/interop_liboqs.py", self.text)
        self.assertTrue(SCRIPT.exists())

    def test_no_other_workflow_mentions_it(self):
        for other in (REPO_ROOT / ".github" / "workflows").glob("*.yml"):
            if other.name != WORKFLOW.name:
                self.assertNotIn("interop_liboqs", other.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
