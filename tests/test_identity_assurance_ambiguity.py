# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""Tests — identity_binding_assurance rejette elle-même les documents ambigus."""
import nacl.signing  # noqa: F401

import copy
import tempfile
import unittest
from unittest.mock import patch

import pytest


def _pq_available():
    try:
        from aiss.crypto import dilithium
        return dilithium is not None and dilithium.is_available()
    except Exception:
        return False


@pytest.mark.skipif(not _pq_available(), reason="ML-DSA-65 backend not installed")
class TestAmbiguousIdentities(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        p = patch("aiss.key_store._SCRYPT_N", 2 ** 10)
        p.start()
        self.addCleanup(p.stop)
        from aiss.identity import create_agent_identity, upgrade_agent_identity
        self.native = create_agent_identity(
            "n", passphrase="correct horse battery", base_dir=self.tmp, hybrid=True)["identity"]
        create_agent_identity("u", passphrase="correct horse battery", base_dir=self.tmp)
        self.upgraded = upgrade_agent_identity(
            "u", "correct horse battery", "correct horse battery", base_dir=self.tmp)["identity"]

    def test_valid_forms_are_unchanged(self):
        from aiss.identity import identity_binding_assurance
        self.assertEqual(identity_binding_assurance(self.native), "hybrid")
        self.assertEqual(identity_binding_assurance(self.upgraded), "classical_only")

    def test_native_with_binding_is_rejected(self):
        from aiss.identity import IdentityBindingError, identity_binding_assurance
        doc = dict(copy.deepcopy(self.native), binding=copy.deepcopy(self.upgraded["binding"]))
        with self.assertRaises(IdentityBindingError) as ctx:
            identity_binding_assurance(doc)
        self.assertIn("ambiguë", str(ctx.exception))

    def test_native_with_public_key_is_rejected(self):
        from aiss.identity import IdentityBindingError, identity_binding_assurance
        doc = dict(copy.deepcopy(self.native), public_key=self.upgraded["public_key"])
        with self.assertRaises(IdentityBindingError):
            identity_binding_assurance(doc)

    def test_no_valid_flow_produces_an_ambiguous_document(self):
        from aiss.identity import export_identity_aiss21, load_agent_pq_key
        for doc in (self.native, self.upgraded):
            ambiguous = "public_key_classical" in doc and ("binding" in doc or "public_key" in doc)
            self.assertFalse(ambiguous)
        pq = load_agent_pq_key("n", "correct horse battery", base_dir=self.tmp)
        self.assertEqual(len(pq), 4032)
        exported = export_identity_aiss21(
            self.native["agent_id"],
            __import__("base64").b64decode(self.native["public_key_classical"][7:]),
            __import__("base64").b64decode(self.native["public_key_pq"][7:]))
        self.assertNotIn("binding", exported)
        self.assertNotIn("public_key", exported)


if __name__ == "__main__":
    unittest.main()
