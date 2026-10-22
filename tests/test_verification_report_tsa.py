# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""Tests — section "tsa" de get_verification_report (chantier C.3). Aucun accès réseau."""
import nacl.signing  # noqa: F401

import base64
import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

HERE = Path(__file__).resolve().parent
FIXTURE_DIR = HERE / "vectors_tsa"
ROOT_PEM = str(FIXTURE_DIR / "freetsa_cacert.pem")

try:
    import rfc3161_client  # noqa: F401
    HAS_LIB = True
except ImportError:
    HAS_LIB = False

needs_lib = pytest.mark.skipif(not HAS_LIB, reason="rfc3161-client (extra timestamp) not installed")


def _generator():
    spec = importlib.util.spec_from_file_location(
        "gen_for_report", HERE.parent / "scripts" / "gen_aiss21_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture_event(label):
    with open(FIXTURE_DIR / "freetsa_events.json", encoding="utf-8") as fh:
        return copy.deepcopy(json.load(fh)["events"][label])


def classical_identity():
    """Identité de l'agent B des vecteurs : l'événement AISS-1 de la fixture est signé par B."""
    gen = _generator()
    return {"agent_id": gen.B.id1, "public_key": base64.b64encode(gen.B.ed_pub).decode()}, gen


@pytest.mark.skipif(importlib.util.find_spec("dilithium_py") is None, reason="dilithium-py absent")
class TestTsaSection(unittest.TestCase):

    def setUp(self):
        from aiss.chain import compute_event_hash
        self.identity, self.gen = classical_identity()
        self.real = fixture_event("aiss1")                       # jeton réel, signature de B valide
        previous = compute_event_hash(self.real)
        def make(i, tag):
            event = self.gen.event1(self.gen.B, 100 + i, f"rep/{tag}", {"tag": tag}, previous)
            return event
        self.plain = make(1, "plain")
        self.pending = make(2, "pending")
        self.pending["trusted_timestamp"] = {"status": "pending"}
        self.forged = make(3, "forged")
        self.forged["trusted_timestamp"] = {"status": "verified", "token": "base64:AAAA", "timestamp": 0}
        self.events = [self.real, self.plain, self.pending, self.forged]

    def report(self, events=None, roots=ROOT_PEM):
        from aiss.verify import get_verification_report
        return get_verification_report(self.events if events is None else events, self.identity, roots)

    def test_section_is_always_present_and_never_silent(self):
        from aiss.verify import get_verification_report
        for events in ([], None, "x"):
            tsa = get_verification_report(events, self.identity)["tsa"]
            self.assertEqual({k: tsa[k] for k in ("verified", "structure_only", "pending", "invalid", "absent")},
                             dict.fromkeys(("verified", "structure_only", "pending", "invalid", "absent"), 0))
            self.assertEqual(tsa["revocation"], "not_checked")

    @needs_lib
    def test_counts_per_status(self):
        tsa = self.report()["tsa"]
        self.assertEqual((tsa["verified"], tsa["absent"], tsa["pending"], tsa["invalid"], tsa["structure_only"]),
                         (1, 1, 1, 1, 0))
        self.assertEqual(tsa["total"], 4)
        self.assertEqual(tsa["trust_roots"], 1)
        self.assertTrue(tsa["verification_available"])
        problems = {d["index"]: d["status"] for d in tsa["details"]}
        self.assertEqual(problems, {2: "pending", 3: "invalid"})
        self.assertTrue(all(d["reason"] for d in tsa["details"]))

    @needs_lib
    def test_a_pending_event_is_never_counted_as_anchored(self):
        tsa = self.report([self.pending])["tsa"]
        self.assertEqual((tsa["pending"], tsa["verified"], tsa["structure_only"]), (1, 0, 0))

    @needs_lib
    def test_without_a_trust_root_a_real_token_is_structure_only(self):
        tsa = self.report(roots=[])["tsa"]
        self.assertEqual((tsa["verified"], tsa["structure_only"]), (0, 1))
        self.assertEqual(tsa["trust_roots"], 0)

    @needs_lib
    def test_a_token_of_another_event_is_invalid(self):
        other = copy.deepcopy(self.plain)
        other["trusted_timestamp"] = copy.deepcopy(self.real["trusted_timestamp"])
        tsa = self.report([other])["tsa"]
        self.assertEqual((tsa["invalid"], tsa["verified"]), (1, 0))

    @needs_lib
    def test_the_section_never_changes_the_verdict(self):
        with_tsa = self.report()
        stripped = [{k: v for k, v in e.items() if k != "trusted_timestamp"} for e in self.events]
        without_tsa = self.report(stripped)
        for key in with_tsa:
            if key != "tsa":
                self.assertEqual(with_tsa[key], without_tsa[key], key)
        self.assertEqual(without_tsa["tsa"]["absent"], 4)

    @needs_lib
    def test_environment_trust_store_is_used_by_default(self):
        with patch.dict("os.environ", {"PIQRYPT_TSA_TRUST_ROOTS": ROOT_PEM}):
            tsa = self.report(roots=None)["tsa"]
        self.assertEqual(tsa["verified"], 1)

    def test_mit_only_build_counts_present_tokens_as_structure_only(self):
        with patch.dict(sys.modules, {"aiss.rfc3161": None}):
            tsa = self.report()["tsa"]
        self.assertFalse(tsa["verification_available"])
        self.assertEqual((tsa["verified"], tsa["structure_only"], tsa["pending"], tsa["absent"]),
                         (0, 2, 1, 1))  # le jeton réel et le jeton forgé : structure seule

    def test_non_object_events_are_counted_invalid(self):
        tsa = self.report([self.plain, None, 5])["tsa"]
        self.assertEqual((tsa["absent"], tsa["invalid"]), (1, 2))


if __name__ == "__main__":
    unittest.main()
