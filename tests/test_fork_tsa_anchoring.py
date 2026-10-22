# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests — résolution de fork non forgeable (chantier C.1).

Le champ trusted_timestamp est détaché et non signé : un événement n'est compté comme ancré que
si un vérificateur fourni par l'appelant le déclare vérifié et rend le genTime du jeton.
"""
import nacl.signing  # noqa: F401

import copy
import unittest

import aiss
from aiss.chain import compute_event_hash
from aiss.fork import (
    STATUS_FORK_AFTER_FINALIZATION, STATUS_FORK_DETECTED, ForkAfterFinalizationError,
    classify_fork, detect_fork_after_finalization, resolve_fork_canonical, select_canonical_chain,
)
from aiss.tsa_token import has_tsa_token, tsa_token_value

PRIV, PUB = aiss.generate_keypair()
AGENT = aiss.derive_agent_id(PUB)
_counter = [0]


def make_chain(length, tag="c", start=None, ts=1_800_000_000):
    """Chaîne AISS-1 de `length` événements ; `start` = chaîne dont on prolonge un préfixe."""
    events = list(start or [])
    previous = compute_event_hash(events[-1]) if events else None
    for i in range(len(events), length):
        _counter[0] += 1
        event = aiss.stamp_event(PRIV, AGENT, {"tag": tag, "i": i}, previous_hash=previous,
                                 nonce=f"{tag}-{i}-{_counter[0]}", timestamp=ts + i)
        events.append(event)
        previous = compute_event_hash(event)
    return events


def attach(event, token="FAKE", local_timestamp=1, status=None, key="rfc3161_token"):
    trusted = {key: token, "timestamp": local_timestamp}
    if status:
        trusted["status"] = status
    event["trusted_timestamp"] = trusted
    return event


def verifier_by_gen_time(mapping):
    """Vérificateur de test : genTime du jeton dans `mapping` (token -> int), sinon None."""
    def verify(event):
        return mapping.get(tsa_token_value(event))
    return verify


class TestHasTsaToken(unittest.TestCase):

    def test_accepts_token_and_legacy_key(self):
        self.assertTrue(has_tsa_token({"trusted_timestamp": {"token": "base64:AAAA"}}))
        self.assertTrue(has_tsa_token({"trusted_timestamp": {"rfc3161_token": "AAAA"}}))
        self.assertEqual(tsa_token_value({"trusted_timestamp": {"token": "base64:AAAA"}}), "base64:AAAA")

    def test_rejects_empty_or_absent(self):
        for event in (
            {}, None, "x", [], {"trusted_timestamp": None}, {"trusted_timestamp": "tok"},
            {"trusted_timestamp": {}}, {"trusted_timestamp": {"token": ""}},
            {"trusted_timestamp": {"token": "   "}}, {"trusted_timestamp": {"token": "base64:"}},
            {"trusted_timestamp": {"token": None, "rfc3161_token": None}},
            {"trusted_timestamp": {"token": 5}}, {"trusted_timestamp": {"token": b"AAAA"}},
            {"trusted_timestamp": {"status": "granted"}},
        ):
            with self.subTest(event=repr(event)):
                self.assertFalse(has_tsa_token(event))

    def test_status_alone_is_not_a_token(self):
        self.assertFalse(has_tsa_token({"trusted_timestamp": {"status": "verified"}}))


class TestForgedAnchorsDoNotWin(unittest.TestCase):

    def test_forged_branch_does_not_win_without_a_verifier(self):
        long_chain = make_chain(5, "long")
        forged = make_chain(2, "forged")
        attach(forged[1], token="x", local_timestamp=0)  # {"rfc3161_token": "x", "timestamp": 0}
        canonical, _ = select_canonical_chain([long_chain, forged])
        self.assertEqual(len(canonical), 5)
        canonical, _ = select_canonical_chain([forged, long_chain])
        self.assertEqual(len(canonical), 5)

    def test_self_declared_status_is_ignored(self):
        long_chain = make_chain(5, "long")
        forged = make_chain(2, "forged")
        attach(forged[1], token="base64:AAAA", status="verified")
        canonical, _ = select_canonical_chain([long_chain, forged])
        self.assertEqual(len(canonical), 5)

    def test_forged_branch_does_not_win_when_the_verifier_rejects_it(self):
        long_chain = make_chain(5, "long")
        forged = make_chain(2, "forged")
        attach(forged[1], token="x", local_timestamp=0)
        canonical, _ = select_canonical_chain([long_chain, forged], tsa_verifier=lambda e: None)
        self.assertEqual(len(canonical), 5)

    def test_without_a_verifier_the_selection_is_length_then_hash_and_deterministic(self):
        a, b = make_chain(3, "a"), make_chain(3, "b")
        attach(a[2], token="x", local_timestamp=0)
        results = [select_canonical_chain(order)[0] for order in ([a, b], [b, a])]
        self.assertEqual(compute_event_hash(results[0][-1]), compute_event_hash(results[1][-1]))
        expected = min((a, b), key=lambda c: compute_event_hash(c[-1]))
        self.assertEqual(compute_event_hash(results[0][-1]), compute_event_hash(expected[-1]))

    def test_a_forged_timestamp_cannot_win_step_two(self):
        one, two = make_chain(3, "one"), make_chain(3, "two")
        attach(one[1], token="real-one", local_timestamp=999_999_999_999)   # horloge locale tardive
        attach(two[1], token="forged", local_timestamp=0)                    # horloge locale forgée
        verifier = verifier_by_gen_time({"real-one": 1_700_000_000, "forged": 1_900_000_000})
        canonical, _ = select_canonical_chain([two, one], tsa_verifier=verifier)
        self.assertEqual(canonical, one)  # le genTime du jeton décide, pas le champ local


class TestVerifiedAnchors(unittest.TestCase):

    def test_verified_anchored_short_chain_beats_a_longer_one(self):
        long_chain = make_chain(5, "long")
        short = make_chain(2, "short")
        attach(short[1], token="good")
        canonical, others = select_canonical_chain(
            [long_chain, short], tsa_verifier=verifier_by_gen_time({"good": 1_700_000_000}))
        self.assertEqual(len(canonical), 2)
        self.assertEqual(others, ["0"])

    def test_more_verified_anchors_win_step_one(self):
        a, b = make_chain(4, "a"), make_chain(4, "b")
        attach(a[0], token="a0"), attach(a[1], token="a1")
        attach(b[0], token="b0")
        verifier = verifier_by_gen_time({"a0": 5, "a1": 6, "b0": 1})
        canonical, _ = select_canonical_chain([b, a], tsa_verifier=verifier)
        self.assertEqual(canonical, a)

    def test_earliest_verified_gen_time_wins_step_two(self):
        a, b = make_chain(4, "a"), make_chain(4, "b")
        attach(a[1], token="late", local_timestamp=1)
        attach(b[1], token="early", local_timestamp=999)
        verifier = verifier_by_gen_time({"late": 2000, "early": 1000})
        for order in ([a, b], [b, a]):
            canonical, _ = select_canonical_chain(order, tsa_verifier=verifier)
            self.assertEqual(canonical, b)

    def test_unusable_verifier_results_do_not_anchor(self):
        long_chain = make_chain(5, "long")
        for label, result in {"none": None, "bool": True, "float": 1.5, "str": "1700000000",
                              "list": [1]}.items():
            short = make_chain(2, "short" + label)
            attach(short[1], token="t")
            with self.subTest(result=label):
                canonical, _ = select_canonical_chain(
                    [short, long_chain], tsa_verifier=lambda e, r=result: r)
                self.assertEqual(len(canonical), 5)

    def test_a_raising_verifier_does_not_anchor_and_does_not_propagate(self):
        long_chain, short = make_chain(5, "long"), make_chain(2, "short")
        attach(short[1], token="t")

        def boom(event):
            raise RuntimeError("trust store unreadable")

        canonical, _ = select_canonical_chain([short, long_chain], tsa_verifier=boom)
        self.assertEqual(len(canonical), 5)

    def test_the_verifier_is_only_called_for_events_with_a_structural_token(self):
        calls = []
        chain = make_chain(4, "plain")
        attach(chain[2], token="t")
        select_canonical_chain([chain, make_chain(3, "other")],
                               tsa_verifier=lambda e: calls.append(tsa_token_value(e)) or 7)
        self.assertEqual(calls, ["t"])

    def test_inputs_are_not_modified(self):
        a, b = make_chain(3, "a"), make_chain(3, "b")
        attach(a[1], token="t")
        snapshot = copy.deepcopy([a, b])
        select_canonical_chain([a, b], tsa_verifier=verifier_by_gen_time({"t": 1}))
        self.assertEqual([a, b], snapshot)


class TestForkAfterFinalization(unittest.TestCase):

    def _fork(self):
        base = make_chain(4, "base")
        canonical = base
        other = make_chain(4, "other", start=base[:3])  # diverge après base[2]
        return canonical, other

    def test_forged_anchor_is_not_a_finalization(self):
        canonical, other = self._fork()
        attach(canonical[1], token="x", local_timestamp=0, status="verified")
        self.assertFalse(detect_fork_after_finalization(canonical, [other]))
        self.assertEqual(classify_fork(canonical, [other]), STATUS_FORK_DETECTED)
        self.assertFalse(detect_fork_after_finalization(canonical, [other], tsa_verifier=lambda e: None))

    def test_verified_anchor_makes_the_fork_a_finalization_breach(self):
        canonical, other = self._fork()
        attach(canonical[1], token="good")
        verifier = verifier_by_gen_time({"good": 1_700_000_000})
        self.assertTrue(detect_fork_after_finalization(canonical, [other], tsa_verifier=verifier))
        self.assertEqual(classify_fork(canonical, [other], tsa_verifier=verifier),
                         STATUS_FORK_AFTER_FINALIZATION)

    def test_resolve_fork_canonical_uses_the_verifier(self):
        canonical, other = self._fork()
        attach(canonical[1], token="good")
        verifier = verifier_by_gen_time({"good": 1_700_000_000})
        with self.assertRaises(ForkAfterFinalizationError):
            resolve_fork_canonical([canonical, other], tsa_verifier=verifier)
        result = resolve_fork_canonical([canonical, other], raise_on_security_incident=False,
                                        tsa_verifier=verifier)
        self.assertEqual(result["status"], STATUS_FORK_AFTER_FINALIZATION)
        self.assertEqual(result["tsa_anchored_events"], 1)

    def test_resolve_fork_canonical_without_a_verifier_ignores_tokens(self):
        canonical, other = self._fork()
        attach(canonical[1], token="good")
        result = resolve_fork_canonical([canonical, other])  # ne lève pas
        self.assertEqual(result["status"], STATUS_FORK_DETECTED)
        self.assertEqual(result["tsa_anchored_events"], 0)


if __name__ == "__main__":
    unittest.main()
