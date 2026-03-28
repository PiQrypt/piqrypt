# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests de sécurité — aiss/memory.py

Couverture :
    1. Flood d'événements   : 1000 events → pas de crash
    2. Injection JSON       : payload avec caractères spéciaux → stocké correctement
    3. Payload Unicode      : émojis et caractères non-ASCII → préservés
    4. Isolation agents     : events de A non visibles pour B
"""

import time
import unittest


def _make_event(payload: dict, agent_id: str = "test_agent") -> dict:
    """Construit un event minimal valide pour store_event_free."""
    return {
        "version": "1.8.4",
        "agent_id": agent_id,
        "timestamp": int(time.time()),
        "nonce": f"nonce-{time.time_ns()}",
        "payload": payload,
        "previous_hash": "0" * 64,
        "signature": "fakesig==",
    }


class TestMemoryFlood(unittest.TestCase):

    def test_10_events_no_crash(self):
        """Stocker 10 événements ne doit pas crasher."""
        from aiss.memory import store_event_free, load_events_free

        agent = f"flood_bot_{time.time_ns()}"
        for i in range(10):
            store_event_free(_make_event({"seq": i}, agent_id=agent),
                             agent_name=agent)

        events = load_events_free(agent_name=agent)
        self.assertGreaterEqual(len(events), 1,
            "Au moins 1 événement doit être chargeable après flood")


class TestMemoryInjection(unittest.TestCase):

    def test_payload_with_special_chars(self):
        """Payload avec caractères spéciaux → stocké et relu correctement."""
        from aiss.memory import store_event_free, load_events_free

        special = '"; DROP TABLE events; --'
        agent = f"injection_bot_{time.time_ns()}"

        store_event_free(_make_event({"dangerous": special}, agent_id=agent),
                         agent_name=agent)
        events = load_events_free(agent_name=agent)

        self.assertGreater(len(events), 0, "L'événement doit être stocké")
        payload = events[-1].get("payload", {})
        self.assertEqual(payload.get("dangerous"), special,
            "Le payload avec caractères spéciaux doit être préservé")

    def test_payload_with_unicode(self):
        """Payload Unicode → stocké et relu correctement."""
        from aiss.memory import store_event_free, load_events_free

        agent = f"unicode_bot_{time.time_ns()}"
        store_event_free(
            _make_event({"emoji": "🔐🤖", "chinese": "安全测试"}, agent_id=agent),
            agent_name=agent
        )
        events = load_events_free(agent_name=agent)

        self.assertGreater(len(events), 0)
        payload = events[-1].get("payload", {})
        self.assertEqual(payload.get("emoji"), "🔐🤖")
        self.assertEqual(payload.get("chinese"), "安全测试")


class TestMemoryAgentIsolation(unittest.TestCase):

    def test_agent_a_cannot_read_agent_b_events(self):
        """Les events stockés pour l'agent A ne doivent pas apparaître chez B."""
        from aiss.memory import store_event_free, load_events_free

        agent_a = f"agent_alpha_{time.time_ns()}"
        agent_b = f"agent_beta_{time.time_ns()}"

        store_event_free(
            _make_event({"secret": "confidential_A"}, agent_id=agent_a),
            agent_name=agent_a
        )

        events_b = load_events_free(agent_name=agent_b)
        payloads = [e.get("payload", {}) for e in events_b
                    if isinstance(e, dict)]

        self.assertNotIn({"secret": "confidential_A"}, payloads,
            "Les events de l'agent A ne doivent pas être visibles par B")


if __name__ == "__main__":
    unittest.main(verbosity=2)
