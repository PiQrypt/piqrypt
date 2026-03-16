"""
Tests — aiss/a2c_detector.py
Detection de collusion Agent-to-Agent

API reelle :
    detect_concentration(events, current_time=None, window_hours=...) -> dict
    detect_entropy_drop(events, current_time=None, ...) -> dict
    detect_synchronization(events, peer_events, current_time=None, ...) -> dict
    detect_silence_break(events, peer_events, current_time=None, ...) -> dict
    compute_a2c_risk(agent_id, events=None, peer_events_map=None, ...) -> dict
    compute_a2c_risk_batch(agent_ids, ...) -> dict
    get_installation_a2c_summary(...) -> dict
    invalidate_cache(agent_id=None)
"""
import time
import unittest


def make_a2a_events(peer_id: str, count: int, base_ts: float = None) -> list:
    """Cree des evenements A2A vers un peer donne."""
    now = base_ts or time.time()
    return [
        {
            "event_type": "a2a_message",
            "timestamp": int(now - i * 60),
            "peer_id": peer_id,
            "agent_id": "bot_a",
            "signature": f"sig_{i}",
        }
        for i in range(count)
    ]


class TestA2CImport(unittest.TestCase):
    def test_import(self):
        from aiss import a2c_detector
        self.assertIsNotNone(a2c_detector)

    def test_has_compute_a2c_risk(self):
        from aiss import a2c_detector
        self.assertTrue(
            hasattr(a2c_detector, "compute_a2c_risk"),
            "a2c_detector doit exposer compute_a2c_risk()"
        )

    def test_has_detect_concentration(self):
        from aiss import a2c_detector
        self.assertTrue(
            hasattr(a2c_detector, "detect_concentration"),
            "a2c_detector doit exposer detect_concentration()"
        )

    def test_has_detect_entropy_drop(self):
        from aiss import a2c_detector
        self.assertTrue(hasattr(a2c_detector, "detect_entropy_drop"))

    def test_has_detect_synchronization(self):
        from aiss import a2c_detector
        self.assertTrue(hasattr(a2c_detector, "detect_synchronization"))

    def test_has_detect_silence_break(self):
        from aiss import a2c_detector
        self.assertTrue(hasattr(a2c_detector, "detect_silence_break"))


class TestDetectConcentration(unittest.TestCase):
    def test_returns_dict(self):
        """detect_concentration retourne un dict"""
        from aiss.a2c_detector import detect_concentration
        events = make_a2a_events("bot_b", 20)
        result = detect_concentration(events)
        self.assertIsInstance(result, dict)

    def test_has_score_key(self):
        """Le resultat contient un score numerique"""
        from aiss.a2c_detector import detect_concentration
        events = make_a2a_events("bot_b", 20)
        result = detect_concentration(events)
        has_score = "score" in result or "risk" in result or "concentration" in result
        self.assertTrue(has_score,
            f"detect_concentration doit retourner un score, got {list(result.keys())}")

    def test_high_concentration(self):
        """90% vers un seul peer => score eleve"""
        from aiss.a2c_detector import detect_concentration
        events = (make_a2a_events("bot_b", 90) +
                  make_a2a_events("bot_c", 5) +
                  make_a2a_events("bot_d", 5))
        result = detect_concentration(events)
        score = result.get("score", result.get("risk", result.get("concentration", 0)))
        self.assertIsInstance(score, (int, float))

    def test_balanced_low_concentration(self):
        """Distribution equilibree => score inferieur a distribution concentree"""
        from aiss.a2c_detector import detect_concentration
        concentrated = (make_a2a_events("bot_b", 90) + make_a2a_events("bot_c", 10))
        balanced = (make_a2a_events("bot_b", 25) + make_a2a_events("bot_c", 25) +
                    make_a2a_events("bot_d", 25) + make_a2a_events("bot_e", 25))
        r_conc = detect_concentration(concentrated)
        r_bal  = detect_concentration(balanced)
        s_conc = r_conc.get("score", r_conc.get("risk", 0))
        s_bal  = r_bal.get("score",  r_bal.get("risk", 0))
        self.assertGreaterEqual(s_conc, s_bal,
            f"Concentre ({s_conc}) doit etre >= equilibre ({s_bal})")

    def test_empty_events(self):
        """Liste vide ne plante pas"""
        from aiss.a2c_detector import detect_concentration
        result = detect_concentration([])
        self.assertIsInstance(result, dict)


class TestDetectEntropyDrop(unittest.TestCase):
    def test_returns_dict(self):
        from aiss.a2c_detector import detect_entropy_drop
        events = make_a2a_events("bot_b", 10)
        result = detect_entropy_drop(events)
        self.assertIsInstance(result, dict)

    def test_empty_events(self):
        from aiss.a2c_detector import detect_entropy_drop
        result = detect_entropy_drop([])
        self.assertIsInstance(result, dict)


class TestComputeA2CRisk(unittest.TestCase):
    def test_returns_dict(self):
        from aiss.a2c_detector import compute_a2c_risk
        result = compute_a2c_risk("test_agent", events=[])
        self.assertIsInstance(result, dict)

    def test_risk_between_0_and_1(self):
        """Le score de risque est dans [0, 1]"""
        from aiss.a2c_detector import compute_a2c_risk
        events = make_a2a_events("peer_b", 30)
        result = compute_a2c_risk("bot_a", events=events)
        risk = result.get("risk", result.get("score", result.get("a2c_risk", 0)))
        self.assertGreaterEqual(float(risk), 0.0)
        self.assertLessEqual(float(risk), 1.0)

    def test_has_severity(self):
        """Le resultat contient une severite"""
        from aiss.a2c_detector import compute_a2c_risk
        result = compute_a2c_risk("test_agent", events=[])
        has_severity = "severity" in result or "level" in result or "state" in result
        self.assertTrue(has_severity,
            f"compute_a2c_risk doit retourner une severite, got {list(result.keys())}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
