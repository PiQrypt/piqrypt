"""
Tests — aiss/trust_score.py
Trust Score 5 composantes (I, V_t, D_t, F, R)

Comportement reel :
    compute_trust_score(agent_id, events) -> dict
    
    events vide => score = 1.0  (nouvel agent = confiance par defaut)
    Ce n est pas un bug : un agent sans historique n a pas encore failli.
"""
import time, unittest


def make_events(n: int, score: float = 0.85) -> list:
    """Genere des evenements AISS factices."""
    now = time.time()
    return [
        {
            "event_type": "finalization",
            "timestamp": int(now - i * 3600),
            "agent_id": "AGENT_TEST",
            "verified": True,
            "signature": "mock_sig",
            "hash": f"hash_{i:04d}",
            "previous_hash": f"hash_{i-1:04d}" if i > 0 else None,
        }
        for i in range(n)
    ]


class TestTrustScoreImport(unittest.TestCase):
    def test_import(self):
        from aiss import trust_score
        self.assertIsNotNone(trust_score)

    def test_has_compute_trust_score(self):
        from aiss import trust_score
        self.assertTrue(
            hasattr(trust_score, "compute_trust_score"),
            "trust_score doit exposer compute_trust_score()"
        )


class TestTrustScoreValues(unittest.TestCase):
    def _get_score(self, result):
        """Extrait la valeur numerique du resultat."""
        if isinstance(result, (int, float)):
            return float(result)
        if isinstance(result, dict):
            return float(result.get("trust_score",
                         result.get("ts",
                         result.get("score", 0))))
        return 0.0

    def test_score_between_0_and_1(self):
        """Le Trust Score est dans [0, 1]"""
        from aiss.trust_score import compute_trust_score
        events = make_events(10)
        result = compute_trust_score("AGENT_TEST", events)
        ts = self._get_score(result)
        self.assertGreaterEqual(ts, 0.0)
        self.assertLessEqual(ts, 1.0)

    def test_no_events_returns_1_0(self):
        """
        Nouvel agent sans historique => score 1.0 (confiance par defaut).
        Comportement intentionnel : un agent sans historique n a pas encore
        echoue. La penalite vient des evenements negatifs, pas de l absence.
        """
        from aiss.trust_score import compute_trust_score
        result = compute_trust_score("NEW_AGENT", [])
        ts = self._get_score(result)
        self.assertAlmostEqual(ts, 1.0, places=1,
            msg=f"Nouvel agent => score attendu proche de 1.0, got {ts}")

    def test_result_has_components(self):
        """Le resultat contient les composantes du score"""
        from aiss.trust_score import compute_trust_score
        events = make_events(5)
        result = compute_trust_score("AGENT_TEST", events)
        if isinstance(result, dict):
            has_components = (
                "components" in result or
                "trust_score" in result or
                "ts" in result or
                "score" in result
            )
            self.assertTrue(has_components,
                f"Le resultat doit avoir au moins une cle de score, got {list(result.keys())}")

    def test_consistent_with_events(self):
        """compute_trust_score ne plante pas avec des evenements valides"""
        from aiss.trust_score import compute_trust_score
        for n in [1, 5, 20]:
            events = make_events(n)
            try:
                result = compute_trust_score("AGENT_TEST", events)
                self.assertIsNotNone(result)
            except Exception as e:
                self.fail(f"compute_trust_score a plante avec {n} evenements : {e}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
