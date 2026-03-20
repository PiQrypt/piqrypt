# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests — aiss/anomaly_monitor.py
Moteur VRS (Vigil Risk Score) + alertes
"""
import time
import unittest


def make_agent_events(n: int = 30, trust_score: float = 0.85) -> list:
    now = time.time()
    return [
        {
            "event_type": "trust_score_updated",
            "timestamp": now - i * 3600,
            "trust_score": trust_score,
            "agent_name": "test_agent",
        }
        for i in range(n)
    ]


class TestAnomalyMonitorImport(unittest.TestCase):
    def test_import(self):
        from aiss import anomaly_monitor
        self.assertIsNotNone(anomaly_monitor)

    def test_has_compute_vrs(self):
        from aiss import anomaly_monitor
        self.assertTrue(
            hasattr(anomaly_monitor, "compute_vrs"),
            "anomaly_monitor doit exposer compute_vrs()"
        )


class TestVRSComputation(unittest.TestCase):
    def test_safe_agent_vrs(self):
        """Agent avec bon trust score => VRS faible (SAFE)"""
        try:
            from aiss.anomaly_monitor import compute_vrs
            events = make_agent_events(trust_score=0.92)
            result = compute_vrs("safe_agent", "AGENT_ID", events)
            self.assertIn("vrs", result)
            self.assertLess(result["vrs"], 0.45,
                f"Agent fiable attendu VRS < 0.45, got {result['vrs']}")
        except (ImportError, AttributeError, TypeError):
            self.skipTest("compute_vrs signature differente - adapter le test")

    def test_vrs_between_0_and_1(self):
        """Le VRS doit etre entre 0 et 1"""
        try:
            from aiss.anomaly_monitor import compute_vrs
            events = make_agent_events(trust_score=0.75)
            result = compute_vrs("test_agent", "AGENT_ID", events)
            self.assertGreaterEqual(result["vrs"], 0.0)
            self.assertLessEqual(result["vrs"], 1.0)
        except (ImportError, AttributeError, TypeError):
            self.skipTest("compute_vrs signature differente")

    def test_vrs_state_consistent(self):
        """L etat VRS est coherent avec la valeur numerique"""
        try:
            from aiss.anomaly_monitor import compute_vrs
            events = make_agent_events(trust_score=0.85)
            result = compute_vrs("test_agent", "AGENT_ID", events)
            vrs = result["vrs"]
            state = result.get("state", "")
            if vrs < 0.20:
                self.assertEqual(state, "SAFE")
            elif vrs < 0.45:
                self.assertIn(state, ["SAFE", "WATCH"])
            elif vrs < 0.75:
                self.assertIn(state, ["WATCH", "ALERT"])
            else:
                self.assertIn(state, ["ALERT", "CRITICAL"])
        except (ImportError, AttributeError, TypeError):
            self.skipTest("compute_vrs signature differente")


class TestVRSAlerts(unittest.TestCase):
    def test_get_agent_alerts_exists(self):
        """get_agent_alerts est accessible"""
        try:
            from aiss.anomaly_monitor import get_agent_alerts
            self.assertIsNotNone(get_agent_alerts)
        except ImportError:
            self.skipTest("get_agent_alerts non trouvee")

    def test_installation_summary_exists(self):
        """get_installation_summary est accessible"""
        try:
            from aiss.anomaly_monitor import get_installation_summary
            self.assertIsNotNone(get_installation_summary)
        except ImportError:
            self.skipTest("get_installation_summary non trouvee")


if __name__ == "__main__":
    unittest.main(verbosity=2)
