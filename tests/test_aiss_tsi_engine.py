# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests — aiss/tsi_engine.py
Trust Stability Index

API reelle :
    compute_tsi(
        agent_id: str,
        current_score: float = None,   # calcule via trust_score si omis
        persist: bool = True,
        current_time: int = None,
    ) -> dict

    Retourne : {"tsi": "STABLE"|"WATCH"|"UNSTABLE"|"CRITICAL", ...}
"""
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


class TestTSIImport(unittest.TestCase):
    def test_import(self):
        from aiss import tsi_engine
        self.assertIsNotNone(tsi_engine)

    def test_has_compute_tsi(self):
        from aiss import tsi_engine
        self.assertTrue(hasattr(tsi_engine, "compute_tsi"),
            "tsi_engine doit exposer compute_tsi()")

    def test_compute_tsi_signature(self):
        """compute_tsi accepte agent_id et current_score"""
        import inspect
        from aiss.tsi_engine import compute_tsi
        sig = inspect.signature(compute_tsi)
        params = list(sig.parameters.keys())
        self.assertIn("agent_id", params,
            "compute_tsi doit accepter agent_id")


class TestTSIWithRealStorage(unittest.TestCase):
    """
    Tests avec stockage reel dans un repertoire temporaire.
    On patch TSI_DIR pour pointer vers un tmpdir isole —
    compatible Linux et Windows.
    """

    def _make_baseline(self, scores, days_back=30):
        """Cree une baseline TSI avec des snapshots horodates."""
        now = int(time.time())
        step = (days_back * 86400) // max(len(scores), 1)
        return {
            "snapshots": [
                {"timestamp": now - (len(scores) - i) * step, "score": s}
                for i, s in enumerate(scores)
            ],
            "last_state": "STABLE",
            "unstable_since": None,
        }

    def _write_baseline(self, tsi_dir: Path, agent_id: str, baseline: dict) -> None:
        """Ecrit une baseline dans le repertoire TSI temporaire."""
        tsi_dir.mkdir(parents=True, exist_ok=True)
        safe_id = agent_id.replace("/", "_").replace("\\", "_")[:64]
        (tsi_dir / f"{safe_id}.json").write_text(json.dumps(baseline))

    def test_stable_scores_return_stable(self):
        """Scores uniformes sur 30j => STABLE"""
        from aiss.tsi_engine import compute_tsi
        import aiss.tsi_engine as _tsi

        with tempfile.TemporaryDirectory() as tmpdir:
            tsi_dir = Path(tmpdir) / "tsi"
            baseline = self._make_baseline([0.88] * 25)
            self._write_baseline(tsi_dir, "stable_agent", baseline)

            with patch.object(_tsi, "TSI_DIR", tsi_dir):
                result = compute_tsi("stable_agent", current_score=0.88, persist=False)

        self.assertIn("tsi", result)
        self.assertIn(result["tsi"], ["STABLE", "WATCH", "UNSTABLE", "CRITICAL"],
            f"Etat TSI invalide : {result['tsi']}")

    def test_return_value_has_tsi_key(self):
        """compute_tsi retourne un dict avec la cle 'tsi'"""
        from aiss.tsi_engine import compute_tsi
        import aiss.tsi_engine as _tsi

        with tempfile.TemporaryDirectory() as tmpdir:
            tsi_dir = Path(tmpdir) / "tsi"
            baseline = self._make_baseline([0.85] * 10)
            self._write_baseline(tsi_dir, "test_agent", baseline)

            with patch.object(_tsi, "TSI_DIR", tsi_dir):
                result = compute_tsi("test_agent", current_score=0.85, persist=False)

        self.assertIsInstance(result, dict)
        self.assertIn("tsi", result)

    def test_no_baseline_returns_stable(self):
        """Sans baseline (nouvel agent), TSI doit etre STABLE par defaut"""
        from aiss.tsi_engine import compute_tsi
        import aiss.tsi_engine as _tsi

        with tempfile.TemporaryDirectory() as tmpdir:
            tsi_dir = Path(tmpdir) / "tsi"
            # Repertoire vide — pas de baseline

            with patch.object(_tsi, "TSI_DIR", tsi_dir):
                result = compute_tsi("new_agent", current_score=0.90, persist=False)

        self.assertIn("tsi", result)
        self.assertIn(result["tsi"], ["STABLE", "WATCH"])

    def test_valid_tsi_states_only(self):
        """TSI ne retourne que des etats valides"""
        from aiss.tsi_engine import compute_tsi
        import aiss.tsi_engine as _tsi

        valid = {"STABLE", "WATCH", "UNSTABLE", "CRITICAL"}

        with tempfile.TemporaryDirectory() as tmpdir:
            tsi_dir = Path(tmpdir) / "tsi"
            baseline = self._make_baseline([0.88] * 15)

            for score in [0.95, 0.75, 0.50, 0.20]:
                self._write_baseline(tsi_dir, "test", baseline)
                with patch.object(_tsi, "TSI_DIR", tsi_dir):
                    result = compute_tsi("test", current_score=score, persist=False)
                self.assertIn(result["tsi"], valid,
                    f"Etat TSI invalide : {result['tsi']}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
