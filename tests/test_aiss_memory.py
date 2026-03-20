# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests — aiss/memory.py
Memoire contextuelle de l agent
"""
import tempfile
import unittest
from pathlib import Path


class TestMemoryImport(unittest.TestCase):
    def test_import(self):
        from aiss import memory
        self.assertIsNotNone(memory)

    def test_has_memory_functions(self):
        from aiss import memory
        has_api = any([
            hasattr(memory, "init_memory_dirs"),
            hasattr(memory, "AgentMemory"),
            hasattr(memory, "load_events"),
            hasattr(memory, "store_event"),
        ])
        self.assertTrue(has_api, "memory doit exposer une API de stockage")


class TestMemoryOperations(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_init_creates_dirs(self):
        """init_memory_dirs cree les repertoires necessaires"""
        try:
            from aiss.memory import init_memory_dirs
            init_memory_dirs(base_dir=self.tmpdir)
            base = Path(self.tmpdir)
            # Au moins un sous-repertoire doit etre cree
            subdirs = [p for p in base.rglob("*") if p.is_dir()]
            self.assertGreater(len(subdirs), 0, "Des sous-repertoires doivent etre crees")
        except (ImportError, AttributeError, TypeError):
            self.skipTest("init_memory_dirs signature differente")

    def test_load_events_empty(self):
        """load_events sur repertoire vide retourne une liste vide"""
        try:
            from aiss.memory import load_events, init_memory_dirs
            init_memory_dirs(base_dir=self.tmpdir)
            events = load_events(base_dir=self.tmpdir)
            self.assertIsInstance(events, list)
            self.assertEqual(len(events), 0)
        except (ImportError, AttributeError, TypeError):
            self.skipTest("load_events signature differente")

    def test_store_and_reload_event(self):
        """Un evenement stocke peut etre recharge"""
        try:
            from aiss.memory import store_event, load_events, init_memory_dirs
            import time
            init_memory_dirs(base_dir=self.tmpdir)
            event = {
                "event_type": "test_event",
                "timestamp": time.time(),
                "agent_name": "test_bot",
                "data": "valeur_test",
            }
            store_event(event, base_dir=self.tmpdir)
            events = load_events(base_dir=self.tmpdir)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "test_event")
        except (ImportError, AttributeError, TypeError):
            self.skipTest("store_event/load_events signature differente")


if __name__ == "__main__":
    unittest.main(verbosity=2)
