# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Test Memory Index — Sprint 3
Vérifie : indexation SQLite + search rapide
"""

import sys
import tempfile
import shutil
sys.path.insert(0, '.')

from aiss.index import MemoryIndex, get_index
from aiss.memory import store_event, search_events, init_memory_dirs
from pathlib import Path


def test_index_basic():
    """Test création index + add_event + search"""
    with tempfile.TemporaryDirectory() as tmpdir:
        index_path = Path(tmpdir) / "test.db"

        with MemoryIndex(index_path) as idx:
            # Add events
            idx.add_event(
                event_hash="a3f7e8c9d1b2a4f6",
                timestamp=1705310400,
                event_type="trade_executed",
                agent_id="test_agent",
                nonce="uuid-1",
                file_path="2025-01.json",
                offset=0,
                length=512,
            )

            idx.add_event(
                event_hash="b4e9f1d0a2c3b5e7",
                timestamp=1705396800,
                event_type="position_closed",
                agent_id="test_agent",
                nonce="uuid-2",
                file_path="2025-01.json",
                offset=512,
                length=480,
            )

            # Search
            results = idx.search(agent_id="test_agent")
            assert len(results) == 2

            results = idx.search(event_type="trade_executed")
            assert len(results) == 1
            assert results[0]["event_hash"] == "a3f7e8c9d1b2a4f6"

            results = idx.search(from_timestamp=1705310400, to_timestamp=1705310400)
            assert len(results) == 1

            # Search by hash prefix
            results = idx.search_by_hash_prefix("a3f7")
            assert len(results) == 1

            # Find by nonce
            entry = idx.find_by_nonce("uuid-1")
            assert entry is not None
            assert entry["event_hash"] == "a3f7e8c9d1b2a4f6"

            # Stats
            stats = idx.get_stats()
            assert stats["total_events"] == 2
            assert stats["agents_count"] == 1

    print("✓ index_basic OK")


def test_memory_integration():
    """Test intégration store_event → index automatique"""
    # Setup test directory
    test_home = Path(tempfile.mkdtemp())
    _ = Path.home()

    try:
        # Override home temporarily
        import aiss.memory
        aiss.memory.PIQRYPT_DIR = test_home / ".piqrypt"
        aiss.memory.EVENTS_PLAIN_DIR = aiss.memory.PIQRYPT_DIR / "events" / "plain"
        aiss.memory.EVENTS_ENC_DIR = aiss.memory.PIQRYPT_DIR / "events" / "encrypted"
        aiss.memory.KEYS_DIR = aiss.memory.PIQRYPT_DIR / "keys"
        aiss.memory.MASTER_KEY_FILE = aiss.memory.KEYS_DIR / "master.key.enc"
        aiss.memory.CONFIG_FILE = aiss.memory.PIQRYPT_DIR / "config.json"

        init_memory_dirs()

        # Create events
        priv, pub = aiss.generate_keypair()
        agent_id = aiss.derive_agent_id(pub)

        for i in range(5):
            event = aiss.stamp_event(
                priv, agent_id, {"action": f"test_{i}", "event_type": "test_event"}
            )
            store_event(event)

        # Verify index was updated
        with get_index(encrypted=False) as idx:
            results = idx.search(agent_id=agent_id)
            assert len(results) == 5

            results = idx.search(event_type="test_event")
            assert len(results) == 5

        # Verify search_events uses index
        search_results = search_events(participant=agent_id, use_index=True)
        assert len(search_results) == 5

        search_results = search_events(event_type="test_event", limit=2)
        assert len(search_results) == 2

        print("✓ memory_integration OK")

    finally:
        shutil.rmtree(test_home)


if __name__ == "__main__":
    print("=" * 60)
    print("Memory Index Tests — Sprint 3")
    print("=" * 60)
    print()

    try:
        test_index_basic()
        test_memory_integration()

        print()
        print("─" * 60)
        print("✅ MEMORY INDEX TESTS PASSED")
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
