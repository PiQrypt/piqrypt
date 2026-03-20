# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Test Archive .pqz — Sprint 3 Partie 2
Vérifie : index.json + decrypt.py v2 + recherche
"""

import sys
import tempfile
import zipfile
import json
sys.path.insert(0, '.')

import aiss
from aiss.archive import create_archive
from pathlib import Path


def test_archive_with_index():
    """Test création archive avec index.json"""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create events
        priv, pub = aiss.generate_keypair()
        agent_id = aiss.derive_agent_id(pub)
        identity = aiss.export_identity(agent_id, pub)

        events = []
        for i in range(10):
            e = aiss.stamp_event(
                priv, agent_id, {"action": f"test_{i}", "event_type": "test_event"}
            )
            events.append(e)

        # Create archive (Free)
        archive_path = Path(tmpdir) / "test.pqz"
        _ = create_archive(events, identity, str(archive_path))

        assert archive_path.exists()
        print(f"✓ Archive created: {archive_path.name}")

        # Verify structure
        with zipfile.ZipFile(archive_path, 'r') as zf:
            files = zf.namelist()
            assert "index.json" in files
            assert "decrypt.py" in files
            assert "data.json" in files  # Free (no passphrase)
            assert "metadata.json" in files

            # Check index.json
            index = json.loads(zf.read("index.json"))
            assert index["version"] == "AISS-INDEX-1.0"
            assert index["total_events"] == 10
            assert len(index["events_index"]) == 10

            # Check index entries have required fields
            entry = index["events_index"][0]
            assert "offset" in entry
            assert "length" in entry
            assert "timestamp" in entry
            assert "event_type" in entry
            assert "event_hash" in entry
            assert "nonce" in entry

            print(f"✓ index.json structure OK ({index['total_events']} events)")

            # Check decrypt.py is v2
            decrypt_content = zf.read("decrypt.py").decode('utf-8')
            assert "Interactive shell" in decrypt_content or "cmd_search" in decrypt_content
            print("✓ decrypt.py v2 included")


def test_archive_encrypted_with_index():
    """Test archive chiffrée avec index"""
    from aiss.license import activate_license, deactivate_license
    activate_license("pk_pro_test123_2423cdc1")

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create events
            priv, pub = aiss.generate_keypair()
            agent_id = aiss.derive_agent_id(pub)
            identity = aiss.export_identity(agent_id, pub)

            events = [aiss.stamp_event(priv, agent_id, {"test": i}) for i in range(5)]

            # Create encrypted archive
            archive_path = Path(tmpdir) / "encrypted.pqz"
            _ = create_archive(events, identity, str(archive_path), passphrase="test-pass")

            # Verify
            with zipfile.ZipFile(archive_path, 'r') as zf:
                assert "data.enc" in zf.namelist()
                assert "index.json" in zf.namelist()

                index = json.loads(zf.read("index.json"))
                assert index["encrypted"] is True
                assert index["total_events"] == 5

            print("✓ Encrypted archive with index OK")

    finally:
        deactivate_license()


if __name__ == "__main__":
    print("=" * 60)
    print("Archive .pqz Tests — Sprint 3 Partie 2")
    print("=" * 60)
    print()

    try:
        test_archive_with_index()
        test_archive_encrypted_with_index()

        print()
        print("─" * 60)
        print("✅ ARCHIVE .PQZ TESTS PASSED")
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
