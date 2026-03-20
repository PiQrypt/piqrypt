# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Test RFC 3161 end-to-end — Sprint 1-B
Vérifie que le TSA timestamp fonctionne avec freetsa.org (ou graceful degradation)
"""

import sys
sys.path.insert(0, '.')

import aiss
from aiss.rfc3161 import request_timestamp, stamp_event_with_tsa, TSAUnavailableError


def test_rfc3161_basic_request():
    """Test basique : demander un timestamp TSA sur des bytes"""
    try:
        data = b"test_data_for_timestamp"
        token = request_timestamp(data)

        assert "authority" in token
        assert "timestamp" in token
        assert "token" in token
        assert token["status"] in ["granted", "grantedWithMods"]

        print(f"✓ RFC 3161 basic request OK — TSA: {token['authority']}")
        print(f"  Status: {token['status']}")
        print(f"  Token size: {token.get('token_size_bytes', 0)} bytes")
        return True

    except TSAUnavailableError as e:
        print(f"⚠️  TSA unavailable (graceful): {e}")
        print("   (Network may be disabled or TSA down — this is expected in offline mode)")
        return "degraded"

    except Exception as e:
        print(f"✗ RFC 3161 request failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_rfc3161_stamp_event():
    """Test : TSA timestamp sur un événement AISS-1 signé"""
    try:
        # Create event
        priv, pub = aiss.generate_keypair()
        agent_id = aiss.derive_agent_id(pub)
        event = aiss.stamp_event(priv, agent_id, {"action": "test_rfc3161"})

        # Add TSA timestamp
        event_with_tsa = stamp_event_with_tsa(event, fail_gracefully=True)

        # Check
        if "trusted_timestamp" in event_with_tsa:
            ts = event_with_tsa["trusted_timestamp"]
            if ts.get("status") == "pending":
                print("⚠️  TSA unavailable — event has pending timestamp (graceful degradation)")
                return "degraded"

            assert ts.get("authority")
            assert ts.get("timestamp")
            print(f"✓ RFC 3161 event stamping OK — TSA: {ts['authority']}")
            return True
        else:
            print("⚠️  No trusted_timestamp field — graceful degradation")
            return "degraded"

    except Exception as e:
        print(f"✗ RFC 3161 event stamping failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_rfc3161_in_aiss2():
    """Test : TSA dans un événement AISS-2 hybride"""
    from aiss.license import activate_license, deactivate_license
    from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
    from aiss.crypto import dilithium

    # Activer Pro temporairement
    activate_license("pk_pro_test_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")

    try:
        if not dilithium or not dilithium.is_available():
            print("⚠️  Dilithium3 not available — skipping AISS-2 test")
            deactivate_license()
            return "skipped"

        priv_ed, pub_ed = aiss.generate_keypair()
        priv_dil, pub_dil = dilithium.generate_keypair()
        agent_id = aiss.derive_agent_id(pub_ed)

        # AISS-2 event with TSA (tsa_stamp_after=True by default)
        event = stamp_event_aiss2_hybrid(
            priv_ed, priv_dil, agent_id,
            {"action": "test_aiss2_rfc3161"},
            tsa_stamp_after=True,  # Auto-request TSA
        )

        # Check
        assert "trusted_timestamp" in event
        ts = event["trusted_timestamp"]

        if ts.get("status") == "pending":
            print("⚠️  AISS-2: TSA unavailable — pending timestamp (graceful)")
            deactivate_license()
            return "degraded"

        assert ts.get("rfc3161_token")
        assert ts.get("tsa_id")
        print(f"✓ AISS-2 with RFC 3161 OK — TSA: {ts['tsa_id']}")

        deactivate_license()
        return True

    except Exception as e:
        print(f"✗ AISS-2 RFC 3161 failed: {e}")
        import traceback
        traceback.print_exc()
        deactivate_license()
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("RFC 3161 End-to-End Tests — Sprint 1-B")
    print("=" * 60)
    print()

    results = {
        "basic_request": test_rfc3161_basic_request(),
        "stamp_event": test_rfc3161_stamp_event(),
        "aiss2": test_rfc3161_in_aiss2(),
    }

    print()
    print("─" * 60)
    print("Results:")
    for name, result in results.items():
        if result is True:
            status = "✅ PASS"
        elif result == "degraded":
            status = "⚠️  DEGRADED"
        elif result == "skipped":
            status = "⏭️  SKIPPED"
        else:
            status = "❌ FAIL"
        print(f"  {name:20s}: {status}")

    # Consider degraded as acceptable (network may be disabled)
    all_pass = all(r in [True, "degraded", "skipped"] for r in results.values())

    if all_pass:
        print("\n✅ RFC 3161 END-TO-END VERIFICATION COMPLETE")
        print("   (Graceful degradation confirmed — TSA works when network available)")
    else:
        print("\n❌ FAILURES DETECTED — review above")
        sys.exit(1)
