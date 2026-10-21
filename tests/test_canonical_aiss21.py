"""
RFC 8785 JCS canonicalization tests for AISS-2.1.

Test vectors taken directly from RFC 8785 Section 3 and Appendix B.
These verify that canonical_aiss21 is strictly conformant, unlike the
stdlib-based aiss.canonical which is frozen for AISS-1.
"""

import pytest

try:
    import rfc8785  # noqa: F401
    _HAS_RFC8785 = True
except ImportError:
    _HAS_RFC8785 = False

pytestmark = pytest.mark.skipif(not _HAS_RFC8785, reason="rfc8785 not installed")


from aiss.canonical_aiss21 import canonicalize, hash_event


# ---------------------------------------------------------------------------
# RFC 8785 canonical form test vectors (Appendix B of the RFC)
# ---------------------------------------------------------------------------

class TestRfc8785Vectors:

    def test_key_ordering(self):
        assert canonicalize({"b": 2, "a": 1}) == b'{"a":1,"b":2}'

    def test_integer_one(self):
        # RFC 8785 §3.2.2.3: integer-valued float -> integer representation
        assert canonicalize(1.0) == b"1"

    def test_negative_zero(self):
        # -0.0 must serialize as 0
        assert canonicalize(-0.0) == b"0"

    def test_float_small(self):
        # 1e-5 is representable without exponent in RFC 8785
        assert canonicalize(1e-5) == b"0.00001"

    def test_float_very_small(self):
        # 1e-7 requires exponent notation
        assert canonicalize(1e-7) == b"1e-7"

    def test_float_large(self):
        # 1e20 is exactly representable
        assert canonicalize(1e20) == b"100000000000000000000"

    def test_float_max_safe_int(self):
        # 2**53 as float: 9007199254740992
        assert canonicalize(float(2**53)) == b"9007199254740992"

    def test_null(self):
        assert canonicalize(None) == b"null"

    def test_bool_true(self):
        assert canonicalize(True) == b"true"

    def test_bool_false(self):
        assert canonicalize(False) == b"false"

    def test_string(self):
        assert canonicalize("hello") == b'"hello"'

    def test_empty_object(self):
        assert canonicalize({}) == b"{}"

    def test_empty_array(self):
        assert canonicalize([]) == b"[]"

    def test_nested(self):
        result = canonicalize({"z": [3, 1], "a": {"y": 0, "x": 1}})
        assert result == b'{"a":{"x":1,"y":0},"z":[3,1]}'

    def test_unicode_string(self):
        # Unicode must be preserved as-is (no ASCII escaping)
        result = canonicalize({"key": "é"})
        assert result == '{"key":"é"}'.encode("utf-8")


# ---------------------------------------------------------------------------
# AISS-2.1 event canonicalization (signatures + trusted_timestamp excluded)
# ---------------------------------------------------------------------------

class TestAiss21EventCanonicalize:

    def _make_event(self):
        return {
            "version": "AISS-2.1",
            "agent_id": "TestAgent01234567890123456789012",
            "timestamp": 1739382403,
            "nonce": "550e8400-e29b-41d4-a716-446655440000",
            "payload": {"event_type": "test", "value": 42},
            "previous_hash": "abc123",
            "signatures": {"classical": {"signature": "SHOULD_NOT_APPEAR"}},
            "trusted_timestamp": {"status": "pending"},
        }

    def test_signatures_excluded(self):
        event = self._make_event()
        event_for_sign = {k: v for k, v in event.items()
                          if k not in ("signatures", "trusted_timestamp")}
        result = canonicalize(event_for_sign)
        assert b"SHOULD_NOT_APPEAR" not in result
        assert b"pending" not in result

    def test_deterministic(self):
        event = self._make_event()
        stripped = {k: v for k, v in event.items()
                    if k not in ("signatures", "trusted_timestamp")}
        assert canonicalize(stripped) == canonicalize(stripped)

    def test_key_order_matches_rfc8785(self):
        event = {"z_last": 1, "a_first": 2}
        result = canonicalize(event)
        assert result == b'{"a_first":2,"z_last":1}'


# ---------------------------------------------------------------------------
# SHA-512 hash for AISS-2.1 chain
# ---------------------------------------------------------------------------

class TestHashEvent:

    def test_hash_length(self):
        # SHA-512 hex = 128 characters
        h = hash_event({"test": 1})
        assert len(h) == 128

    def test_hash_deterministic(self):
        h1 = hash_event({"a": 1, "b": 2})
        h2 = hash_event({"b": 2, "a": 1})
        assert h1 == h2  # same canonical form -> same hash

    def test_hash_different_inputs(self):
        assert hash_event({"a": 1}) != hash_event({"a": 2})

    def test_hash_known_value(self):
        import hashlib
        obj = {"hello": "world"}
        expected = hashlib.sha512(b'{"hello":"world"}').hexdigest()
        assert hash_event(obj) == expected


# ---------------------------------------------------------------------------
# Difference from aiss.canonical (AISS-1 path — must NOT match on floats)
# ---------------------------------------------------------------------------

class TestDifferenceFromAiss1Canonical:

    def test_float_1_0_differs_from_aiss1(self):
        from aiss.canonical import canonicalize as c1
        # AISS-1 canonical.py: 1.0 -> "1.0"   (stdlib repr, non-conformant)
        # AISS-2.1 rfc8785:    1.0 -> "1"      (RFC 8785 conformant)
        aiss1_result = c1(1.0)
        aiss21_result = canonicalize(1.0)
        assert aiss1_result != aiss21_result
        assert aiss21_result == b"1"
