"""
ML-DSA-65 regression tests (FIPS 204) — self-generated vectors.

These vectors are generated deterministically from dilithium-py >= 1.0.0
using ML-DSA.KeyGen_internal (key_derive) and ML-DSA.Sign with rnd = 0^32
(Algorithm 2 FIPS 204 with explicit zero randomness).

PURPOSE: regression — detect accidental code changes that break the current
implementation. They do NOT detect bugs in dilithium-py itself, because the
expected values are produced by the same library.
For independent reference verification, see tests/test_nist_acvp_ml_dsa.py
which uses official NIST ACVP vectors from usnistgov/ACVP-Server.

Source: dilithium-py ML_DSA_65, MIT license, https://github.com/GiacomoPope/dilithium-py
"""

import pytest

# ---------------------------------------------------------------------------
# FIPS 204 size constants
# ---------------------------------------------------------------------------
PK_SIZE = 1952   # bytes
SK_SIZE = 4032   # bytes
SIG_SIZE = 3309  # bytes


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _skip_if_unavailable():
    try:
        from dilithium_py.ml_dsa import ML_DSA_65  # noqa: F401
    except ImportError:
        pytest.skip("dilithium-py not installed")


def _ml_dsa():
    from dilithium_py.ml_dsa import ML_DSA_65
    return ML_DSA_65


# ---------------------------------------------------------------------------
# Deterministic reference vectors (generated once, frozen here)
# seed = 0x000102...1f  (32 bytes, sequential)
# ---------------------------------------------------------------------------
_SEED = bytes(range(32))
_MSG = b"AISS-2.1 test vector"

# Expected values — regenerate with:
#   from dilithium_py.ml_dsa import ML_DSA_65
#   pk, sk = ML_DSA_65.key_derive(bytes(range(32)))
#   sig = ML_DSA_65.sign(sk, b"AISS-2.1 test vector", deterministic=True)
_EXPECTED_PK_PREFIX = bytes.fromhex("48683d91978e31eb")
_EXPECTED_SIG_PREFIX = bytes.fromhex("0fe4b3c8735b93d8")

# Zero-seed vector
_SEED_ZERO = bytes(32)
_EXPECTED_ZERO_PK_PREFIX = bytes.fromhex("424b2f267e58d5b3")


# ---------------------------------------------------------------------------
# 1. Key sizes (FIPS 204 §4 Table 1)
# ---------------------------------------------------------------------------

class TestKeyGen:

    def test_pk_size(self):
        _skip_if_unavailable()
        ml = _ml_dsa()
        pk, sk = ml.key_derive(_SEED)
        assert len(pk) == PK_SIZE, f"pk size {len(pk)} != {PK_SIZE}"

    def test_sk_size(self):
        _skip_if_unavailable()
        ml = _ml_dsa()
        pk, sk = ml.key_derive(_SEED)
        assert len(sk) == SK_SIZE, f"sk size {len(sk)} != {SK_SIZE}"

    def test_keygen_deterministic_from_seed(self):
        """Same seed must always produce the same pk."""
        _skip_if_unavailable()
        ml = _ml_dsa()
        pk1, _ = ml.key_derive(_SEED)
        pk2, _ = ml.key_derive(_SEED)
        assert pk1 == pk2

    def test_keygen_prefix_matches_vector(self):
        """Regression: pk prefix must match stored reference."""
        _skip_if_unavailable()
        ml = _ml_dsa()
        pk, _ = ml.key_derive(_SEED)
        assert pk[:8] == _EXPECTED_PK_PREFIX

    def test_zero_seed_keygen_prefix(self):
        _skip_if_unavailable()
        ml = _ml_dsa()
        pk, _ = ml.key_derive(_SEED_ZERO)
        assert pk[:8] == _EXPECTED_ZERO_PK_PREFIX

    def test_distinct_seeds_give_distinct_keys(self):
        _skip_if_unavailable()
        ml = _ml_dsa()
        pk1, _ = ml.key_derive(_SEED)
        pk2, _ = ml.key_derive(_SEED_ZERO)
        assert pk1 != pk2


# ---------------------------------------------------------------------------
# 2. Signature generation (sigGen)
# ---------------------------------------------------------------------------

class TestSigGen:

    def test_sig_size_deterministic(self):
        """Internal sigGen (rnd = 0^32): signature size must be 3309 bytes."""
        _skip_if_unavailable()
        ml = _ml_dsa()
        _, sk = ml.key_derive(_SEED)
        sig = ml.sign(sk, _MSG, deterministic=True)
        assert len(sig) == SIG_SIZE, f"sig size {len(sig)} != {SIG_SIZE}"

    def test_sig_deterministic_reproducible(self):
        """Same sk + msg + rnd=0^32 must always produce the same signature."""
        _skip_if_unavailable()
        ml = _ml_dsa()
        _, sk = ml.key_derive(_SEED)
        sig1 = ml.sign(sk, _MSG, deterministic=True)
        sig2 = ml.sign(sk, _MSG, deterministic=True)
        assert sig1 == sig2

    def test_sig_prefix_matches_vector(self):
        """Regression: sig prefix must match stored reference."""
        _skip_if_unavailable()
        ml = _ml_dsa()
        _, sk = ml.key_derive(_SEED)
        sig = ml.sign(sk, _MSG, deterministic=True)
        assert sig[:8] == _EXPECTED_SIG_PREFIX

    def test_sig_size_randomized(self):
        """External sigGen (rnd from OS): signature size must still be 3309 bytes."""
        _skip_if_unavailable()
        ml = _ml_dsa()
        _, sk = ml.key_derive(_SEED)
        sig = ml.sign(sk, _MSG, deterministic=False)
        assert len(sig) == SIG_SIZE


# ---------------------------------------------------------------------------
# 3. Signature verification (sigVer)
# ---------------------------------------------------------------------------

class TestSigVer:

    def test_verify_valid(self):
        _skip_if_unavailable()
        ml = _ml_dsa()
        pk, sk = ml.key_derive(_SEED)
        sig = ml.sign(sk, _MSG, deterministic=True)
        assert ml.verify(pk, _MSG, sig) is True

    def test_verify_wrong_message(self):
        _skip_if_unavailable()
        ml = _ml_dsa()
        pk, sk = ml.key_derive(_SEED)
        sig = ml.sign(sk, _MSG, deterministic=True)
        assert ml.verify(pk, b"wrong message", sig) is False

    def test_verify_tampered_sig(self):
        _skip_if_unavailable()
        ml = _ml_dsa()
        pk, sk = ml.key_derive(_SEED)
        sig = bytearray(ml.sign(sk, _MSG, deterministic=True))
        sig[0] ^= 0xFF
        assert ml.verify(pk, _MSG, bytes(sig)) is False

    def test_verify_wrong_pk(self):
        _skip_if_unavailable()
        ml = _ml_dsa()
        pk1, sk1 = ml.key_derive(_SEED)
        pk2, _   = ml.key_derive(_SEED_ZERO)
        sig = ml.sign(sk1, _MSG, deterministic=True)
        assert ml.verify(pk2, _MSG, sig) is False

    def test_verify_empty_message(self):
        """Empty message must be signable and verifiable."""
        _skip_if_unavailable()
        ml = _ml_dsa()
        pk, sk = ml.key_derive(_SEED)
        sig = ml.sign(sk, b"", deterministic=True)
        assert ml.verify(pk, b"", sig) is True
        assert ml.verify(pk, b"not empty", sig) is False


# ---------------------------------------------------------------------------
# 4. Cross-backend: dilithium-py sign -> aiss.crypto.dilithium.verify
# ---------------------------------------------------------------------------

class TestCrossBackend:
    """
    Verify interoperability between dilithium-py and the aiss backend.
    Both must produce and accept the same ML-DSA-65 key/sig bytes.
    """

    def test_dilithium_py_sign_aiss_verify(self):
        """Sign with dilithium-py, verify via aiss.crypto.dilithium."""
        _skip_if_unavailable()
        from aiss.crypto import dilithium as aiss_dil
        if not aiss_dil.is_available():
            pytest.skip("aiss ML-DSA-65 backend not available")
        ml = _ml_dsa()
        pk, sk = ml.key_derive(_SEED)
        sig = ml.sign(sk, _MSG, deterministic=True)
        assert aiss_dil.verify(pk, _MSG, sig) is True

    def test_aiss_sign_dilithium_py_verify(self):
        """Sign with aiss.crypto.dilithium, verify via dilithium-py."""
        _skip_if_unavailable()
        from aiss.crypto import dilithium as aiss_dil
        if not aiss_dil.is_available():
            pytest.skip("aiss ML-DSA-65 backend not available")
        ml = _ml_dsa()
        pk_ref, sk_ref = ml.key_derive(_SEED)
        # Use aiss backend to sign (may use liboqs or dilithium-py internally)
        # We generate a fresh keypair via aiss (non-deterministic)
        sk_aiss, pk_aiss = aiss_dil.generate_keypair()
        sig_aiss = aiss_dil.sign(sk_aiss, _MSG)
        assert ml.verify(pk_aiss, _MSG, sig_aiss) is True

    def test_key_sizes_via_aiss_backend(self):
        """aiss.crypto.dilithium must generate FIPS 204-sized keys."""
        _skip_if_unavailable()
        from aiss.crypto import dilithium as aiss_dil
        if not aiss_dil.is_available():
            pytest.skip("aiss ML-DSA-65 backend not available")
        sk, pk = aiss_dil.generate_keypair()
        assert len(pk) == PK_SIZE
        assert len(sk) == SK_SIZE
