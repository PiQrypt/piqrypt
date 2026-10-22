"""
ML-DSA-65 NIST ACVP tests (FIPS 204).

Vectors from usnistgov/ACVP-Server, branch master (vsId 42), accessed 2026-10-21.
Source: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/
License: NIST public domain (17 U.S.C. § 105 — US Government work).
  "NIST-developed software is provided by NIST as a public service.
   You may use, copy, and distribute copies of the software in any medium,
   provided that you keep intact this entire notice."

Tests:
  - keyGen (tgId=2): seed → (pk, sk) full byte comparison, 25 vectors.
  - sigVer external/pure (tgId=3): verify(pk, msg, sig, ctx), 15 vectors,
    3 passing (tcId 33, 43, 44), 12 failing.
  - sigVer internal, externalMu=False (tgId=10): _verify_internal(pk, M', σ),
    15 vectors, 3 passing (tcId 143, 146, 150), 12 failing, messages non-empty.
    (tgId=9 was externalMu=True — M'=μ — that is a different API level.)
"""

import json
import pytest
from pathlib import Path

_VECTORS_DIR = Path(__file__).parent / "vectors_nist"
_KEYGEN_FILE = _VECTORS_DIR / "ml_dsa_65_keyGen.json"
_SIGVER_FILE = _VECTORS_DIR / "ml_dsa_65_sigVer.json"


def _skip_if_unavailable():
    try:
        from dilithium_py.ml_dsa import ML_DSA_65  # noqa: F401
    except ImportError:
        pytest.skip("dilithium-py not installed")


def _ml_dsa():
    from dilithium_py.ml_dsa import ML_DSA_65
    return ML_DSA_65


# ---------------------------------------------------------------------------
# 1. keyGen — seed → (pk, sk) full comparison
# ---------------------------------------------------------------------------

class TestKeyGenNIST:
    """NIST ACVP keyGen: given seed, pk and sk must match exactly."""

    def _load(self):
        if not _KEYGEN_FILE.exists():
            pytest.skip(f"Vector file not found: {_KEYGEN_FILE}")
        with open(_KEYGEN_FILE, encoding="utf-8") as f:
            return json.load(f)["tests"]

    def test_keygen_pk_matches_nist(self):
        _skip_if_unavailable()
        ml = _ml_dsa()
        for vec in self._load():
            seed = bytes.fromhex(vec["seed"])
            expected_pk = bytes.fromhex(vec["pk"])
            pk, _ = ml.key_derive(seed)
            assert pk == expected_pk, (
                f"tcId={vec['tcId']}: pk mismatch\n"
                f"  got  {pk.hex()[:32]}...\n"
                f"  want {vec['pk'][:32]}..."
            )

    def test_keygen_sk_matches_nist(self):
        _skip_if_unavailable()
        ml = _ml_dsa()
        for vec in self._load():
            seed = bytes.fromhex(vec["seed"])
            expected_sk = bytes.fromhex(vec["sk"])
            _, sk = ml.key_derive(seed)
            assert sk == expected_sk, (
                f"tcId={vec['tcId']}: sk mismatch\n"
                f"  got  {sk.hex()[:32]}...\n"
                f"  want {vec['sk'][:32]}..."
            )

    def test_keygen_pk_size(self):
        _skip_if_unavailable()
        ml = _ml_dsa()
        for vec in self._load():
            seed = bytes.fromhex(vec["seed"])
            pk, _ = ml.key_derive(seed)
            assert len(pk) == 1952, f"tcId={vec['tcId']}: pk size {len(pk)} != 1952"

    def test_keygen_sk_size(self):
        _skip_if_unavailable()
        ml = _ml_dsa()
        for vec in self._load():
            seed = bytes.fromhex(vec["seed"])
            _, sk = ml.key_derive(seed)
            assert len(sk) == 4032, f"tcId={vec['tcId']}: sk size {len(sk)} != 4032"


# ---------------------------------------------------------------------------
# 2. sigVer external/pure — verify(pk, msg, sig, ctx=context)
# ---------------------------------------------------------------------------

class TestSigVerExternalNIST:
    """NIST ACVP sigVer tgId=3: ML-DSA-65, external interface, pure (no preHash)."""

    def _load_external(self):
        if not _SIGVER_FILE.exists():
            pytest.skip(f"Vector file not found: {_SIGVER_FILE}")
        with open(_SIGVER_FILE, encoding="utf-8") as f:
            data = json.load(f)["tests"]
        return [t for t in data if t["tgId"] == 3]

    def test_external_pass_cases_verify_true(self):
        """All testPassed=True must return True from verify."""
        _skip_if_unavailable()
        ml = _ml_dsa()
        passing = [t for t in self._load_external() if t["testPassed"]]
        assert len(passing) > 0, "No passing external-pure sigVer vectors found"
        for vec in passing:
            pk = bytes.fromhex(vec["pk"])
            msg = bytes.fromhex(vec["message"])
            ctx = bytes.fromhex(vec.get("context", ""))
            sig = bytes.fromhex(vec["signature"])
            result = ml.verify(pk, msg, sig, ctx)
            assert result is True, (
                f"tcId={vec['tcId']}: expected True but got {result}"
            )

    def test_external_fail_cases_verify_false(self):
        """All testPassed=False must return False from verify."""
        _skip_if_unavailable()
        ml = _ml_dsa()
        failing = [t for t in self._load_external() if not t["testPassed"]]
        assert len(failing) > 0, "No failing external-pure sigVer vectors found"
        for vec in failing:
            pk = bytes.fromhex(vec["pk"])
            msg = bytes.fromhex(vec["message"])
            ctx = bytes.fromhex(vec.get("context", ""))
            sig = bytes.fromhex(vec["signature"])
            result = ml.verify(pk, msg, sig, ctx)
            assert result is False, (
                f"tcId={vec['tcId']}: expected False but got {result}"
            )


# ---------------------------------------------------------------------------
# 3. sigVer internal — _verify_internal(pk, msg, sig)
# ---------------------------------------------------------------------------

class TestSigVerInternalNIST:
    """NIST ACVP sigVer tgId=10: ML-DSA-65, internal interface, externalMu=False.

    tgId=10 uses ML-DSA.VerifyInternal(pk, M', σ) where M' is a non-empty message
    (up to ~6500 bytes), not the μ hash. This is the correct internal-interface group.
    dilithium-py 1.5.1+ passes all 15/15 cases.

    (tgId=9 was externalMu=True — it passes M'=μ, 64-byte hash — different API.)
    """

    _EXPECTED_PASS_COUNT = 3   # tcId 143, 146, 150
    _EXPECTED_FAIL_COUNT = 12

    def _load_internal(self):
        if not _SIGVER_FILE.exists():
            pytest.skip(f"Vector file not found: {_SIGVER_FILE}")
        with open(_SIGVER_FILE, encoding="utf-8") as f:
            data = json.load(f)["tests"]
        tests = [t for t in data if t["tgId"] == 10]
        assert len(tests) == 15, f"Expected 15 tgId=10 tests, got {len(tests)}"
        return tests

    def test_internal_pass_cases_verify_true(self):
        """All testPassed=True must return True from _verify_internal (tcId 143, 146, 150)."""
        _skip_if_unavailable()
        ml = _ml_dsa()
        passing = [t for t in self._load_internal() if t["testPassed"]]
        assert len(passing) == self._EXPECTED_PASS_COUNT, (
            f"Expected {self._EXPECTED_PASS_COUNT} passing vectors, got {len(passing)}"
        )
        for vec in passing:
            msg = bytes.fromhex(vec["message"])
            assert len(msg) > 0, f"tcId={vec['tcId']}: message must be non-empty for tgId=10"
            pk = bytes.fromhex(vec["pk"])
            sig = bytes.fromhex(vec["signature"])
            result = ml._verify_internal(pk, msg, sig)
            assert result is True, (
                f"tcId={vec['tcId']}: expected True but got {result}"
            )

    def test_internal_fail_cases_verify_false(self):
        """All testPassed=False must return False from _verify_internal."""
        _skip_if_unavailable()
        ml = _ml_dsa()
        failing = [t for t in self._load_internal() if not t["testPassed"]]
        assert len(failing) == self._EXPECTED_FAIL_COUNT, (
            f"Expected {self._EXPECTED_FAIL_COUNT} failing vectors, got {len(failing)}"
        )
        for vec in failing:
            pk = bytes.fromhex(vec["pk"])
            msg = bytes.fromhex(vec["message"])
            sig = bytes.fromhex(vec["signature"])
            result = ml._verify_internal(pk, msg, sig)
            assert result is False, (
                f"tcId={vec['tcId']}: expected False but got {result}"
            )
