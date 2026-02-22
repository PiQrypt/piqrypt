"""
Tests — Sprint 1-A
Authority Binding Layer (RFC §5) + Canonical History Rule (RFC §6)
"""

import sys
import time
sys.path.insert(0, '.')

import aiss
from aiss.authority import (
    create_authority_statement,
    verify_authority_statement,
    build_authority_chain,
    validate_authority_chain,
    get_accountable_authority,
    annotate_event_with_authority,
    RESULT_VALID_AUTHORIZED,
    RESULT_VALID_UNAUTHORIZED,
    AuthorityExpiredError,
    AuthorityScopeError,
)
from aiss.fork import (
    select_canonical_chain,
    resolve_fork_canonical,
    ForkAfterFinalizationError,
    STATUS_FORK_DETECTED,
    STATUS_FORK_AFTER_FINALIZATION,
)
from aiss import generate_keypair, derive_agent_id, stamp_event
from aiss.chain import compute_event_hash


def make_chain(n_events: int = 3):
    """Helper: create a chain of n events."""
    priv, pub = generate_keypair()
    agent_id = derive_agent_id(pub)
    events = []
    prev_hash = None
    for i in range(n_events):
        e = stamp_event(priv, agent_id, {"seq": i}, previous_hash=prev_hash)
        prev_hash = compute_event_hash(e)
        events.append(e)
    return events, pub


# ─── Authority Binding Tests ──────────────────────────────────────────────────

def test_create_authority_statement():
    priv, pub = generate_keypair()
    agent_id = derive_agent_id(pub)
    stmt = create_authority_statement(
        priv, "acme_corp", agent_id,
        scope=["execute_order", "read_data"],
        validity_days=30,
    )
    assert stmt["issuer_id"] == "acme_corp"
    assert stmt["subject_id"] == agent_id
    assert "execute_order" in stmt["scope"]
    assert "signature" in stmt
    print("✓ create_authority_statement")


def test_verify_authority_statement_valid():
    priv, pub = generate_keypair()
    agent_id = derive_agent_id(pub)
    stmt = create_authority_statement(priv, "corp", agent_id, ["trade"])
    result = verify_authority_statement(stmt, pub, requested_action="trade")
    assert result is True
    print("✓ verify_authority_statement (valid)")


def test_verify_authority_statement_wrong_action():
    priv, pub = generate_keypair()
    agent_id = derive_agent_id(pub)
    stmt = create_authority_statement(priv, "corp", agent_id, ["read_only"])
    try:
        verify_authority_statement(stmt, pub, requested_action="execute_order")
        assert False, "Should have raised"
    except AuthorityScopeError:
        pass
    print("✓ verify_authority_statement (scope error)")


def test_verify_authority_statement_expired():
    priv, pub = generate_keypair()
    agent_id = derive_agent_id(pub)
    stmt = create_authority_statement(priv, "corp", agent_id, ["trade"], validity_days=1)
    # Check at a timestamp in the past
    try:
        verify_authority_statement(stmt, pub, at_timestamp=1000)  # Year 1970
        assert False, "Should have raised"
    except AuthorityExpiredError:
        pass
    print("✓ verify_authority_statement (expired)")


def test_validate_authority_chain_valid():
    priv_corp, pub_corp = generate_keypair()
    priv_system, pub_system = generate_keypair()
    priv_agent, pub_agent = generate_keypair()
    
    corp_id = "acme_corp"
    system_id = derive_agent_id(pub_system)
    agent_id = derive_agent_id(pub_agent)

    # Corp → System
    stmt1 = create_authority_statement(priv_corp, corp_id, system_id, ["operate"])
    # System → Agent
    stmt2 = create_authority_statement(priv_system, system_id, agent_id, ["execute_order"])

    chain = [stmt1, stmt2]
    public_keys = {
        corp_id: pub_corp,
        system_id: pub_system,
    }

    result, errors = validate_authority_chain(
        chain, public_keys, requested_action="execute_order"
    )
    assert result == RESULT_VALID_AUTHORIZED, f"Errors: {errors}"
    assert get_accountable_authority(chain) == corp_id
    print("✓ validate_authority_chain (2-level, valid)")


def test_validate_authority_chain_missing_key():
    priv, pub = generate_keypair()
    agent_id = derive_agent_id(pub)
    stmt = create_authority_statement(priv, "unknown_corp", agent_id, ["trade"])
    
    result, errors = validate_authority_chain([stmt], {})  # No public keys
    assert result == RESULT_VALID_UNAUTHORIZED
    assert len(errors) > 0
    print("✓ validate_authority_chain (missing key → VALID_UNAUTHORIZED)")


# ─── Canonical History Rule Tests ─────────────────────────────────────────────

def test_select_canonical_chain_longest():
    """Step 3: Longest chain wins (no TSA anchors)."""
    short_chain, _ = make_chain(2)
    long_chain, _ = make_chain(5)
    
    canonical, _ = select_canonical_chain([short_chain, long_chain])
    assert len(canonical) == 5
    print("✓ select_canonical_chain (longest wins)")


def test_select_canonical_chain_deterministic():
    """Step 4: Tie-breaker is deterministic (same result every call)."""
    chain_a, _ = make_chain(3)
    chain_b, _ = make_chain(3)
    
    result1, _ = select_canonical_chain([chain_a, chain_b])
    result2, _ = select_canonical_chain([chain_a, chain_b])
    result3, _ = select_canonical_chain([chain_b, chain_a])  # Reversed order
    
    # Must be same result regardless of input order
    hash1 = compute_event_hash(result1[-1])
    hash2 = compute_event_hash(result2[-1])
    hash3 = compute_event_hash(result3[-1])
    
    assert hash1 == hash2 == hash3, "Result must be deterministic"
    print("✓ select_canonical_chain (deterministic tie-breaker)")


def test_select_canonical_chain_tsa_wins():
    """Step 1: Chain with TSA-anchored event wins over longer chain."""
    short_chain, _ = make_chain(2)
    long_chain, _ = make_chain(5)
    
    # Add TSA anchor to short chain
    short_chain[1]["trusted_timestamp"] = {
        "rfc3161_token": "FAKE_TOKEN_FOR_TEST",
        "tsa_id": "freetsa.org",
        "timestamp": int(time.time()),
    }
    
    canonical, _ = select_canonical_chain([long_chain, short_chain])
    assert len(canonical) == 2  # Short but anchored wins
    print("✓ select_canonical_chain (TSA-anchored beats longer)")


def test_resolve_fork_canonical_standard():
    """Standard fork — should resolve without exception."""
    chain_a, _ = make_chain(3)
    chain_b, _ = make_chain(2)
    
    result = resolve_fork_canonical([chain_a, chain_b], raise_on_security_incident=False)
    assert "canonical_chain" in result
    assert result["status"] == STATUS_FORK_DETECTED
    print("✓ resolve_fork_canonical (standard fork)")


def test_single_chain_no_fork():
    """Single chain → no selection needed."""
    chain, _ = make_chain(4)
    canonical, others = select_canonical_chain([chain])
    assert canonical == chain
    assert others == []
    print("✓ select_canonical_chain (single chain, no-op)")


# ─── Authority + Event Annotation ─────────────────────────────────────────────

def test_annotate_event_with_authority():
    priv_corp, pub_corp = generate_keypair()
    priv_agent, pub_agent = generate_keypair()
    agent_id = derive_agent_id(pub_agent)
    
    stmt = create_authority_statement(priv_corp, "corp", agent_id, ["trade"])
    event = stamp_event(priv_agent, agent_id, {"action": "buy"})
    
    annotated = annotate_event_with_authority(event, [stmt])
    assert "authority_chain" in annotated
    assert len(annotated["authority_chain"]) == 1
    print("✓ annotate_event_with_authority")


# ─── Run all ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_create_authority_statement,
        test_verify_authority_statement_valid,
        test_verify_authority_statement_wrong_action,
        test_verify_authority_statement_expired,
        test_validate_authority_chain_valid,
        test_validate_authority_chain_missing_key,
        test_select_canonical_chain_longest,
        test_select_canonical_chain_deterministic,
        test_select_canonical_chain_tsa_wins,
        test_resolve_fork_canonical_standard,
        test_single_chain_no_fork,
        test_annotate_event_with_authority,
    ]
    
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"✗ {test.__name__}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print(f"\n{'─'*50}")
    print(f"Sprint 1-A: {passed} passed, {failed} failed")
    if failed == 0:
        print("✅ ALL TESTS PASSED")
    else:
        print("❌ FAILURES — review above")
        sys.exit(1)
