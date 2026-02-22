"""
Test CLI Authority — Sprint 1-B
Vérifie les commandes : piqrypt authority create/verify/chain
"""

import sys
import os
import json
import tempfile
import subprocess
from pathlib import Path

sys.path.insert(0, '.')
import aiss
from aiss.crypto import ed25519


def run_cli(cmd: list) -> tuple:
    """Execute CLI command, return (stdout, stderr, returncode)"""
    result = subprocess.run(
        ["python3", "-m", "cli.main"] + cmd,
        cwd="/home/claude/piqrypt-v1.2.0",
        env={**os.environ, "PYTHONPATH": "/home/claude/piqrypt-v1.2.0"},
        capture_output=True,
        text=True,
    )
    return result.stdout, result.stderr, result.returncode


def test_authority_create(tmpdir):
    """Test: piqrypt authority create"""
    # Create issuer identity
    priv, pub = aiss.generate_keypair()
    agent_id = aiss.derive_agent_id(pub)
    identity = aiss.export_identity(agent_id, pub)
    issuer_file = Path(tmpdir) / "issuer.json"
    issuer_file.write_text(json.dumps({
        "identity": identity,
        "private_key": ed25519.encode_base64(priv),
    }))
    
    # Create subject identity
    _, pub_subj = aiss.generate_keypair()
    subject_id = aiss.derive_agent_id(pub_subj)
    
    # Run: piqrypt authority create
    stmt_file = Path(tmpdir) / "authority.json"
    stdout, stderr, code = run_cli([
        "authority", "create",
        str(issuer_file),
        subject_id,
        "--scope", "execute_order", "read_data",
        "--days", "30",
        "--output", str(stmt_file),
    ])
    
    assert code == 0, f"CLI failed: {stderr}"
    assert stmt_file.exists()
    
    stmt = json.loads(stmt_file.read_text())
    assert stmt["issuer_id"] == agent_id
    assert stmt["subject_id"] == subject_id
    assert "execute_order" in stmt["scope"]
    assert "signature" in stmt
    
    print("✓ piqrypt authority create OK")
    return issuer_file, stmt_file, subject_id


def test_authority_verify(issuer_file, stmt_file):
    """Test: piqrypt authority verify"""
    stdout, stderr, code = run_cli([
        "authority", "verify",
        str(stmt_file),
        str(issuer_file),
        "--action", "execute_order",
    ])
    
    assert code == 0, f"Verify failed: {stderr}"
    assert "VALID" in stdout
    assert "authorized" in stdout.lower()
    
    print("✓ piqrypt authority verify OK")


def test_authority_chain(tmpdir):
    """Test: piqrypt authority chain (2-level)"""
    # Level 1: Corp → System
    priv_corp, pub_corp = aiss.generate_keypair()
    corp_id = "acme_corp"
    
    priv_sys, pub_sys = aiss.generate_keypair()
    sys_id = aiss.derive_agent_id(pub_sys)
    
    stmt1 = aiss.create_authority_statement(
        priv_corp, corp_id, sys_id, ["operate"], validity_days=365
    )
    stmt1_file = Path(tmpdir) / "stmt1.json"
    stmt1_file.write_text(json.dumps(stmt1))
    
    # Level 2: System → Agent
    priv_agent, pub_agent = aiss.generate_keypair()
    agent_id = aiss.derive_agent_id(pub_agent)
    
    stmt2 = aiss.create_authority_statement(
        priv_sys, sys_id, agent_id, ["execute_order"], validity_days=30
    )
    stmt2_file = Path(tmpdir) / "stmt2.json"
    stmt2_file.write_text(json.dumps(stmt2))
    
    # Pubkeys file
    pubkeys = {
        corp_id: {
            "identity": {
                "agent_id": corp_id,
                "public_key": ed25519.encode_base64(pub_corp),
            }
        },
        sys_id: {
            "identity": {
                "agent_id": sys_id,
                "public_key": ed25519.encode_base64(pub_sys),
            }
        },
    }
    pubkeys_file = Path(tmpdir) / "pubkeys.json"
    pubkeys_file.write_text(json.dumps(pubkeys))
    
    # Run: piqrypt authority chain
    stdout, stderr, code = run_cli([
        "authority", "chain",
        str(stmt1_file), str(stmt2_file),
        "--pubkeys", str(pubkeys_file),
        "--action", "execute_order",
    ])
    
    assert code == 0, f"Chain validation failed: {stderr}"
    assert "VALID_AUTHORIZED" in stdout or "VALID and AUTHORIZED" in stdout
    assert corp_id in stdout  # Accountable authority
    
    print("✓ piqrypt authority chain OK (2-level)")


if __name__ == "__main__":
    print("=" * 60)
    print("CLI Authority Tests — Sprint 1-B")
    print("=" * 60)
    print()
    
    # Use a single tmpdir for all tests
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            issuer_f, stmt_f, subj_id = test_authority_create(tmpdir)
            test_authority_verify(issuer_f, stmt_f)
            test_authority_chain(tmpdir)
            
            print()
            print("─" * 60)
            print("✅ CLI AUTHORITY TESTS PASSED")
        except AssertionError as e:
            print(f"\n❌ Test failed: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
