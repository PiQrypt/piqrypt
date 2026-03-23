# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Test CLI Certified Export — Sprint 2
Vérifie : piqrypt export --certified + piqrypt verify-export
"""

import sys
import os
import json
import tempfile
import subprocess
from pathlib import Path

sys.path.insert(0, '.')
import aiss


def run_cli(cmd: list) -> tuple:
    """Execute CLI command"""
    result = subprocess.run(
        [sys.executable, "-m", "cli.main"] + cmd,
        cwd=str(Path(__file__).parent.parent),
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parent.parent)},
        capture_output=True,
        text=True,
    )
    return result.stdout, result.stderr, result.returncode


def test_certified_export_and_verify(tmpdir):
    """Test: certify_export + verify_certified_export (direct Python)"""
    from aiss.exports import export_audit_chain, certify_export, verify_certified_export
    from aiss.license import activate_license, deactivate_license

    # Create identity
    priv, pub = aiss.generate_keypair()
    agent_id = aiss.derive_agent_id(pub)
    identity = aiss.export_identity(agent_id, pub)

    # Create some events
    events = []
    prev_hash = None
    for i in range(5):
        e = aiss.stamp_event(priv, agent_id, {"action": f"test_{i}"}, previous_hash=prev_hash)
        from aiss.chain import compute_event_hash
        prev_hash = compute_event_hash(e)
        events.append(e)

    # Export audit
    audit = export_audit_chain(identity, events)
    audit_file = Path(tmpdir) / "audit.json"
    audit_file.write_text(json.dumps(audit, indent=2))
    print("✓ export_audit_chain OK")

    # Certify export (Pro required)
    import pytest
    pytest.skip("Pro license required — run with real dev token")

    try:
        cert_path = certify_export(str(audit_file), priv, agent_id)
        assert Path(cert_path).exists()
        assert cert_path == str(audit_file) + ".cert"
        print("✓ certify_export OK")

        # Verify certified export
        is_valid = verify_certified_export(str(audit_file), cert_path)
        assert is_valid
        print("✓ verify_certified_export OK")

    finally:
        deactivate_license()

    # Test CLI verify-export
    stdout, stderr, code = run_cli([
        "verify-export",
        str(audit_file),
        cert_path,
    ])

    assert code == 0, f"CLI verify-export failed: {stderr}\n{stdout}"
    assert "VALID" in stdout
    print("✓ piqrypt verify-export (CLI) OK")


if __name__ == "__main__":
    print("=" * 60)
    print("CLI Certified Export Tests — Sprint 2")
    print("=" * 60)
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            test_certified_export_and_verify(tmpdir)

            print()
            print("─" * 60)
            print("✅ CLI CERTIFIED EXPORT TESTS PASSED")
        except AssertionError as e:
            print(f"\n❌ Test failed: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
