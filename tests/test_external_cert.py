"""
Test External Certification — v1.3.0
Vérifie : workflow complet user → PiQrypt → user
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
from aiss.external_cert import (
    create_certification_request,
    validate_and_certify,
    verify_piqrypt_certification,
    CertificationError
)
from aiss.exports import export_audit_chain, certify_export
from aiss.license import activate_license, deactivate_license


def test_certification_workflow():
    """Test complet : request → validate → verify"""
    
    activate_license("pk_pro_test123_2423cdc1")
    
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # ── Step 1: User crée un export certifié ──────────────────────
            print("\n[USER] Creating certified export...")
            
            priv, pub = aiss.generate_keypair()
            agent_id = aiss.derive_agent_id(pub)
            identity = aiss.export_identity(agent_id, pub)
            
            events = [aiss.stamp_event(priv, agent_id, {"test": i}) for i in range(5)]
            
            # Export audit
            audit = export_audit_chain(identity, events)
            audit_path = tmpdir / "audit.json"
            audit_path.write_text(json.dumps(audit, indent=2))
            
            # Certify locally
            cert_path = certify_export(str(audit_path), priv, agent_id)
            
            print(f"✓ audit.json created")
            print(f"✓ audit.json.cert created")
            
            # ── Step 2: User crée certification request ───────────────────
            print("\n[USER] Creating certification request...")
            
            request_zip = create_certification_request(
                str(audit_path),
                cert_path,
                "test@example.com",
                output_dir=str(tmpdir)
            )
            
            print(f"✓ Request ZIP created: {Path(request_zip).name}")
            
            # ── Step 3: PiQrypt valide et certifie ────────────────────────
            print("\n[PIQRYPT] Validating and certifying...")
            
            # Use CA key generated earlier
            ca_key_path = "/home/claude/piqrypt-v1.2.0/piqrypt-ca-private.key"
            
            certified_path = validate_and_certify(
                request_zip,
                ca_key_path,
                output_dir=str(tmpdir)
            )
            
            print(f"✓ Certified export created: {Path(certified_path).name}")
            
            # ── Step 4: User vérifie certification PiQrypt ────────────────
            print("\n[USER] Verifying PiQrypt certification...")
            
            result = verify_piqrypt_certification(certified_path)
            
            assert result["status"] == "valid"
            assert "PIQRYPT-CERT" in result["certificate_id"]
            assert result["certified_by"] == "PiQrypt Inc."
            
            print(f"✓ Certification verified")
            print(f"  Certificate ID: {result['certificate_id']}")
            print(f"  Certified by: {result['certified_by']}")
            
            print("\n✅ Complete workflow successful!")
    
    finally:
        deactivate_license()


def test_certification_cli():
    """Test CLI commands"""
    
    activate_license("pk_pro_test123_2423cdc1")
    
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Create export
            priv, pub = aiss.generate_keypair()
            agent_id = aiss.derive_agent_id(pub)
            identity = aiss.export_identity(agent_id, pub)
            events = [aiss.stamp_event(priv, agent_id, {"test": i}) for i in range(3)]
            
            audit = export_audit_chain(identity, events)
            audit_path = tmpdir / "audit.json"
            audit_path.write_text(json.dumps(audit, indent=2))
            
            cert_path = certify_export(str(audit_path), priv, agent_id)
            
            # Test certify-request CLI
            result = subprocess.run(
                ["python3", "-m", "cli.main", "certify-request",
                 str(audit_path), cert_path, "--email", "test@example.com",
                 "--output-dir", str(tmpdir)],
                cwd="/home/claude/piqrypt-v1.2.0",
                env={**os.environ, "PYTHONPATH": "/home/claude/piqrypt-v1.2.0"},
                capture_output=True,
                text=True,
            )
            
            assert result.returncode == 0
            assert "certification-request-CERT" in result.stdout
            print("✓ CLI certify-request OK")
            
            # Find request zip
            request_zips = list(tmpdir.glob("certification-request-*.zip"))
            assert len(request_zips) == 1
            request_zip = request_zips[0]
            
            # Validate with script
            ca_key_path = "/home/claude/piqrypt-v1.2.0/piqrypt-ca-private.key"
            result = subprocess.run(
                ["python3", "scripts/validate_certification_request.py",
                 str(request_zip), "--ca-key", ca_key_path,
                 "--output-dir", str(tmpdir)],
                cwd="/home/claude/piqrypt-v1.2.0",
                capture_output=True,
                text=True,
            )
            
            assert result.returncode == 0
            assert "CERTIFICATION SUCCESSFUL" in result.stdout
            print("✓ Validation script OK")
            
            # Find certified file
            certified_files = list(tmpdir.glob("*.piqrypt-certified"))
            assert len(certified_files) == 1
            certified_path = certified_files[0]
            
            # Test certify-verify CLI
            result = subprocess.run(
                ["python3", "-m", "cli.main", "certify-verify", str(certified_path)],
                cwd="/home/claude/piqrypt-v1.2.0",
                env={**os.environ, "PYTHONPATH": "/home/claude/piqrypt-v1.2.0"},
                capture_output=True,
                text=True,
            )
            
            assert result.returncode == 0
            assert "Certification VALID" in result.stdout
            print("✓ CLI certify-verify OK")
    
    finally:
        deactivate_license()


if __name__ == "__main__":
    print("=" * 60)
    print("External Certification Tests — v1.3.0")
    print("=" * 60)
    
    try:
        test_certification_workflow()
        print()
        test_certification_cli()
        
        print()
        print("─" * 60)
        print("✅ EXTERNAL CERTIFICATION TESTS PASSED")
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
