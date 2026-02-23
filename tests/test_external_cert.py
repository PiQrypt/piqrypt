"""
Tests for aiss/external_cert.py — Public Client API

Tests only the user-facing functions:
  - create_certification_request()
  - verify_piqrypt_certification()

Round-trip integration tests simulate the server-side signing inline,
without depending on any private/internal module.
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
    verify_piqrypt_certification,
    CertificationError,
)
from aiss.exports import export_audit_chain, certify_export
from aiss.license import activate_license, deactivate_license

REPO_ROOT = str(Path(__file__).parent.parent)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_audit_and_cert(tmpdir: Path):
    """Create a minimal audit.json + audit.json.cert in tmpdir."""
    priv, pub = ed25519.generate_keypair()
    agent_id = aiss.derive_agent_id(pub)
    identity = aiss.export_identity(agent_id, pub)
    events = [aiss.stamp_event(priv, agent_id, {"i": i}) for i in range(3)]

    audit_data = export_audit_chain(identity, events)
    audit_path = tmpdir / "audit.json"
    audit_path.write_text(json.dumps(audit_data, indent=2))

    cert_path = certify_export(str(audit_path), priv, agent_id)
    return str(audit_path), cert_path


def _temp_ca_key(tmpdir: Path):
    """Generate a throw-away CA keypair and write the private key file.
    Returns (key_file_path, public_key_bytes, ca_id).
    """
    ca_priv, ca_pub = ed25519.generate_keypair()
    ca_id = "piqrypt-ca-test"
    ca_data = {
        "ca_id": ca_id,
        "private_key": ed25519.encode_base64(ca_priv),
        "public_key": ed25519.encode_base64(ca_pub),
    }
    key_path = tmpdir / "ca.key"
    key_path.write_text(json.dumps(ca_data))
    return str(key_path), ca_pub, ca_id


# ─── create_certification_request ─────────────────────────────────────────────

class TestCreateCertificationRequest:

    def test_returns_zip_path(self, tmp_path):
        activate_license("pk_pro_test123_2423cdc1")
        try:
            audit_path, cert_path = _make_audit_and_cert(tmp_path)
            zip_path = create_certification_request(
                audit_path, cert_path, "test@example.com",
                output_dir=str(tmp_path)
            )
            assert Path(zip_path).exists()
            assert zip_path.endswith(".zip")
        finally:
            deactivate_license()

    def test_zip_name_contains_cert_prefix(self, tmp_path):
        activate_license("pk_pro_test123_2423cdc1")
        try:
            audit_path, cert_path = _make_audit_and_cert(tmp_path)
            zip_path = create_certification_request(
                audit_path, cert_path, "test@example.com",
                output_dir=str(tmp_path)
            )
            assert "certification-request-CERT" in Path(zip_path).name
        finally:
            deactivate_license()

    def test_zip_contains_expected_files(self, tmp_path):
        activate_license("pk_pro_test123_2423cdc1")
        try:
            import zipfile as zf
            audit_path, cert_path = _make_audit_and_cert(tmp_path)
            zip_path = create_certification_request(
                audit_path, cert_path, "test@example.com",
                output_dir=str(tmp_path)
            )
            with zf.ZipFile(zip_path) as z:
                names = z.namelist()
            assert "audit.json" in names
            assert "audit.json.cert" in names
            assert "request.json" in names
        finally:
            deactivate_license()

    def test_request_json_contains_email(self, tmp_path):
        activate_license("pk_pro_test123_2423cdc1")
        try:
            import zipfile as zf
            audit_path, cert_path = _make_audit_and_cert(tmp_path)
            zip_path = create_certification_request(
                audit_path, cert_path, "alice@company.com",
                output_dir=str(tmp_path)
            )
            with zf.ZipFile(zip_path) as z:
                meta = json.loads(z.read("request.json"))
            assert meta["user_email"] == "alice@company.com"
        finally:
            deactivate_license()

    def test_missing_audit_raises(self, tmp_path):
        activate_license("pk_pro_test123_2423cdc1")
        try:
            import pytest
            with pytest.raises(CertificationError, match="Audit file not found"):
                create_certification_request(
                    str(tmp_path / "nope.json"),
                    str(tmp_path / "nope.cert"),
                    "x@x.com",
                )
        finally:
            deactivate_license()


# ─── verify_piqrypt_certification ─────────────────────────────────────────────

class TestVerifyPiqryptCertification:
    """Full round-trip: create request → server certifies → user verifies."""

    def _round_trip(self, tmp_path):
        """Helper: full round-trip without depending on the private server module.
        Simulates validate_and_certify() inline so only public API is needed.
        Returns (certified_path_str, ca_pub_bytes, ca_id_str).
        """
        import hashlib, zipfile, uuid
        from datetime import datetime, timezone
        from aiss.crypto import ed25519

        activate_license("pk_pro_test123_2423cdc1")
        try:
            audit_path, cert_path = _make_audit_and_cert(tmp_path)
            zip_path = create_certification_request(
                audit_path, cert_path, "test@example.com",
                output_dir=str(tmp_path)
            )

            # Generate temp CA key
            ca_key_path, ca_pub, ca_id = _temp_ca_key(tmp_path)
            ca_data = json.loads(Path(ca_key_path).read_text())
            ca_private = ed25519.decode_base64(ca_data["private_key"])

            # Extract request ZIP
            with zipfile.ZipFile(zip_path, "r") as zf:
                request_meta = json.loads(zf.read("request.json"))
                audit_data = json.loads(zf.read("audit.json"))
                cert_data = json.loads(zf.read("audit.json.cert"))

            request_id = request_meta["request_id"]
            certificate_id = f"PIQRYPT-{request_id}"
            certified_at = datetime.now(timezone.utc).isoformat()

            attestation = {
                "version": "PIQRYPT-ATTESTATION-1.0",
                "certificate_id": certificate_id,
                "request_id": request_id,
                "certified_at": certified_at,
                "certified_by": "PiQrypt Inc.",
                "ca_id": ca_id,
                "verification_results": {
                    "agent_signature": "valid",
                    "chain_integrity": "valid",
                    "export_hash": "valid",
                    "events_count": len(audit_data.get("events", [])),
                },
                "legal_statement": "PiQrypt Inc. has independently verified this audit.",
            }

            attestation_bytes = json.dumps(attestation, sort_keys=True).encode()
            ca_signature = ed25519.sign(ca_private, attestation_bytes)
            attestation["ca_signature"] = ed25519.encode_base64(ca_signature)

            certified_export = {
                "version": "PIQRYPT-CERTIFIED-1.0",
                "audit": audit_data,
                "agent_certification": cert_data,
                "piqrypt_attestation": attestation,
            }

            output_path = tmp_path / f"audit-{request_id}.piqrypt-certified"
            output_path.write_text(json.dumps(certified_export, indent=2))

            return str(output_path), ca_pub, ca_id
        finally:
            deactivate_license()

    def test_status_is_valid(self, tmp_path):
        certified, ca_pub, ca_id = self._round_trip(tmp_path)
        result = verify_piqrypt_certification(
            certified, ca_public_key=ca_pub, ca_key_id=ca_id
        )
        assert result["status"] == "valid"

    def test_certificate_id_format(self, tmp_path):
        certified, ca_pub, ca_id = self._round_trip(tmp_path)
        result = verify_piqrypt_certification(
            certified, ca_public_key=ca_pub, ca_key_id=ca_id
        )
        assert "PIQRYPT-CERT" in result["certificate_id"]

    def test_certified_by_piqrypt(self, tmp_path):
        certified, ca_pub, ca_id = self._round_trip(tmp_path)
        result = verify_piqrypt_certification(
            certified, ca_public_key=ca_pub, ca_key_id=ca_id
        )
        assert result["certified_by"] == "PiQrypt Inc."

    def test_verification_results_present(self, tmp_path):
        certified, ca_pub, ca_id = self._round_trip(tmp_path)
        result = verify_piqrypt_certification(
            certified, ca_public_key=ca_pub, ca_key_id=ca_id
        )
        vr = result["verification_results"]
        assert vr["agent_signature"] == "valid"
        assert vr["chain_integrity"] == "valid"
        assert vr["export_hash"] == "valid"

    def test_missing_file_raises(self, tmp_path):
        import pytest
        with pytest.raises(CertificationError, match="File not found"):
            verify_piqrypt_certification(str(tmp_path / "missing.piqrypt-certified"))

    def test_wrong_ca_key_raises(self, tmp_path):
        import pytest
        certified, _, _ = self._round_trip(tmp_path)
        # Use a completely different CA key → signature mismatch
        (tmp_path / "wrong").mkdir(exist_ok=True)
        _, wrong_pub, wrong_id = _temp_ca_key(tmp_path / "wrong")
        with pytest.raises(CertificationError, match="CA signature verification failed"):
            verify_piqrypt_certification(
                certified, ca_public_key=wrong_pub, ca_key_id=wrong_id
            )


# ─── CLI: certify-request ─────────────────────────────────────────────────────

def test_cli_certify_request(tmp_path):
    """piqrypt certify-request creates a valid ZIP."""
    activate_license("pk_pro_test123_2423cdc1")
    try:
        import zipfile as zf
        audit_path, cert_path = _make_audit_and_cert(tmp_path)

        result = subprocess.run(
            [sys.executable, "-m", "cli.main", "certify-request",
             audit_path, cert_path,
             "--email", "test@example.com",
             "--output-dir", str(tmp_path)],
            cwd=REPO_ROOT,
            env={**os.environ, "PYTHONPATH": REPO_ROOT},
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        assert "certification-request-CERT" in result.stdout

        zips = list(tmp_path.glob("certification-request-*.zip"))
        assert len(zips) == 1
        with zf.ZipFile(zips[0]) as z:
            assert "audit.json" in z.namelist()
    finally:
        deactivate_license()


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
