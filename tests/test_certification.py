"""
Tests for aiss/certification.py, aiss/cert_badges.py, aiss/telemetry.py

Coverage:
  - generate_cert_id()
  - validate_audit_for_certification()
  - compute_audit_hash()
  - certify_simple()
  - certify_audit() dispatcher
  - CertificationError exceptions
  - generate_cert_badge_svg()
  - generate_cert_badge()
  - generate_badge_snippets()
  - Telemetry.enable() / disable() / track_event()
  - is_telemetry_enabled() / get_telemetry_status()
"""

import json
import re
import time
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

# ─── Fixtures shared across the module ────────────────────────────────────────

@pytest.fixture()
def tmp_dir(tmp_path):
    """Temporary directory for output files."""
    return tmp_path


@pytest.fixture()
def sample_keypair():
    """Real Ed25519 keypair for signing."""
    from aiss.crypto import ed25519
    return ed25519.generate_keypair()


@pytest.fixture()
def minimal_audit(tmp_path, sample_keypair):
    """
    Minimal valid audit.json with 2 chained events.
    Written to disk and returned as (path, data).
    """
    from aiss import derive_agent_id, stamp_genesis_event, stamp_event
    from aiss.chain import compute_event_hash

    priv_key, pub_key = sample_keypair
    agent_id = derive_agent_id(pub_key)

    # Genesis event — signature: (private_key, public_key, agent_id, payload)
    genesis = stamp_genesis_event(priv_key, pub_key, agent_id, {"action": "init"})
    # Second event chained — signature: (private_key, agent_id, payload, previous_hash)
    second = stamp_event(priv_key, agent_id, {"action": "update"},
                         previous_hash=compute_event_hash(genesis))

    audit = {
        "agent_id": agent_id,
        "events": [genesis, second],
    }

    audit_path = tmp_path / "audit.json"
    audit_path.write_text(json.dumps(audit))
    return str(audit_path), audit


# ══════════════════════════════════════════════════════════════════════════════
# 1. certification.py
# ══════════════════════════════════════════════════════════════════════════════

class TestGenerateCertId:
    """generate_cert_id() — unique IDs in CERT-YYYYMMDD-XXXXXX format."""

    def test_format(self):
        from aiss.certification import generate_cert_id
        cert_id = generate_cert_id()
        assert re.match(r"^CERT-\d{8}-[0-9A-F]{6}$", cert_id), \
            f"Unexpected format: {cert_id}"

    def test_uniqueness(self):
        from aiss.certification import generate_cert_id
        ids = {generate_cert_id() for _ in range(50)}
        assert len(ids) == 50, "Duplicate cert IDs generated"

    def test_date_is_today(self):
        from aiss.certification import generate_cert_id
        from datetime import datetime, timezone
        cert_id = generate_cert_id()
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        assert today in cert_id


class TestComputeAuditHash:
    """compute_audit_hash() — deterministic SHA-256 with prefix."""

    def test_prefix(self):
        from aiss.certification import compute_audit_hash
        h = compute_audit_hash({"events": []})
        assert h.startswith("sha256:")

    def test_deterministic(self):
        from aiss.certification import compute_audit_hash
        data = {"events": [{"id": "x"}], "agent_id": "abc"}
        assert compute_audit_hash(data) == compute_audit_hash(data)

    def test_different_data_different_hash(self):
        from aiss.certification import compute_audit_hash
        h1 = compute_audit_hash({"events": [{"id": "1"}]})
        h2 = compute_audit_hash({"events": [{"id": "2"}]})
        assert h1 != h2

    def test_hex_length(self):
        from aiss.certification import compute_audit_hash
        h = compute_audit_hash({"x": 1})
        # "sha256:" + 64 hex chars
        assert len(h) == 7 + 64


class TestValidateAuditForCertification:
    """validate_audit_for_certification() — input validation and chain check."""

    def test_valid_audit_passes(self, minimal_audit):
        from aiss.certification import validate_audit_for_certification
        audit_path, _ = minimal_audit
        result = validate_audit_for_certification(audit_path)
        assert "events" in result
        assert len(result["events"]) == 2

    def test_missing_file_raises(self, tmp_dir):
        from aiss.certification import validate_audit_for_certification, CertificationError
        with pytest.raises(CertificationError, match="Failed to load"):
            validate_audit_for_certification(str(tmp_dir / "missing.json"))

    def test_missing_events_field_raises(self, tmp_dir):
        from aiss.certification import validate_audit_for_certification, CertificationError
        bad_path = tmp_dir / "bad.json"
        bad_path.write_text(json.dumps({"agent_id": "x"}))
        with pytest.raises(CertificationError, match="missing 'events'"):
            validate_audit_for_certification(str(bad_path))

    def test_empty_events_raises(self, tmp_dir):
        from aiss.certification import validate_audit_for_certification, CertificationError
        bad_path = tmp_dir / "empty.json"
        bad_path.write_text(json.dumps({"events": []}))
        with pytest.raises(CertificationError, match="no events"):
            validate_audit_for_certification(str(bad_path))

    def test_events_not_list_raises(self, tmp_dir):
        from aiss.certification import validate_audit_for_certification, CertificationError
        bad_path = tmp_dir / "notlist.json"
        bad_path.write_text(json.dumps({"events": "oops"}))
        with pytest.raises(CertificationError, match="must be a list"):
            validate_audit_for_certification(str(bad_path))

    def test_invalid_json_raises(self, tmp_dir):
        from aiss.certification import validate_audit_for_certification, CertificationError
        bad_path = tmp_dir / "corrupt.json"
        bad_path.write_text("{ not valid json }")
        with pytest.raises(CertificationError):
            validate_audit_for_certification(str(bad_path))


class TestCertifySimple:
    """certify_simple() — Simple (€9) tier end-to-end."""

    def test_returns_cert_id(self, minimal_audit, tmp_dir, sample_keypair):
        from aiss.certification import certify_simple
        from aiss import derive_agent_id

        priv_key, pub_key = sample_keypair
        ca_agent_id = derive_agent_id(pub_key)
        audit_path, _ = minimal_audit

        result = certify_simple(audit_path, priv_key, ca_agent_id, str(tmp_dir))

        assert "cert_id" in result
        assert re.match(r"^CERT-\d{8}-[0-9A-F]{6}$", result["cert_id"])

    def test_creates_zip_bundle(self, minimal_audit, tmp_dir, sample_keypair):
        from aiss.certification import certify_simple
        from aiss import derive_agent_id

        priv_key, pub_key = sample_keypair
        audit_path, _ = minimal_audit

        result = certify_simple(audit_path, priv_key, derive_agent_id(pub_key), str(tmp_dir))

        bundle_path = Path(result["bundle_path"])
        assert bundle_path.exists()
        assert bundle_path.suffix == ".piqrypt-certified" or ".piqrypt-certified" in bundle_path.name

    def test_zip_contains_expected_files(self, minimal_audit, tmp_dir, sample_keypair):
        from aiss.certification import certify_simple
        from aiss import derive_agent_id

        priv_key, pub_key = sample_keypair
        audit_path, _ = minimal_audit

        result = certify_simple(audit_path, priv_key, derive_agent_id(pub_key), str(tmp_dir))

        with zipfile.ZipFile(result["bundle_path"], 'r') as zf:
            names = zf.namelist()

        assert "audit.json" in names
        assert "certificate.json" in names
        assert "badge.svg" in names
        assert "SNIPPETS.txt" in names

    def test_certificate_has_ca_signature(self, minimal_audit, tmp_dir, sample_keypair):
        from aiss.certification import certify_simple
        from aiss import derive_agent_id

        priv_key, pub_key = sample_keypair
        audit_path, _ = minimal_audit

        result = certify_simple(audit_path, priv_key, derive_agent_id(pub_key), str(tmp_dir))

        cert = result["certificate"]
        assert "ca_signature" in cert
        assert cert["ca_signature"].startswith("base64:")

    def test_certificate_metadata(self, minimal_audit, tmp_dir, sample_keypair):
        from aiss.certification import certify_simple
        from aiss import derive_agent_id

        priv_key, pub_key = sample_keypair
        audit_path, _ = minimal_audit

        result = certify_simple(audit_path, priv_key, derive_agent_id(pub_key), str(tmp_dir))

        cert = result["certificate"]
        assert cert["tier"] == "simple"
        assert cert["version"] == "PIQRYPT-CERT-1.0"
        assert cert["events_count"] == 2
        assert "certified_at" in cert
        assert cert["certified_at"] <= int(time.time())

    def test_tier_field_in_result(self, minimal_audit, tmp_dir, sample_keypair):
        from aiss.certification import certify_simple
        from aiss import derive_agent_id

        priv_key, pub_key = sample_keypair
        audit_path, _ = minimal_audit

        result = certify_simple(audit_path, priv_key, derive_agent_id(pub_key), str(tmp_dir))
        assert result["tier"] == "simple"


class TestCertifyAuditDispatcher:
    """certify_audit() — dispatcher selects correct tier."""

    def test_dispatches_simple(self, minimal_audit, tmp_dir, sample_keypair):
        from aiss.certification import certify_audit
        from aiss import derive_agent_id

        priv_key, pub_key = sample_keypair
        audit_path, _ = minimal_audit

        result = certify_audit(
            audit_path, "simple",
            ca_private_key=priv_key,
            ca_agent_id=derive_agent_id(pub_key),
            output_dir=str(tmp_dir)
        )
        assert result["tier"] == "simple"

    def test_unknown_tier_raises(self, minimal_audit, tmp_dir, sample_keypair):
        from aiss.certification import certify_audit, CertificationError
        from aiss import derive_agent_id

        priv_key, pub_key = sample_keypair
        audit_path, _ = minimal_audit

        with pytest.raises(CertificationError, match="Unknown tier"):
            certify_audit(
                audit_path, "platinum",
                ca_private_key=priv_key,
                ca_agent_id=derive_agent_id(pub_key),
                output_dir=str(tmp_dir)
            )

    def test_missing_ca_key_file_raises(self, minimal_audit, tmp_dir):
        """Without CA key passed and no file on disk → CertificationError."""
        from aiss.certification import certify_audit, CertificationError
        audit_path, _ = minimal_audit

        with patch("pathlib.Path.exists", return_value=False):
            with pytest.raises(CertificationError, match="CA private key not found"):
                certify_audit(
                    audit_path, "simple",
                    ca_private_key=None,
                    output_dir=str(tmp_dir)
                )


# ══════════════════════════════════════════════════════════════════════════════
# 2. cert_badges.py
# ══════════════════════════════════════════════════════════════════════════════

class TestGenerateCertBadgeSvg:
    """generate_cert_badge_svg() — produces valid SVG with correct content."""

    def test_returns_svg_string(self):
        from aiss.cert_badges import generate_cert_badge_svg
        svg = generate_cert_badge_svg("CERT-20260220-A3F7E8", "simple")
        assert isinstance(svg, str)
        assert "<svg" in svg
        assert "</svg>" in svg

    def test_contains_cert_id(self):
        from aiss.cert_badges import generate_cert_badge_svg
        cert_id = "CERT-20260220-A3F7E8"
        svg = generate_cert_badge_svg(cert_id, "simple")
        # Cert ID or its prefix must appear
        assert "CERT-20260220" in svg

    def test_tier_color_simple(self):
        from aiss.cert_badges import generate_cert_badge_svg
        svg = generate_cert_badge_svg("CERT-X", "simple")
        assert "#0066cc" in svg  # Blue for simple

    def test_tier_color_timestamp(self):
        from aiss.cert_badges import generate_cert_badge_svg
        svg = generate_cert_badge_svg("CERT-X", "timestamp")
        assert "#ff9500" in svg  # Orange

    def test_tier_color_pq_bundle(self):
        from aiss.cert_badges import generate_cert_badge_svg
        svg = generate_cert_badge_svg("CERT-X", "pq_bundle")
        assert "#ffd700" in svg  # Gold

    def test_unknown_tier_falls_back_to_simple(self):
        from aiss.cert_badges import generate_cert_badge_svg
        svg = generate_cert_badge_svg("CERT-X", "unknown_tier")
        # Should not crash — fallback to simple color
        assert "<svg" in svg


class TestGenerateCertBadge:
    """generate_cert_badge() — full badge dict structure."""

    CERT_ID = "CERT-20260220-AABBCC"

    def test_returns_dict_with_required_keys(self):
        from aiss.cert_badges import generate_cert_badge
        badge = generate_cert_badge(self.CERT_ID, "simple")
        for key in ("cert_id", "tier", "svg", "badge_url", "verify_url",
                    "markdown", "html", "rst", "issued_at", "tier_display"):
            assert key in badge, f"Missing key: {key}"

    def test_cert_id_preserved(self):
        from aiss.cert_badges import generate_cert_badge
        badge = generate_cert_badge(self.CERT_ID, "simple")
        assert badge["cert_id"] == self.CERT_ID

    def test_verify_url_contains_cert_id(self):
        from aiss.cert_badges import generate_cert_badge
        badge = generate_cert_badge(self.CERT_ID, "simple")
        assert self.CERT_ID in badge["verify_url"]

    def test_badge_url_ends_with_svg(self):
        from aiss.cert_badges import generate_cert_badge
        badge = generate_cert_badge(self.CERT_ID, "simple")
        assert badge["badge_url"].endswith(".svg")

    def test_markdown_embed_format(self):
        from aiss.cert_badges import generate_cert_badge
        badge = generate_cert_badge(self.CERT_ID, "timestamp")
        # Markdown image link: [![alt](img_url)](link_url)
        assert badge["markdown"].startswith("[![")
        assert "](https://" in badge["markdown"]

    def test_html_embed_format(self):
        from aiss.cert_badges import generate_cert_badge
        badge = generate_cert_badge(self.CERT_ID, "pq_bundle")
        assert '<a href=' in badge["html"]
        assert '<img src=' in badge["html"]

    def test_issued_at_is_recent_timestamp(self):
        from aiss.cert_badges import generate_cert_badge
        before = int(time.time())
        badge = generate_cert_badge(self.CERT_ID, "simple")
        after = int(time.time())
        assert before <= badge["issued_at"] <= after

    @pytest.mark.parametrize("tier,expected_label", [
        ("simple", "Simple"),
        ("timestamp", "Timestamp"),
        ("pq_bundle", "Post-Quantum"),
    ])
    def test_tier_display_label(self, tier, expected_label):
        from aiss.cert_badges import generate_cert_badge
        badge = generate_cert_badge(self.CERT_ID, tier)
        assert badge["tier_display"] == expected_label


class TestGenerateBadgeSnippets:
    """generate_badge_snippets() — human-readable text with embed codes."""

    def test_returns_string(self):
        from aiss.cert_badges import generate_badge_snippets
        snippets = generate_badge_snippets("CERT-X", "simple")
        assert isinstance(snippets, str)

    def test_contains_cert_id(self):
        from aiss.cert_badges import generate_badge_snippets
        snippets = generate_badge_snippets("CERT-20260220-AABBCC", "simple")
        assert "CERT-20260220-AABBCC" in snippets

    def test_contains_all_sections(self):
        from aiss.cert_badges import generate_badge_snippets
        snippets = generate_badge_snippets("CERT-X", "timestamp")
        assert "MARKDOWN" in snippets
        assert "HTML" in snippets
        assert "RESTRUCTUREDTEXT" in snippets
        assert "DOWNLOAD" in snippets


# ══════════════════════════════════════════════════════════════════════════════
# 3. telemetry.py
# ══════════════════════════════════════════════════════════════════════════════

class TestTelemetry:
    """Telemetry — opt-in only, no PII, graceful failure."""

    @pytest.fixture(autouse=True)
    def isolate_telemetry(self, tmp_path, monkeypatch):
        """Redirect ~/.piqrypt to tmp dir and reset global Telemetry state.
        Sets both HOME (Linux/Mac) and USERPROFILE (Windows) for portability.
        """
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        # Force reimport so Telemetry reads our tmp HOME / USERPROFILE
        import importlib
        import aiss.telemetry as tel_mod
        importlib.reload(tel_mod)
        self.tel_mod = tel_mod
        yield
        importlib.reload(tel_mod)  # Restore after test

    def test_disabled_by_default(self):
        assert not self.tel_mod.is_telemetry_enabled()

    def test_env_var_override_disables(self, monkeypatch):
        monkeypatch.setenv("PIQRYPT_TELEMETRY", "0")
        import importlib
        importlib.reload(self.tel_mod)
        assert not self.tel_mod.is_telemetry_enabled()

    def test_enable_persists(self):
        self.tel_mod.enable_telemetry()
        assert self.tel_mod.is_telemetry_enabled()

    def test_disable_after_enable(self):
        self.tel_mod.enable_telemetry()
        self.tel_mod.disable_telemetry()
        assert not self.tel_mod.is_telemetry_enabled()

    def test_get_status_returns_dict(self):
        status = self.tel_mod.get_telemetry_status()
        assert isinstance(status, dict)
        assert "enabled" in status
        assert "installation_id" in status

    def test_status_enabled_false_by_default(self):
        status = self.tel_mod.get_telemetry_status()
        assert status["enabled"] is False

    def test_status_after_enable(self):
        self.tel_mod.enable_telemetry()
        status = self.tel_mod.get_telemetry_status()
        assert status["enabled"] is True
        # Installation ID must be a valid UUID when enabled
        import uuid
        uuid.UUID(status["installation_id"])  # Raises if invalid

    def test_track_when_disabled_does_not_write(self, tmp_path):
        """track() must be a no-op when disabled."""
        self.tel_mod.track("test_event", foo="bar")
        log_file = tmp_path / ".piqrypt" / "telemetry.log"
        assert not log_file.exists()

    def test_track_when_enabled_logs_locally(self, tmp_path):
        self.tel_mod.enable_telemetry()
        self.tel_mod.track("identity_created", algorithm="Ed25519")
        log_file = tmp_path / ".piqrypt" / "telemetry.log"
        assert log_file.exists()
        lines = log_file.read_text().strip().splitlines()
        assert len(lines) >= 1
        event = json.loads(lines[-1])
        assert event["event"] == "identity_created"
        assert event["properties"]["algorithm"] == "Ed25519"

    def test_track_does_not_include_agent_id(self, tmp_path):
        """Confirm no agent ID (PII) sneaks into logs."""
        self.tel_mod.enable_telemetry()
        self.tel_mod.track("event_signed", events=10)
        log_file = tmp_path / ".piqrypt" / "telemetry.log"
        content = log_file.read_text()
        assert "agent_id" not in content

    def test_track_silent_failure_never_raises(self):
        """track() must never raise even if filesystem broken."""
        self.tel_mod.enable_telemetry()
        with patch("builtins.open", side_effect=PermissionError("denied")):
            # Should not raise
            self.tel_mod.track("event_signed")

    def test_installation_id_is_uuid(self):
        self.tel_mod.enable_telemetry()
        import uuid
        status = self.tel_mod.get_telemetry_status()
        uuid.UUID(status["installation_id"])  # Must not raise

    def test_installation_id_stable_across_calls(self):
        self.tel_mod.enable_telemetry()
        s1 = self.tel_mod.get_telemetry_status()
        s2 = self.tel_mod.get_telemetry_status()
        assert s1["installation_id"] == s2["installation_id"]
