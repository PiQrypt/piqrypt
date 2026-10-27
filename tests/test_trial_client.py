# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
"""Tests for aiss/trial.py and the piqrypt trial CLI commands."""
from __future__ import annotations

import base64
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]

# ── Guard ──────────────────────────────────────────────────────────────────────

assert "trust-server-ucjb.onrender.com" not in os.environ.get(
    "PIQRYPT_TRIAL_ENDPOINT", ""
), "PIQRYPT_TRIAL_ENDPOINT must not point to production"


# ── JWT helpers ───────────────────────────────────────────────────────────────

def _b64url_encode(b: bytes) -> str:
    return base64.b64encode(b).decode().replace("+", "-").replace("/", "_").rstrip("=")


def _make_jwt(payload: Dict[str, Any], private_key_bytes: bytes) -> str:
    """Sign a JWT with a raw Ed25519 private key (seed only, 32 bytes)."""
    from nacl.signing import SigningKey
    sk = SigningKey(private_key_bytes)
    header = _b64url_encode(json.dumps({"alg": "EdDSA", "typ": "JWT"}).encode())
    body = _b64url_encode(json.dumps(payload).encode())
    message = f"{header}.{body}".encode()
    signature = _b64url_encode(bytes(sk.sign(message).signature))
    return f"{header}.{body}.{signature}"


def _gen_keypair():
    from nacl.signing import SigningKey
    sk = SigningKey.generate()
    priv = bytes(sk)           # 32-byte seed
    pub = bytes(sk.verify_key) # 32-byte public key
    pub_b64 = base64.b64encode(pub).decode()
    return priv, pub, pub_b64


# ── Isolation fixture ─────────────────────────────────────────────────────────

class TrialTestBase(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        piqrypt_home = self.tmp / ".piqrypt"
        piqrypt_home.mkdir()

        # Generate throwaway keypair
        self._priv, self._pub, self._pub_b64 = _gen_keypair()

        import aiss.license as _lic
        import aiss.trial as _trial

        self._lic = _lic
        self._trial = _trial

        # Build a clean Free license instance for reset
        free_lic = _lic.License.__new__(_lic.License)
        free_lic._tier = "free"
        free_lic._payload = _lic.License.__new__(_lic.License)._default_free_payload()
        free_lic._loaded_at = 0.0

        # Patch config paths (restored after each test)
        p1 = patch.object(_lic, "_CONFIG_DIR", piqrypt_home)
        p2 = patch.object(_lic, "_LICENSE_FILE", piqrypt_home / "license.jwt")
        p3 = patch.object(_lic, "_GRACE_FILE", piqrypt_home / "license.grace")
        p4 = patch.object(_lic, "_DEV_PUBLIC_KEY_B64", self._pub_b64)
        p5 = patch.object(_lic, "_license", free_lic)
        for p in (p1, p2, p3, p4, p5):
            p.start()
            self.addCleanup(p.stop)

        # Remove license env keys (restored after each test)
        env_patch = patch.dict(os.environ,
                               {"PIQRYPT_LICENSE_KEY": "", "AISS2_LICENSE_KEY": ""},
                               clear=False)
        env_patch.start()
        self.addCleanup(env_patch.stop)
        os.environ.pop("PIQRYPT_LICENSE_KEY", None)
        os.environ.pop("AISS2_LICENSE_KEY", None)

    def _make_trial_token(self, days=30):
        now = int(time.time())
        payload = {
            "tier": "pro",
            "trial": True,
            "trial_days": days,
            "license_id": "trial-abcdef1234567890",
            "issued_at": now,
            "expires_at": now + days * 86400,
            "agents_max": 50,
            "events_month": 500000,
        }
        return _make_jwt(payload, self._priv), payload

    def _server_response(self, status, body):
        """Patch _post_json to return (status, body)."""
        return patch.object(self._trial, "_post_json", return_value=(status, body))


# ── Test cases ────────────────────────────────────────────────────────────────

class TestStartTrialSuccess(TrialTestBase):

    def test_success_activates_license(self):
        token, payload = self._make_trial_token()
        response = {
            "status": "ok", "token": token, "tier": "pro",
            "license_id": payload["license_id"],
            "issued_at": payload["issued_at"],
            "expires_at": payload["expires_at"],
            "trial_days": 30,
        }
        with self._server_response(200, response):
            result = self._trial.start_trial()
        self.assertEqual(result["license_id"], payload["license_id"])
        self.assertEqual(result["trial_days"], 30)
        self.assertIsNotNone(result["days_left"])
        self.assertGreater(result["days_left"], 0)

    def test_success_writes_marker(self):
        token, payload = self._make_trial_token()
        response = {
            "status": "ok", "token": token, "tier": "pro",
            "license_id": payload["license_id"],
            "issued_at": payload["issued_at"],
            "expires_at": payload["expires_at"],
            "trial_days": 30,
        }
        with self._server_response(200, response):
            self._trial.start_trial()
        marker_path = self._lic._CONFIG_DIR / "trial.json"
        self.assertTrue(marker_path.exists())
        marker = json.loads(marker_path.read_text())
        self.assertEqual(marker["license_id"], payload["license_id"])

    def test_request_body_fields(self):
        token, payload = self._make_trial_token()
        response = {
            "status": "ok", "token": token, "tier": "pro",
            "license_id": payload["license_id"],
            "issued_at": payload["issued_at"],
            "expires_at": payload["expires_at"],
            "trial_days": 30,
        }
        captured = {}

        def capture(url, body, timeout):
            captured.update(body)
            return 200, response

        with patch.object(self._trial, "_post_json", side_effect=capture):
            self._trial.start_trial()

        self.assertIn("installation_id", captured)
        self.assertIn("client_version", captured)
        self.assertEqual(set(captured.keys()), {"installation_id", "client_version"})
        # installation_id matches telemetry id
        from aiss.telemetry import _telemetry
        self.assertEqual(captured["installation_id"], _telemetry.installation_id)

    def test_license_status_is_trial(self):
        token, payload = self._make_trial_token()
        response = {
            "status": "ok", "token": token, "tier": "pro",
            "license_id": payload["license_id"],
            "issued_at": payload["issued_at"],
            "expires_at": payload["expires_at"],
            "trial_days": 30,
        }
        with self._server_response(200, response):
            self._trial.start_trial()
        info = self._lic.get_license().info()
        self.assertEqual(info["status"], "trial")
        self.assertEqual(info["days_left"], 30)


class TestStartTrialRefused(TrialTestBase):

    def test_refused_when_paid_license_active(self):
        # Activate a non-trial license
        token_payload = {
            "tier": "pro", "trial": False,
            "license_id": "paid-abc", "issued_at": int(time.time()),
            "expires_at": int(time.time()) + 365 * 86400,
            "agents_max": 50, "events_month": 500000,
        }
        token = _make_jwt(token_payload, self._priv)
        self._lic._license.activate(token)

        called = []
        _noop = lambda *a, **kw: called.append(1) or (200, {})  # noqa: E731
        with patch.object(self._trial, "_post_json", side_effect=_noop):
            with self.assertRaises(self._trial.TrialError) as ctx:
                self._trial.start_trial()
        self.assertEqual(ctx.exception.code, "license_active")
        self.assertEqual(called, [])

    def test_refused_when_env_license_key_set(self):
        os.environ["PIQRYPT_LICENSE_KEY"] = "fake_key"
        called = []
        try:
            _noop2 = lambda *a, **kw: called.append(1) or (200, {})  # noqa: E731
            with patch.object(self._trial, "_post_json", side_effect=_noop2):
                with self.assertRaises(self._trial.TrialError) as ctx:
                    self._trial.start_trial()
            self.assertEqual(ctx.exception.code, "env_license")
            self.assertEqual(called, [])
        finally:
            os.environ.pop("PIQRYPT_LICENSE_KEY", None)

    def test_refused_locally_when_marker_expired(self):
        expired = int(time.time()) - 86400
        marker = {"license_id": "trial-old", "started_at": expired - 30 * 86400,
                   "expires_at": expired, "notified": []}
        (self._lic._CONFIG_DIR / "trial.json").write_text(json.dumps(marker))
        called = []
        _noop3 = lambda *a, **kw: called.append(1) or (200, {})  # noqa: E731
        with patch.object(self._trial, "_post_json", side_effect=_noop3):
            with self.assertRaises(self._trial.TrialError) as ctx:
                self._trial.start_trial()
        self.assertEqual(ctx.exception.code, "already_used")
        self.assertEqual(called, [])

    def test_reissue_with_marker_inside_window_and_no_license_file(self):
        """A trial in window but no license file: network is called and license restored."""
        future = int(time.time()) + 20 * 86400
        marker = {"license_id": "trial-live", "started_at": int(time.time()) - 10 * 86400,
                   "expires_at": future, "notified": []}
        (self._lic._CONFIG_DIR / "trial.json").write_text(json.dumps(marker))

        token, payload = self._make_trial_token(days=20)
        payload["license_id"] = "trial-live"
        payload["expires_at"] = future
        response = {
            "status": "ok", "token": token, "tier": "pro",
            "license_id": "trial-live",
            "issued_at": payload["issued_at"],
            "expires_at": future,
            "trial_days": 20,
        }
        called = []

        def fake_post(url, body, timeout):
            called.append(1)
            return 200, response

        with patch.object(self._trial, "_post_json", side_effect=fake_post):
            result = self._trial.start_trial()
        self.assertEqual(called, [1])
        self.assertEqual(result["license_id"], "trial-live")


class TestStartTrialErrors(TrialTestBase):

    def _assert_no_marker_change(self, code, server_status, server_body):
        marker_path = self._lic._CONFIG_DIR / "trial.json"
        before = marker_path.read_text() if marker_path.exists() else None
        with self._server_response(server_status, server_body):
            with self.assertRaises(self._trial.TrialError) as ctx:
                self._trial.start_trial()
        after = marker_path.read_text() if marker_path.exists() else None
        self.assertEqual(ctx.exception.code, code)
        self.assertEqual(before, after)

    def test_409_already_used(self):
        self._assert_no_marker_change("already_used", 409, {"error": "trial_already_used"})

    def test_429_capacity(self):
        self._assert_no_marker_change("capacity", 429, {"error": "trial_capacity"})

    def test_503_unavailable(self):
        self._assert_no_marker_change("unavailable", 503, {"error": "trial_unavailable"})

    def test_other_non_200(self):
        self._assert_no_marker_change("rejected", 400, {"error": "invalid_json"})

    def test_empty_token(self):
        self._assert_no_marker_change("rejected", 200, {"token": ""})

    def test_invalid_token(self):
        self._assert_no_marker_change("invalid_token", 200,
                                       {"token": "bad.token.here",
                                        "license_id": "trial-x", "issued_at": int(time.time()),
                                        "expires_at": int(time.time()) + 86400, "trial_days": 30})

    def test_unreachable(self):
        import urllib.error
        with patch.object(self._trial, "_post_json",
                          side_effect=urllib.error.URLError("no route to host")):
            with self.assertRaises(self._trial.TrialError) as ctx:
                self._trial.start_trial()
        self.assertEqual(ctx.exception.code, "unreachable")


class TestTokenNotInOutput(TrialTestBase):

    def test_token_never_in_stdout_stderr(self):
        token, payload = self._make_trial_token()
        response = {
            "status": "ok", "token": token, "tier": "pro",
            "license_id": payload["license_id"],
            "issued_at": payload["issued_at"],
            "expires_at": payload["expires_at"],
            "trial_days": 30,
        }
        import io
        from contextlib import redirect_stdout, redirect_stderr
        out, err = io.StringIO(), io.StringIO()
        with self._server_response(200, response):
            with redirect_stdout(out), redirect_stderr(err):
                self._trial.start_trial()
        self.assertNotIn(token, out.getvalue())
        self.assertNotIn(token, err.getvalue())


class TestPendingNotice(TrialTestBase):

    def _make_active_license(self, days_left):
        token, payload = self._make_trial_token(days=days_left)
        self._lic._license.activate(token)

    def _set_marker(self, expires_at, notified=None):
        marker = {
            "license_id": "trial-abc",
            "started_at": expires_at - 30 * 86400,
            "expires_at": expires_at,
            "notified": notified or [],
        }
        (self._lic._CONFIG_DIR / "trial.json").write_text(json.dumps(marker))

    def test_j7_shown_once(self):
        self._make_active_license(days_left=5)
        self._set_marker(int(time.time()) + 5 * 86400)
        msg1 = self._trial.pending_notice()
        msg2 = self._trial.pending_notice()
        self.assertIsNotNone(msg1)
        self.assertIn("days left", msg1)
        self.assertIsNone(msg2)

    def test_j1_shown_once(self):
        # Build license directly — days_left=0 means expires_at ≈ now,
        # which activate() would reject as already expired.
        exp = int(time.time()) + 3600  # 1 hour left (< 1 day)
        lic = self._lic.License.__new__(self._lic.License)
        lic._tier = "pro"
        lic._payload = {
            "tier": "pro", "trial": True, "trial_days": 1,
            "license_id": "trial-j1", "issued_at": int(time.time()) - 29 * 86400,
            "expires_at": exp,
            "agents_max": 50, "events_month": 500000,
        }
        lic._loaded_at = 0.0
        self._lic._license = lic
        self._set_marker(exp)
        msg1 = self._trial.pending_notice()
        msg2 = self._trial.pending_notice()
        self.assertIsNotNone(msg1)
        self.assertIn("1 day or less", msg1)
        self.assertIsNone(msg2)

    def test_nothing_for_free_without_marker(self):
        # Free tier, no marker
        msg = self._trial.pending_notice()
        self.assertIsNone(msg)

    def test_nothing_for_paid_non_trial(self):
        token_payload = {
            "tier": "pro", "trial": False,
            "license_id": "paid-x", "issued_at": int(time.time()),
            "expires_at": int(time.time()) + 365 * 86400,
            "agents_max": 50, "events_month": 500000,
        }
        token = _make_jwt(token_payload, self._priv)
        self._lic._license.activate(token)
        msg = self._trial.pending_notice()
        self.assertIsNone(msg)

    def test_never_raises(self):
        # Even with a broken marker
        (self._lic._CONFIG_DIR / "trial.json").write_text("NOT_JSON")
        try:
            self._trial.pending_notice()
        except Exception as exc:
            self.fail(f"pending_notice raised: {exc}")


    def test_grace_shown_once(self):
        # Grace: trial license expired recently, still in grace period
        past = int(time.time()) - 3600  # expired 1 hour ago
        lic = self._lic.License.__new__(self._lic.License)
        lic._tier = "pro"
        lic._payload = {
            "tier": "pro", "trial": True, "trial_days": 30,
            "license_id": "trial-grace", "issued_at": int(time.time()) - 30 * 86400,
            "expires_at": past,
            "agents_max": 50, "events_month": 500000,
        }
        lic._loaded_at = 0.0
        self._lic._license = lic
        self._set_marker(past)
        msg1 = self._trial.pending_notice()
        msg2 = self._trial.pending_notice()
        self.assertIsNotNone(msg1)
        self.assertIn("grace", msg1)
        self.assertIsNone(msg2)

    def test_ended_shown_once(self):
        # Ended: trial expired and tier is back to free
        past = int(time.time()) - 86400  # expired yesterday
        self._set_marker(past)
        msg1 = self._trial.pending_notice()
        msg2 = self._trial.pending_notice()
        self.assertIsNotNone(msg1)
        self.assertIn("ended", msg1)
        self.assertIsNone(msg2)


class TestReadMarker(TrialTestBase):

    def test_list_marker_is_ignored(self):
        """A trial.json containing a JSON array is treated as absent (not a dict)."""
        (self._lic._CONFIG_DIR / "trial.json").write_text("[1, 2]")
        result = self._trial._read_marker()
        self.assertIsNone(result)

    def test_valid_dict_marker_is_read(self):
        """A well-formed dict marker is returned unchanged."""
        marker = {
            "license_id": "trial-test",
            "started_at": int(time.time()) - 86400,
            "expires_at": int(time.time()) + 29 * 86400,
            "notified": [],
        }
        (self._lic._CONFIG_DIR / "trial.json").write_text(json.dumps(marker))
        result = self._trial._read_marker()
        self.assertIsNotNone(result)
        self.assertEqual(result["license_id"], "trial-test")


class TestTrialStatus(TrialTestBase):

    def test_not_started(self):
        st = self._trial.trial_status()
        self.assertEqual(st["state"], "not_started")
        self.assertFalse(st["paid_license"])

    def test_active(self):
        token, payload = self._make_trial_token(days=30)
        self._lic._license.activate(token)
        now = int(time.time())
        (self._lic._CONFIG_DIR / "trial.json").write_text(json.dumps({
            "license_id": payload["license_id"],
            "started_at": now,
            "expires_at": payload["expires_at"],
            "notified": [],
        }))
        st = self._trial.trial_status()
        self.assertEqual(st["state"], "active")
        self.assertIsNotNone(st["expires_at_iso"])

    def test_ended(self):
        past = int(time.time()) - 86400
        (self._lic._CONFIG_DIR / "trial.json").write_text(json.dumps({
            "license_id": "trial-old",
            "started_at": past - 30 * 86400,
            "expires_at": past,
            "notified": [],
        }))
        st = self._trial.trial_status()
        self.assertEqual(st["state"], "ended")

    def test_paid_license(self):
        token_payload = {
            "tier": "pro", "trial": False,
            "license_id": "paid-x", "issued_at": int(time.time()),
            "expires_at": int(time.time()) + 365 * 86400,
            "agents_max": 50, "events_month": 500000,
        }
        token = _make_jwt(token_payload, self._priv)
        self._lic._license.activate(token)
        st = self._trial.trial_status()
        self.assertTrue(st["paid_license"])


# ── Real urllib HTTP server test ──────────────────────────────────────────────

class _SimpleHandler(http.server.BaseHTTPRequestHandler):
    responses = []  # list of (status, body_dict) to serve

    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if _SimpleHandler.responses:
            status, body = _SimpleHandler.responses.pop(0)
        else:
            status, body = 200, {"status": "ok"}
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())


class TestPostJsonRealHttp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import aiss.trial as _trial
        cls._trial = _trial
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _SimpleHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_200(self):
        _SimpleHandler.responses = [(200, {"status": "ok", "token": "t"})]
        url = f"http://127.0.0.1:{self.port}/api/trial/start"
        status, data = self._trial._post_json(url, {"a": 1}, 5.0)
        self.assertEqual(status, 200)
        self.assertEqual(data["token"], "t")

    def test_409(self):
        _SimpleHandler.responses = [(409, {"error": "trial_already_used"})]
        url = f"http://127.0.0.1:{self.port}/api/trial/start"
        status, data = self._trial._post_json(url, {}, 5.0)
        self.assertEqual(status, 409)

    def test_429(self):
        _SimpleHandler.responses = [(429, {"error": "trial_capacity"})]
        url = f"http://127.0.0.1:{self.port}/api/trial/start"
        status, data = self._trial._post_json(url, {}, 5.0)
        self.assertEqual(status, 429)

    def test_503(self):
        _SimpleHandler.responses = [(503, {"error": "trial_unavailable"})]
        url = f"http://127.0.0.1:{self.port}/api/trial/start"
        status, data = self._trial._post_json(url, {}, 5.0)
        self.assertEqual(status, 503)


# ── CLI subprocess tests ──────────────────────────────────────────────────────

def _cli(args, home, extra_env=None):
    env = dict(os.environ)
    env.update({
        "USERPROFILE": str(home), "HOME": str(home),
        "PIQRYPT_HOME": str(Path(home) / ".piqrypt"),
        "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
        "PIQRYPT_TRIAL_ENDPOINT": "pytest-no-network://trial",
    })
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-c",
         "import sys; from cli.main import main; sys.exit(main() or 0)"] + args,
        cwd=str(REPO_ROOT), env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=30,
    )


class TestTrialCli(unittest.TestCase):

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())

    def test_status_not_started_exit_0(self):
        r = _cli(["trial", "status"], self.home)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("NOT STARTED", r.stdout)

    def test_start_unreachable_exit_1_no_trial_json(self):
        r = _cli(["trial", "start"], self.home)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Could not reach", r.stderr)
        trial_json = self.home / ".piqrypt" / "trial.json"
        self.assertFalse(trial_json.exists())


class TestCertifiedExportDuringTrial(TrialTestBase):
    """Prove that the local certified export works with a trial Pro license."""

    def test_certify_export_does_not_raise(self):
        """A trial Pro token passes is_pro(); certify_export must not raise."""
        import aiss
        from aiss.exports import export_audit_chain, certify_export
        from aiss.crypto import ed25519

        # Activate a trial Pro token
        token, _ = self._make_trial_token(days=30)
        self._lic._license.activate(token)

        # Build a minimal chain
        priv, pub = ed25519.generate_keypair()
        agent_id = aiss.derive_agent_id(pub)
        identity = aiss.export_identity(agent_id, pub)
        events = [aiss.stamp_event(priv, agent_id, {"i": i}) for i in range(2)]

        audit_path = self.tmp / "audit_trial.json"
        audit_path.write_text(json.dumps(export_audit_chain(identity, events)))

        # Must not raise FeatureNotAvailableError
        cert_path = certify_export(str(audit_path), priv, agent_id)
        self.assertTrue(Path(cert_path).exists())


class TestCmdTrialStartDays(TrialTestBase):
    """Verify that cmd_trial_start prints at most trial_days, not days_left."""

    def _run_cmd(self, days_left, trial_days):
        import io
        from contextlib import redirect_stdout
        import cli.main as _cli

        token, payload = self._make_trial_token(days=trial_days)
        result = {
            "license_id": payload["license_id"],
            "expires_at": payload["expires_at"],
            "trial_days": trial_days,
            "days_left": days_left,
        }
        out = io.StringIO()
        with patch.object(self._trial, "start_trial", return_value=result):
            with redirect_stdout(out):
                _cli.cmd_trial_start(None)
        return out.getvalue()

    def test_days_left_exceeds_trial_days_capped(self):
        """days_left=31, trial_days=30 -> "(30 days)" printed."""
        output = self._run_cmd(days_left=31, trial_days=30)
        self.assertIn("(30 days)", output)
        self.assertNotIn("(31 days)", output)

    def test_days_left_below_trial_days_unchanged(self):
        """days_left=12, trial_days=30 -> "(12 days)" printed (re-issued trial)."""
        output = self._run_cmd(days_left=12, trial_days=30)
        self.assertIn("(12 days)", output)


if __name__ == "__main__":
    unittest.main()
