# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com
"""
Trial management for PiQrypt.

Handles the 30-day Pro trial: requesting a token from the Trust Server,
activating it locally, writing a marker file, and emitting reminder messages.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_ENDPOINT = "https://trust-server-ucjb.onrender.com/api/trial/start"
PRICING_URL = "https://piqrypt.com/pricing"


class TrialError(Exception):
    """Raised when a trial operation cannot be completed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ── Network seam ──────────────────────────────────────────────────────────────

def _post_json(url: str, body: Dict[str, Any], timeout: float) -> tuple:
    """POST body as JSON; return (status_code, response_dict)."""
    import urllib.request
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read()
            parsed = json.loads(raw)
        except Exception:
            parsed = {}
        return exc.code, parsed
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = {}
    return 200, parsed


# ── Marker helpers ────────────────────────────────────────────────────────────

def _marker_path() -> Path:
    from aiss import license as _lic
    return _lic._CONFIG_DIR / "trial.json"


def _read_marker() -> Optional[Dict[str, Any]]:
    try:
        return json.loads(_marker_path().read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_marker(data: Dict[str, Any]) -> None:
    from aiss import license as _lic
    _lic._CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    path = _marker_path()
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise


# ── Public API ────────────────────────────────────────────────────────────────

def start_trial(timeout: float = 60.0) -> Dict[str, Any]:
    """
    Request a 30-day Pro trial token from the Trust Server and activate it.

    Returns a dict with license_id, expires_at, trial_days, days_left.
    Raises TrialError on any failure.
    """
    import aiss
    from aiss import license as _lic

    # Step 1: env key takes priority
    if os.environ.get("PIQRYPT_LICENSE_KEY") or os.environ.get("AISS2_LICENSE_KEY"):
        raise TrialError(
            "env_license",
            "A license key is set in the environment (PIQRYPT_LICENSE_KEY) and takes "
            "priority over a trial. Unset it and run this command again.",
        )

    # Step 2: refuse if a paid (non-trial) license is already active
    info = _lic.get_license().info()
    if info["tier"] != "free" and not info.get("trial"):
        raise TrialError(
            "license_active",
            "A license is already active (tier "
            + info["tier"].upper()
            + "). No trial is needed.",
        )

    # Step 3: refuse locally if a marker is present and expired
    marker = _read_marker()
    if marker and time.time() >= marker.get("expires_at", 0):
        raise TrialError(
            "already_used",
            "A trial was already used on this installation. Pro is EUR 390/year: "
            + PRICING_URL,
        )

    # Step 4: network request
    from aiss.telemetry import _telemetry
    iid = _telemetry.installation_id
    endpoint = os.environ.get("PIQRYPT_TRIAL_ENDPOINT", DEFAULT_ENDPOINT)
    body = {"installation_id": iid, "client_version": aiss.__version__}
    try:
        status, data = _post_json(endpoint, body, timeout)
    except Exception as exc:
        raise TrialError(
            "unreachable",
            "Could not reach the PiQrypt server ("
            + type(exc).__name__
            + "). Nothing was changed. Try again in a minute; the Free tier keeps working.",
        )

    if status == 409:
        raise TrialError(
            "already_used",
            "A trial was already used on this installation. Pro is EUR 390/year: "
            + PRICING_URL,
        )
    if status == 429:
        raise TrialError("capacity", "Trial issuance is busy right now. Try again later.")
    if status == 503:
        raise TrialError(
            "unavailable", "Trial issuance is temporarily unavailable. Try again later."
        )
    if status != 200:
        raise TrialError("rejected", "The server refused the request (HTTP " + str(status) + ").")

    # Step 5: activate the token
    token = data.get("token", "")
    if not isinstance(token, str) or not token:
        raise TrialError(
            "rejected",
            "The server refused the request (HTTP " + str(status) + ").",
        )
    try:
        _lic.activate_license(token)
    except (_lic.LicenseInvalidError, _lic.LicenseExpiredError):
        raise TrialError(
            "invalid_token",
            "The server returned a token this version cannot verify. "
            "Update PiQrypt (pip install -U piqrypt) and try again.",
        )

    # Step 6: write marker
    license_id = data.get("license_id", "trial-unknown")
    issued_at = data.get("issued_at", int(time.time()))
    expires_at = data.get("expires_at", int(time.time()) + 30 * 86400)
    prev_notified: List[str] = []
    if marker and marker.get("license_id") == license_id:
        prev_notified = marker.get("notified", [])
    _write_marker({
        "license_id": license_id,
        "started_at": issued_at,
        "expires_at": expires_at,
        "notified": prev_notified,
    })

    fresh_info = _lic.get_license().info()
    days_left = fresh_info.get("days_left")
    return {
        "license_id": license_id,
        "expires_at": expires_at,
        "trial_days": data.get("trial_days", 30),
        "days_left": days_left,
    }


def trial_status() -> Dict[str, Any]:
    """Return a dict describing the current trial state."""
    from aiss import license as _lic

    info = _lic.get_license().info()
    marker = _read_marker()
    now = time.time()

    paid_license = (info["tier"] != "free" and not info.get("trial"))

    exp_iso: Optional[str] = None
    if marker:
        try:
            exp_iso = datetime.fromtimestamp(
                marker["expires_at"], tz=timezone.utc
            ).strftime("%Y-%m-%d")
        except Exception:
            pass
    elif info.get("expires_at"):
        exp_iso = info["expires_at"][:10] if info["expires_at"] else None

    if paid_license:
        state = "not_started"
    elif info.get("status") == "trial":
        state = "active"
    elif info.get("status") == "grace" and info.get("trial"):
        state = "grace"
    elif marker and now >= marker.get("expires_at", 0) and info["tier"] == "free":
        state = "ended"
    else:
        state = "not_started"

    return {
        "state": state,
        "days_left": info.get("days_left"),
        "expires_at_iso": exp_iso,
        "license_tier": info["tier"],
        "paid_license": paid_license,
    }


def pending_notice() -> Optional[str]:
    """
    Return at most one pending notice string and persist the fact that it was shown.
    Never raises.
    """
    try:
        from aiss import license as _lic

        marker = _read_marker()
        info = _lic.get_license().info()

        # Only act when a trial exists (marker or active trial license)
        if not marker and info.get("status") not in ("trial", "grace"):
            return None

        # No notice for paid non-trial licenses
        if info["tier"] != "free" and not info.get("trial") and not marker:
            return None

        notified: List[str] = list(marker.get("notified", [])) if marker else []
        days_left = info.get("days_left")
        status = info.get("status", "free")

        msg: Optional[str] = None
        new_keys: List[str] = []

        if status == "trial" and days_left is not None and days_left <= 1:
            if "j1" not in notified:
                msg = "PiQrypt trial: ends in 1 day or less. Keep Pro: " + PRICING_URL
                new_keys = ["j1", "j7"]
        elif status == "trial" and days_left is not None and days_left <= 7:
            if "j7" not in notified:
                msg = (
                    "PiQrypt trial: "
                    + str(days_left)
                    + " days left. Keep Pro: "
                    + PRICING_URL
                )
                new_keys = ["j7"]
        elif status == "grace" and info.get("trial") and "grace" not in notified:
            msg = (
                "PiQrypt trial: expired. Pro stays on for a short grace period. "
                "Keep Pro: " + PRICING_URL
            )
            new_keys = ["grace"]
        elif marker:
            now = time.time()
            if now >= marker.get("expires_at", 0) and info["tier"] == "free":
                if "ended" not in notified:
                    msg = (
                        "Your PiQrypt trial has ended. You are back on the Free tier "
                        "(3 agents); your data is untouched. Keep Pro: " + PRICING_URL
                    )
                    new_keys = ["ended"]

        if msg and new_keys and marker:
            for k in new_keys:
                if k not in notified:
                    notified.append(k)
            updated = dict(marker)
            updated["notified"] = notified
            try:
                _write_marker(updated)
            except Exception:
                pass

        return msg
    except Exception:
        return None
