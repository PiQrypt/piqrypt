# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
Telemetry for PiQrypt (enabled by default, opt-out)

Anonymous usage statistics to improve the project. Telemetry is enabled by
default and a notice is shown on the first run of the piqrypt command line.
No agent IDs, event payloads or personal data are sent. Each event carries a
random installation ID, the PiQrypt version, the event name and coarse system
information (operating system, CPU architecture, whether stdout is a
terminal). Details: docs/TELEMETRY.md

Disable:
    piqrypt telemetry disable
    or set the environment variable PIQRYPT_TELEMETRY=0
    (also accepted: false, no, off, in any case)

Enable again:
    piqrypt telemetry enable

Status:
    piqrypt telemetry status
"""

import json
import os
import platform
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

# ── Endpoint ────────────────────────────────────────────────────────────────
TELEMETRY_ENDPOINT = os.getenv(
    "PIQRYPT_TELEMETRY_ENDPOINT",
    "https://trust-server-ucjb.onrender.com/api/telemetry",
)

# ── Version ──────────────────────────────────────────────────────────────────
_VERSION = "1.11.0"

# ── System fingerprint (computed once at import) ─────────────────────────────
_os_name   = platform.system()    # Linux / Windows / Darwin
_arch      = platform.machine()   # x86_64 / ARM64 / etc.
_is_server = not sys.stdout.isatty()

# Values of PIQRYPT_TELEMETRY that switch telemetry off (any case).
_OFF_VALUES = ("0", "false", "no", "off")


def _env_disables_telemetry() -> bool:
    """True when PIQRYPT_TELEMETRY is set to one of the usual 'off' values."""
    return os.getenv("PIQRYPT_TELEMETRY", "").strip().lower() in _OFF_VALUES


class Telemetry:
    """
    Anonymous telemetry collection (enabled by default, opt-out)

    Collected data:
      - Event types (identity_created, event_signed, etc.)
      - Feature usage (aiss1, aiss2, exports)
      - Error types (for debugging)
      - Version info

    NOT collected:
      - Agent IDs
      - Event payloads
      - Any personal data
      - IP addresses
    """

    def __init__(self):
        # Respect HOME (Linux/Mac) or USERPROFILE (Windows) env var overrides,
        # which pytest monkeypatch uses to isolate tests.
        home_override = os.environ.get("HOME") or os.environ.get("USERPROFILE")
        home = Path(home_override) if home_override else Path.home()
        self.config_dir  = home / ".piqrypt"
        self.config_file = self.config_dir / "telemetry.json"
        self._id_file    = self.config_dir / "installation_id"
        self.enabled          = self._check_enabled()
        self.installation_id  = self._get_installation_id()

    def _check_enabled(self) -> bool:
        """Check if telemetry is enabled"""
        if _env_disables_telemetry():
            return False
        if self.config_file.exists():
            try:
                with open(self.config_file) as f:
                    config = json.load(f)
                    return config.get("enabled", False)
            except Exception:
                return False
        return True

    def _get_installation_id(self) -> str:
        """
        Get or create anonymous installation ID (UUID).
        Persisted in ~/.piqrypt/installation_id (dedicated file).
        Falls back to telemetry.json for backward compatibility.
        """
        # 1. Dedicated file (preferred)
        if self._id_file.exists():
            try:
                return self._id_file.read_text().strip()
            except Exception:
                pass

        # 2. Legacy: read from telemetry.json
        if self.config_file.exists():
            try:
                with open(self.config_file) as f:
                    install_id = json.load(f).get("installation_id")
                if install_id:
                    # Migrate to dedicated file
                    try:
                        self.config_dir.mkdir(exist_ok=True)
                        self._id_file.write_text(install_id)
                    except Exception:
                        pass
                    return install_id
            except Exception:
                pass

        # 3. Generate fresh UUID and persist
        new_id = str(uuid.uuid4())
        try:
            self.config_dir.mkdir(exist_ok=True)
            self._id_file.write_text(new_id)
        except Exception:
            pass
        return new_id

    def enable(self):
        """Enable telemetry"""
        self.config_dir.mkdir(exist_ok=True)

        config = {
            "enabled":         True,
            "installation_id": self.installation_id,
            "enabled_at":      datetime.utcnow().isoformat() + "Z",
            "version":         _VERSION,
        }

        with open(self.config_file, "w") as f:
            json.dump(config, f, indent=2)

        self.enabled = True

        print("✓ Telemetry enabled")
        print("\nWhat is sent with each event:")
        print("  • Event name (for example identity_created)")
        print("  • Random installation ID and PiQrypt version")
        print("  • Operating system, CPU architecture, terminal or not")
        print("\nWhat is NOT collected:")
        print("  • Agent IDs")
        print("  • Event payloads")
        print("  • Personal data")
        print("\nHelps us improve PiQrypt. Thank you! 🙏")

    def disable(self):
        """Disable telemetry"""
        if self.config_file.exists():
            try:
                with open(self.config_file) as f:
                    config = json.load(f)
                config["enabled"]     = False
                config["disabled_at"] = datetime.utcnow().isoformat() + "Z"
                with open(self.config_file, "w") as f:
                    json.dump(config, f, indent=2)
            except Exception:
                self.config_file.unlink()

        self.enabled = False
        print("✓ Telemetry disabled")

    def get_status(self) -> Dict[str, Any]:
        """Get telemetry status"""
        return {
            "enabled":         self.enabled,
            "installation_id": self.installation_id if self.enabled else "N/A",
        }

    def _send_to_server(self, event_type: str) -> None:
        """Send the anonymous event to the Trust Server (3 s timeout, errors ignored)."""
        if _env_disables_telemetry():
            return
        try:
            import urllib.request
            payload = json.dumps({
                "installation_id": self.installation_id,
                "version":         _VERSION,
                "event":           event_type,
                "system": {
                    "os":        _os_name,
                    "arch":      _arch,
                    "is_server": _is_server,
                },
            }).encode()
            req = urllib.request.Request(
                TELEMETRY_ENDPOINT,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=3)
        except Exception:
            pass  # silent fail — never block the user

    def track_event(
        self,
        event_name: str,
        properties: Optional[Dict[str, Any]] = None,
    ):
        """
        Track anonymous event

        Args:
            event_name: Event name (e.g., "identity_created", "event_signed")
            properties: Anonymous properties (no PII)
        """
        if not self.enabled:
            return

        event = {
            "event":           event_name,
            "timestamp":       datetime.utcnow().isoformat() + "Z",
            "installation_id": self.installation_id,
            "version":         _VERSION,
            "properties":      properties or {},
        }

        self._log_event(event)
        self._send_to_server(event_name)

    def _log_event(self, event: Dict[str, Any]):
        """Log event to local file."""
        log_file = self.config_dir / "telemetry.log"
        try:
            with open(log_file, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass  # Silent fail — telemetry must never break the app


# Global instance
_telemetry = Telemetry()


def track(event_name: str, **properties):
    """
    Track anonymous event (no-op when telemetry is disabled)

    Examples:
        track("identity_created", algorithm="Ed25519")
        track("event_signed", aiss_version="2.0", hybrid=True)
        track("chain_verified", events=100)
    """
    _telemetry.track_event(event_name, properties)


def enable_telemetry():
    """Enable telemetry"""
    _telemetry.enable()


def disable_telemetry():
    """Disable telemetry"""
    _telemetry.disable()


def is_telemetry_enabled() -> bool:
    """Check if telemetry is enabled"""
    return _telemetry.enabled


def get_telemetry_status() -> Dict[str, Any]:
    """Get telemetry status"""
    return _telemetry.get_status()


# Public API
__all__ = [
    "track",
    "enable_telemetry",
    "disable_telemetry",
    "is_telemetry_enabled",
    "get_telemetry_status",
    "TELEMETRY_ENDPOINT",
]
