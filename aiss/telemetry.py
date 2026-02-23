"""
Opt-in Telemetry for PiQrypt

Anonymous usage statistics to improve the project.
Users must explicitly opt-in. No PII collected.

Enable:
    piqrypt telemetry enable

Disable:
    piqrypt telemetry disable

Status:
    piqrypt telemetry status
"""

import os
import json
import uuid
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime


class Telemetry:
    """
    Anonymous telemetry collection (opt-in only)

    Collected data:
      - Event types (identity_created, event_signed, etc.)
      - Feature usage (aiss1, aiss2, exports)
      - Error types (for debugging)
      - Version info

    NOT collected:
      - Agent IDs
      - Event payloads
      - Any personal data
      - IP addresses (when server implemented)
    """

    def __init__(self):
        self.config_dir = Path.home() / ".piqrypt"
        self.config_file = self.config_dir / "telemetry.json"
        self.enabled = self._check_enabled()
        self.installation_id = self._get_installation_id()

    def _check_enabled(self) -> bool:
        """Check if telemetry is enabled"""
        # Environment variable override (disable)
        if os.getenv("PIQRYPT_TELEMETRY") == "0":
            return False

        # Check config file
        if self.config_file.exists():
            try:
                with open(self.config_file) as f:
                    config = json.load(f)
                    return config.get("enabled", False)
            except:
                return False

        return False

    def _get_installation_id(self) -> str:
        """Get or create anonymous installation ID (UUID)"""
        if self.config_file.exists():
            try:
                with open(self.config_file) as f:
                    config = json.load(f)
                    install_id = config.get("installation_id")
                    if install_id:
                        return install_id
            except Exception:
                pass

        # Generate new UUID
        return str(uuid.uuid4())

    def enable(self):
        """Enable telemetry"""
        self.config_dir.mkdir(exist_ok=True)

        config = {
            "enabled": True,
            "installation_id": self.installation_id,
            "enabled_at": datetime.utcnow().isoformat() + "Z",
            "version": "1.1.0"
        }

        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)

        self.enabled = True

        print("✓ Telemetry enabled")
        print("\nWhat is collected:")
        print("  • Feature usage (anonymous)")
        print("  • Error types")
        print("  • Performance metrics")
        print("\nWhat is NOT collected:")
        print("  • Agent IDs")
        print("  • Event payloads")
        print("  • Personal data")
        print("\nHelps us improve PiQrypt. Thank you! 🙏")

    def disable(self):
        """Disable telemetry"""
        if self.config_file.exists():
            # Keep installation_id but disable
            try:
                with open(self.config_file) as f:
                    config = json.load(f)

                config["enabled"] = False
                config["disabled_at"] = datetime.utcnow().isoformat() + "Z"

                with open(self.config_file, 'w') as f:
                    json.dump(config, f, indent=2)
            except Exception:
                self.config_file.unlink()

        self.enabled = False
        print("✓ Telemetry disabled")

    def get_status(self) -> Dict[str, Any]:
        """Get telemetry status"""
        return {
            "enabled": self.enabled,
            "installation_id": self.installation_id if self.enabled else "N/A"
        }

    def track_event(
        self,
        event_name: str,
        properties: Optional[Dict[str, Any]] = None
    ):
        """
        Track anonymous event

        Args:
            event_name: Event name (e.g., "identity_created", "event_signed")
            properties: Anonymous properties (no PII)
        """
        if not self.enabled:
            return

        # Build event
        event = {
            "event": event_name,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "installation_id": self.installation_id,
            "version": "1.1.0",
            "properties": properties or {}
        }

        # In production, send to telemetry server
        # For now, log locally
        self._log_event(event)

    def _log_event(self, event: Dict[str, Any]):
        """Log event to local file (development/testing)"""
        log_file = self.config_dir / "telemetry.log"

        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass  # Silent fail (telemetry should never break app)


# Global instance
_telemetry = Telemetry()


def track(event_name: str, **properties):
    """
    Track anonymous event (if opt-in enabled)

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
]
