# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# PROPRIETARY METHOD -- Dual License
# This file contains original algorithmic methods protected by
# e-Soleau deposits DSO2026006483 and DSO2026009143 (INPI France).
#
# Licensed under the Elastic License 2.0 (ELv2) for open/internal use.
# A separate commercial license is required for:
#   - SaaS or managed service deployment to third parties
#   - Proprietary products embedding this method
#   - OEM or white-label use
# Commercial license: contact@piqrypt.com -- Subject: Commercial License Inquiry

"""
policy_loader.py — Trust Gate Policy Loader

Loads, validates and manages policy.yaml files.

Compliance:
    ANSSI R35  — policy file integrity (SHA-256 hash on load)
    ANSSI R29  — policy_version + policy_hash in every decision
    NIST GOVERN 6.2 — policies reviewed and updated with audit trail
    AI Act Art.9  — risk management system documented and maintained
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Optional YAML support — fallback to json if not available
try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# ─── Exceptions ───────────────────────────────────────────────────────────────

class PolicyLoadError(Exception):
    """Policy file cannot be loaded or parsed."""

class PolicyIntegrityError(Exception):
    """Policy file hash mismatch — possible tampering. ANSSI R35."""

class PolicyValidationError(Exception):
    """Policy file is structurally invalid."""


# ─── Policy dataclasses ───────────────────────────────────────────────────────

@dataclass
class RolePolicy:
    allowed_tools: List[str] = field(default_factory=list)
    blocked_tools: List[str] = field(default_factory=list)

    def can_use(self, tool: str) -> bool:
        if "*" in self.blocked_tools:
            return False
        if tool in self.blocked_tools:
            return False
        if "*" in self.allowed_tools:
            return True
        return tool in self.allowed_tools


@dataclass
class ThresholdPolicy:
    vrs_require_human:    float = 0.60
    vrs_block:            float = 0.85
    tsi_unstable_action:  str   = "REQUIRE_HUMAN"
    tsi_critical_action:  str   = "BLOCK"


@dataclass
class EscalationPolicy:
    max_watch_events:       int = 3
    auto_restrict_after:    int = 5
    restrict_duration_minutes: int = 60


@dataclass
class NetworkPolicy:
    allowed_domains:  List[str] = field(default_factory=list)
    block_external:   bool      = True
    log_external_calls: bool    = True


@dataclass
class NotificationPolicy:
    timeout_seconds:        int  = 300
    on_timeout:             str  = "REJECT"    # REJECT | BLOCK | ESCALATE
    require_justification:  bool = False
    channels:               List[Dict] = field(default_factory=list)
    principals:             List[str]  = field(default_factory=list)


@dataclass
class Policy:
    # ── Metadata ──────────────────────────────────────────────────────────────
    version:     str = "1.0"
    name:        str = "default"
    profile:     str = "custom"     # anssi_strict | nist_balanced | ai_act_high_risk
    author:      str = ""
    created_at:  int = field(default_factory=lambda: int(time.time()))

    # ── Integrity — ANSSI R35 ─────────────────────────────────────────────────
    content_hash: str = ""          # SHA-256 of raw file content

    # ── Sections ──────────────────────────────────────────────────────────────
    thresholds:    ThresholdPolicy    = field(default_factory=ThresholdPolicy)
    roles:         Dict[str, RolePolicy] = field(default_factory=dict)
    escalation:    EscalationPolicy   = field(default_factory=EscalationPolicy)
    network:       NetworkPolicy      = field(default_factory=NetworkPolicy)
    notification:  NotificationPolicy = field(default_factory=NotificationPolicy)
    dangerous_patterns: List[str]     = field(default_factory=list)

    def get_role(self, role_name: str) -> RolePolicy:
        return self.roles.get(role_name, RolePolicy())

    def to_version_id(self) -> str:
        """Short version identifier for Decision records."""
        return f"{self.name}@{self.version}"


# ─── Loader ───────────────────────────────────────────────────────────────────

def load_policy(path: Path, verify_hash: Optional[str] = None) -> Policy:
    """
    Load and validate a policy file.

    Args:
        path:        Path to policy.yaml or policy.json
        verify_hash: Expected SHA-256 hash — raises PolicyIntegrityError if mismatch.
                     ANSSI R35: must be verified in production.

    Returns:
        Validated Policy object.

    Raises:
        PolicyLoadError:       File not found or cannot be parsed
        PolicyIntegrityError:  Hash mismatch — ANSSI R35
        PolicyValidationError: Schema validation failure
    """
    if not path.exists():
        raise PolicyLoadError(f"Policy file not found: {path}")

    raw = path.read_bytes()

    # ── Integrity check — ANSSI R35 ──────────────────────────────────────────
    computed_hash = hashlib.sha256(raw).hexdigest()
    if verify_hash and computed_hash != verify_hash:
        raise PolicyIntegrityError(
            f"Policy integrity check failed.\n"
            f"  Expected : {verify_hash}\n"
            f"  Got      : {computed_hash}\n"
            f"  File     : {path}\n"
            f"Policy may have been tampered with. — ANSSI R35"
        )

    # ── Parse ─────────────────────────────────────────────────────────────────
    try:
        suffix = path.suffix.lower()
        if suffix in (".yaml", ".yml"):
            if not _HAS_YAML:
                raise PolicyLoadError(
                    "PyYAML not installed. Install with: pip install pyyaml"
                )
            data = yaml.safe_load(raw.decode("utf-8"))
        elif suffix == ".json":
            data = json.loads(raw.decode("utf-8"))
        else:
            raise PolicyLoadError(f"Unsupported policy format: {suffix} (use .yaml or .json)")
    except (yaml.YAMLError if _HAS_YAML else Exception) as e:
        raise PolicyLoadError(f"Cannot parse policy file: {e}")

    # ── Validate & build ──────────────────────────────────────────────────────
    policy = _build_policy(data)
    policy.content_hash = computed_hash
    _validate(policy)
    return policy


def compute_policy_hash(path: Path) -> str:
    """Return SHA-256 of a policy file — for storage in Decision records."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ─── Internal builders ────────────────────────────────────────────────────────

def _build_policy(data: dict) -> Policy:
    p = Policy()
    p.version    = str(data.get("version", "1.0"))
    p.name       = str(data.get("name", "default"))
    p.profile    = str(data.get("profile", "custom"))
    p.author     = str(data.get("author", ""))
    p.created_at = int(data.get("created_at", int(time.time())))

    # Thresholds
    t = data.get("thresholds", {})
    p.thresholds = ThresholdPolicy(
        vrs_require_human   = float(t.get("vrs_require_human", 0.60)),
        vrs_block           = float(t.get("vrs_block", 0.85)),
        tsi_unstable_action = str(t.get("tsi_unstable_action", "REQUIRE_HUMAN")),
        tsi_critical_action = str(t.get("tsi_critical_action", "BLOCK")),
    )

    # Roles
    roles_data = data.get("roles", {})
    for role_name, role_data in roles_data.items():
        p.roles[role_name] = RolePolicy(
            allowed_tools = list(role_data.get("allowed_tools", [])),
            blocked_tools = list(role_data.get("blocked_tools", [])),
        )

    # Escalation
    esc = data.get("escalation", {})
    p.escalation = EscalationPolicy(
        max_watch_events          = int(esc.get("max_watch_events", 3)),
        auto_restrict_after       = int(esc.get("auto_restrict_after", 5)),
        restrict_duration_minutes = int(esc.get("restrict_duration_minutes", 60)),
    )

    # Network
    net = data.get("network", {})
    p.network = NetworkPolicy(
        allowed_domains   = list(net.get("allowed_domains", [])),
        block_external    = bool(net.get("block_external", True)),
        log_external_calls= bool(net.get("log_external_calls", True)),
    )

    # Notification
    notif = data.get("notification", {})
    p.notification = NotificationPolicy(
        timeout_seconds       = int(notif.get("timeout_seconds", 300)),
        on_timeout            = str(notif.get("on_timeout", "REJECT")),
        require_justification = bool(notif.get("require_justification", False)),
        channels              = list(notif.get("channels", [])),
        principals            = list(notif.get("principals", [])),
    )

    # Dangerous patterns
    p.dangerous_patterns = [str(p_) for p_ in data.get("dangerous_patterns", [])]

    return p


def _validate(p: Policy) -> None:
    """Structural validation — raises PolicyValidationError on failure."""
    errors = []

    if not (0.0 < p.thresholds.vrs_require_human < 1.0):
        errors.append("thresholds.vrs_require_human must be in (0, 1)")

    if not (0.0 < p.thresholds.vrs_block < 1.0):
        errors.append("thresholds.vrs_block must be in (0, 1)")

    if p.thresholds.vrs_require_human >= p.thresholds.vrs_block:
        errors.append(
            "thresholds.vrs_require_human must be < thresholds.vrs_block"
        )

    valid_outcomes = {"ALLOW", "REQUIRE_HUMAN", "BLOCK", "RESTRICTED"}
    if p.thresholds.tsi_unstable_action not in valid_outcomes:
        errors.append(f"thresholds.tsi_unstable_action must be one of {valid_outcomes}")

    if p.thresholds.tsi_critical_action not in valid_outcomes:
        errors.append(f"thresholds.tsi_critical_action must be one of {valid_outcomes}")

    valid_on_timeout = {"REJECT", "BLOCK", "ESCALATE"}
    if p.notification.on_timeout not in valid_on_timeout:
        errors.append(f"notification.on_timeout must be one of {valid_on_timeout}")

    if errors:
        raise PolicyValidationError(
            "Policy validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
        )
