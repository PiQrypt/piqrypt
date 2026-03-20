# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
notifier.py — Trust Gate Notifier

Active push notification for REQUIRE_HUMAN decisions.

When a decision enters the queue, Notifier immediately pushes
to all responsible principals via configured channels.

This is the difference between Vigil (passive dashboard — someone
must be watching) and Trust Gate (active push — someone is
interrupted regardless of whether they're watching).

Channels:
    webhook   — HTTP POST to any endpoint (generic)
    slack     — Slack Incoming Webhook
    email     — SMTP (optional)
    console   — stdout (dev/testing)

Compliance:
    ANSSI R9   — human must be reachable, not just notified if online
    AI Act Art.14 — effective human oversight requires active notification
    NIST MANAGE 2.2 — human oversight mechanism documented
"""

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import List, Optional

from trustgate.decision import Decision
from trustgate.human_principal import HumanPrincipal


# ─── Notification context ─────────────────────────────────────────────────────

@dataclass
class NotificationContext:
    """
    Complete context sent to principals for a REQUIRE_HUMAN decision.
    Must contain everything needed to make an informed approval decision.
    AI Act Art.13 — transparency about what is being decided.
    """
    decision_id:     str
    agent_id:        str
    agent_name:      str
    action:          str
    vrs:             float
    tsi_state:       str
    a2c_score:       float
    outcome:         str
    reason:          str
    policy_version:  str
    timestamp:       int
    timeout_at:      Optional[int]
    payload_summary: str           # human-readable summary — NOT raw payload

    # Links for Trust Gate Console
    approve_url:     str = ""
    reject_url:      str = ""

    # Severity label for notification urgency
    severity:        str = "WATCH"   # WATCH | ALERT | CRITICAL

    def minutes_remaining(self) -> Optional[int]:
        if self.timeout_at is None:
            return None
        remaining = self.timeout_at - int(time.time())
        return max(0, remaining // 60)

    def to_dict(self) -> dict:
        return {
            "decision_id":    self.decision_id,
            "agent_id":       self.agent_id,
            "agent_name":     self.agent_name,
            "action":         self.action,
            "vrs":            round(self.vrs, 3),
            "tsi_state":      self.tsi_state,
            "outcome":        self.outcome,
            "reason":         self.reason,
            "severity":       self.severity,
            "policy_version": self.policy_version,
            "timestamp":      self.timestamp,
            "timeout_at":     self.timeout_at,
            "minutes_remaining": self.minutes_remaining(),
            "payload_summary":self.payload_summary,
            "approve_url":    self.approve_url,
            "reject_url":     self.reject_url,
        }


# ─── Channel base class ───────────────────────────────────────────────────────

class NotificationChannel:
    """Base class for notification channels."""

    def send(
        self,
        context: NotificationContext,
        principals: List[HumanPrincipal],
    ) -> bool:
        """
        Send notification. Returns True on success, False on failure.
        Failures are logged but never raise — notification must not block.
        """
        raise NotImplementedError


# ─── Console channel (dev/testing) ────────────────────────────────────────────

class ConsoleChannel(NotificationChannel):
    """Prints to stdout — for development and smoke tests."""

    def send(
        self,
        context: NotificationContext,
        principals: List[HumanPrincipal],
    ) -> bool:
        names = [p.record.name for p in principals]
        print(
            f"\n[TrustGate] REQUIRE_HUMAN — {context.severity}\n"
            f"  Decision : {context.decision_id}\n"
            f"  Agent    : {context.agent_name} ({context.agent_id})\n"
            f"  Action   : {context.action}\n"
            f"  VRS      : {context.vrs:.3f} | TSI: {context.tsi_state}\n"
            f"  Reason   : {context.reason}\n"
            f"  Timeout  : {context.minutes_remaining()} min remaining\n"
            f"  Notify   : {', '.join(names)}\n"
            f"  Approve  : {context.approve_url or '(no URL configured)'}\n"
        )
        return True


# ─── Webhook channel ──────────────────────────────────────────────────────────

class WebhookChannel(NotificationChannel):
    """HTTP POST to any webhook endpoint."""

    def __init__(self, url: str, timeout_seconds: int = 10, headers: dict = None):
        self.url     = url
        self.timeout = timeout_seconds
        self.headers = headers or {"Content-Type": "application/json"}

    def send(
        self,
        context: NotificationContext,
        principals: List[HumanPrincipal],
    ) -> bool:
        payload = {
            "trustgate_event": "REQUIRE_HUMAN",
            "context":         context.to_dict(),
            "principals":      [p.record.name for p in principals],
        }
        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            self.url,
            data    = data,
            method  = "POST",
            headers = self.headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError):
            return False


# ─── Slack channel ────────────────────────────────────────────────────────────

class SlackChannel(NotificationChannel):
    """Slack Incoming Webhook notification."""

    SEVERITY_EMOJI = {
        "WATCH":    ":warning:",
        "ALERT":    ":rotating_light:",
        "CRITICAL": ":red_circle:",
    }

    def __init__(self, webhook_url: str, channel: str = ""):
        self.webhook_url = webhook_url
        self.channel     = channel

    def send(
        self,
        context: NotificationContext,
        principals: List[HumanPrincipal],
    ) -> bool:
        emoji   = self.SEVERITY_EMOJI.get(context.severity, ":warning:")
        mention = " ".join(f"@{p.record.name}" for p in principals)
        timeout_str = (
            f"{context.minutes_remaining()} min remaining"
            if context.minutes_remaining() is not None
            else "no timeout"
        )

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Trust Gate — Human Approval Required",
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Agent:*\n{context.agent_name}"},
                    {"type": "mrkdwn", "text": f"*Action:*\n`{context.action}`"},
                    {"type": "mrkdwn", "text": f"*VRS:*\n{context.vrs:.3f}"},
                    {"type": "mrkdwn", "text": f"*TSI:*\n{context.tsi_state}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{context.severity}"},
                    {"type": "mrkdwn", "text": f"*Timeout:*\n{timeout_str}"},
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Reason:* {context.reason}",
                }
            },
        ]

        if context.approve_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Approve"},
                        "style": "primary",
                        "url":  context.approve_url,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "❌ Reject"},
                        "style": "danger",
                        "url":  context.reject_url,
                    },
                ]
            })

        if mention:
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"Assigned to: {mention}"}]
            })

        payload = {"blocks": blocks}
        if self.channel:
            payload["channel"] = self.channel

        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            self.webhook_url,
            data    = data,
            method  = "POST",
            headers = {"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError):
            return False


# ─── Notifier ─────────────────────────────────────────────────────────────────

class Notifier:
    """
    Push notifications for REQUIRE_HUMAN decisions.

    Configured with one or more channels.
    Sends to all principals assigned to a decision.

    Failures are logged but never block — the decision queue is the
    source of truth, not the notification system.
    """

    def __init__(
        self,
        channels: Optional[List[NotificationChannel]] = None,
        console_server_base_url: str = "http://localhost:8422",
    ):
        self.channels   = channels or [ConsoleChannel()]
        self.base_url   = console_server_base_url.rstrip("/")
        self._sent: int = 0
        self._failed: int = 0

    def push(
        self,
        decision: Decision,
        principals: List[HumanPrincipal],
    ) -> dict:
        """
        Push notification for a REQUIRE_HUMAN decision to all principals.

        Returns:
            {"sent": N, "failed": N, "channels": [...status...]}
        """
        context = self._build_context(decision)
        results = []

        for channel in self.channels:
            try:
                ok = channel.send(context, principals)
                results.append({"channel": type(channel).__name__, "ok": ok})
                if ok:
                    self._sent += 1
                else:
                    self._failed += 1
            except Exception as e:
                results.append({
                    "channel": type(channel).__name__,
                    "ok": False,
                    "error": str(e),
                })
                self._failed += 1

        return {
            "decision_id": decision.decision_id,
            "sent":        sum(1 for r in results if r["ok"]),
            "failed":      sum(1 for r in results if not r["ok"]),
            "channels":    results,
        }

    def _build_context(self, decision: Decision) -> NotificationContext:
        """
        Build notification context from a Decision.
        AI Act Art.13 — transparent, human-readable context.
        """
        # Determine severity
        if decision.vrs_at_decision >= 0.75:
            severity = "CRITICAL"
        elif decision.vrs_at_decision >= 0.50:
            severity = "ALERT"
        else:
            severity = "WATCH"

        return NotificationContext(
            decision_id     = decision.decision_id,
            agent_id        = decision.agent_id,
            agent_name      = decision.agent_name,
            action          = decision.action,
            vrs             = decision.vrs_at_decision,
            tsi_state       = decision.tsi_state,
            a2c_score       = decision.a2c_score,
            outcome         = decision.outcome,
            reason          = decision.reason,
            policy_version  = decision.policy_version,
            timestamp       = decision.timestamp,
            timeout_at      = decision.timeout_at,
            payload_summary = f"action={decision.action} payload_hash={decision.payload_hash}",
            severity        = severity,
            approve_url     = (
                f"{self.base_url}/api/decisions/{decision.decision_id}/approve"
            ),
            reject_url      = (
                f"{self.base_url}/api/decisions/{decision.decision_id}/reject"
            ),
        )

    @classmethod
    def from_policy(
        cls,
        notification_policy,
        console_server_base_url: str = "http://localhost:8422",
    ) -> "Notifier":
        """
        Build a Notifier from a NotificationPolicy (loaded from policy.yaml).
        """
        channels: List[NotificationChannel] = []

        for ch_config in notification_policy.channels:
            ch_type = ch_config.get("type", "")
            if ch_type == "webhook":
                channels.append(WebhookChannel(
                    url             = ch_config["url"],
                    timeout_seconds = ch_config.get("timeout", 10),
                    headers         = ch_config.get("headers"),
                ))
            elif ch_type == "slack":
                channels.append(SlackChannel(
                    webhook_url = ch_config["url"],
                    channel     = ch_config.get("channel", ""),
                ))
            elif ch_type == "console":
                channels.append(ConsoleChannel())

        # Always add console in dev mode (no channels configured)
        if not channels:
            channels.append(ConsoleChannel())

        return cls(
            channels                = channels,
            console_server_base_url = console_server_base_url,
        )
