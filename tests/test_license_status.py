# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
"""Tests for License._status_fields() and info() trial/status/days_left fields."""
from __future__ import annotations

import time
import unittest

from aiss.license import License, TIERS


def _make_license(tier: str, payload_extra=None) -> License:
    lic = License.__new__(License)
    lic._tier = tier
    payload = {
        "tier": tier,
        "license_id": f"test_{tier}",
        "agents_max": TIERS[tier]["agents_max"],
        "events_month": TIERS[tier]["events_month"],
        "expires_at": None,
    }
    if payload_extra:
        payload.update(payload_extra)
    lic._payload = payload
    lic._loaded_at = 0.0
    return lic


class TestLicenseStatusFields(unittest.TestCase):

    def test_free_status(self):
        lic = _make_license("free")
        fields = lic._status_fields()
        self.assertEqual(fields["status"], "free")
        self.assertFalse(fields["trial"])
        self.assertIsNone(fields["days_left"])

    def test_pro_active_future_expiry(self):
        future = time.time() + 365 * 86400
        lic = _make_license("pro", {"expires_at": future})
        fields = lic._status_fields()
        self.assertEqual(fields["status"], "active")
        self.assertFalse(fields["trial"])
        self.assertIsNotNone(fields["days_left"])
        self.assertGreater(fields["days_left"], 0)

    def test_trial_status_and_days_left(self):
        future = time.time() + 30 * 86400
        lic = _make_license("pro", {"expires_at": future, "trial": True,
                                     "license_id": "trial-abc123"})
        fields = lic._status_fields()
        self.assertEqual(fields["status"], "trial")
        self.assertTrue(fields["trial"])
        self.assertEqual(fields["days_left"], 30)

    def test_expired_within_grace_gives_grace(self):
        past = time.time() - 3600  # 1 hour ago
        lic = _make_license("pro", {"expires_at": past})
        fields = lic._status_fields()
        self.assertEqual(fields["status"], "grace")

    def test_days_left_never_negative(self):
        past = time.time() - 10 * 86400
        lic = _make_license("pro", {"expires_at": past})
        fields = lic._status_fields()
        self.assertGreaterEqual(fields["days_left"], 0)

    def test_info_contains_all_previous_keys(self):
        lic = _make_license("pro", {"expires_at": time.time() + 86400})
        info = lic.info()
        for key in ("tier", "license_id", "agents_max", "events_month",
                    "expires_at", "features", "validation", "local_first"):
            self.assertIn(key, info, f"Missing key: {key}")

    def test_info_contains_status_trial_days_left(self):
        lic = _make_license("pro", {"expires_at": time.time() + 86400})
        info = lic.info()
        self.assertIn("status", info)
        self.assertIn("trial", info)
        self.assertIn("days_left", info)

    def test_free_info_status_free(self):
        lic = _make_license("free")
        info = lic.info()
        self.assertEqual(info["status"], "free")
        self.assertFalse(info["trial"])
        self.assertIsNone(info["days_left"])


if __name__ == "__main__":
    unittest.main()
