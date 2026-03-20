"""
Tests — aiss/license.py  (v1.7.1)
Un test par feature par tier interdit.
Documentation vivante des droits d'accès.

Changelog v1.7.1:
- Tier "startup" ajouté entre pro et team
- vigil passe de "readonly" à "full" en Free
- Nouveaux champs: vigil_alerts_full, vigil_vrs_days, vigil_bridge_limit
- Quotas certification: cert_simple_month, cert_timestamp_month, cert_pq_month
- TIER_ORDER mis à jour: ["free", "pro", "startup", "team", "business", "enterprise"]
"""
import sys
import unittest
from unittest.mock import MagicMock


# ── Mock PyNaCl pour les tests offline ───────────────────────────────────────
class _MockVerifyKey:
    def __init__(self, key): pass
    def verify(self, msg, sig):
        pass

_mock_nacl = MagicMock()
_mock_nacl.signing.VerifyKey = _MockVerifyKey
_mock_nacl.exceptions.BadSignatureError = Exception
sys.modules.setdefault("nacl", _mock_nacl)
sys.modules.setdefault("nacl.signing", _mock_nacl.signing)
sys.modules.setdefault("nacl.exceptions", _mock_nacl.exceptions)

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aiss.license import (
    License, TIERS, TIER_ORDER,
    FeatureNotAvailableError, QuotaExceededError, require_pro,
)


def _make_license(tier: str) -> License:
    """Crée une instance License patchée sur un tier donné."""
    lic = License.__new__(License)
    lic._tier = tier
    lic._payload = {
        "tier": tier,
        "license_id": f"test_{tier}",
        "agents_max": TIERS[tier]["agents_max"],
        "events_month": TIERS[tier]["events_month"],
        "expires_at": None,
    }
    lic._loaded_at = 0.0
    return lic


# ══════════════════════════════════════════════════════════════════════════════
# TIERS — structure et cohérence
# ══════════════════════════════════════════════════════════════════════════════

class TestTiersStructure(unittest.TestCase):

    def test_all_tiers_present(self):
        for t in ["free", "pro", "startup", "team", "business", "enterprise"]:
            self.assertIn(t, TIERS, f"Tier '{t}' missing from TIERS")

    def test_tier_order_complete(self):
        self.assertEqual(
            TIER_ORDER,
            ["free", "pro", "startup", "team", "business", "enterprise"]
        )

    def test_agents_max_non_decreasing(self):
        # free(3) <= pro(50) = startup(50) <= team(150) <= business(500)
        prev = 0
        for t in TIER_ORDER[:-1]:  # skip enterprise (None)
            val = TIERS[t]["agents_max"]
            self.assertGreaterEqual(val, prev,
                f"agents_max should not decrease: {t}={val} < {prev}")
            prev = val

    def test_pro_startup_same_agents(self):
        # startup et pro ont le même agents_max — feature différenciation via events
        self.assertEqual(TIERS["pro"]["agents_max"], TIERS["startup"]["agents_max"])

    def test_startup_more_events_than_pro(self):
        self.assertGreater(
            TIERS["startup"]["events_month"],
            TIERS["pro"]["events_month"]
        )

    def test_enterprise_is_unlimited(self):
        self.assertIsNone(TIERS["enterprise"]["agents_max"])
        self.assertIsNone(TIERS["enterprise"]["events_month"])

    def test_all_tiers_have_required_keys(self):
        required = [
            "agents_max", "events_month", "quantum", "tsa_rfc3161",
            "pqz_certified", "vigil", "trustgate", "validation",
            # v1.7.1 new keys
            "vigil_alerts_full", "vigil_vrs_days", "vigil_bridge_limit",
            "cert_timestamp_month", "cert_pq_month",
        ]
        for tier, cfg in TIERS.items():
            for key in required:
                self.assertIn(key, cfg, f"Tier '{tier}' missing key '{key}'")
        # Free uses cert_simple_once (one-time gift); paid tiers use cert_simple_month
        self.assertIn("cert_simple_once", TIERS["free"])
        for tier in ["pro", "startup", "team", "business", "enterprise"]:
            self.assertIn("cert_simple_month", TIERS[tier],
                          f"Paid tier '{tier}' missing key 'cert_simple_month'")

    def test_free_has_no_price(self):
        self.assertEqual(TIERS["free"]["price_monthly"], 0)
        self.assertEqual(TIERS["free"]["price_annual"], 0)

    def test_enterprise_price_is_none(self):
        self.assertIsNone(TIERS["enterprise"]["price_monthly"])
        self.assertIsNone(TIERS["enterprise"]["price_annual"])

    def test_startup_price(self):
        self.assertEqual(TIERS["startup"]["price_annual"], 990)

    def test_team_price_updated(self):
        self.assertEqual(TIERS["team"]["price_annual"], 2_990)

    def test_business_events_20m(self):
        self.assertEqual(TIERS["business"]["events_month"], 20_000_000)


# ══════════════════════════════════════════════════════════════════════════════
# VIGIL FEATURES — nouveaux champs v1.7.1
# ══════════════════════════════════════════════════════════════════════════════

class TestVigilFeatures(unittest.TestCase):

    def test_free_vigil_is_full(self):
        # v1.7.1: Free Vigil est full (pas readonly)
        self.assertEqual(TIERS["free"]["vigil"], "full")

    def test_free_vigil_alerts_not_full(self):
        # Free: alertes CRITICAL seulement
        self.assertFalse(TIERS["free"]["vigil_alerts_full"])

    def test_pro_vigil_alerts_full(self):
        self.assertTrue(TIERS["pro"]["vigil_alerts_full"])

    def test_free_vrs_history_7_days(self):
        self.assertEqual(TIERS["free"]["vigil_vrs_days"], 7)

    def test_pro_vrs_history_90_days(self):
        self.assertEqual(TIERS["pro"]["vigil_vrs_days"], 90)

    def test_startup_vrs_history_90_days(self):
        self.assertEqual(TIERS["startup"]["vigil_vrs_days"], 90)

    def test_enterprise_vrs_history_unlimited(self):
        self.assertIsNone(TIERS["enterprise"]["vigil_vrs_days"])

    def test_free_bridge_limit_is_2(self):
        self.assertEqual(TIERS["free"]["vigil_bridge_limit"], 2)

    def test_pro_bridge_limit_is_none(self):
        # None = unlimited
        self.assertIsNone(TIERS["pro"]["vigil_bridge_limit"])

    def test_startup_bridge_limit_is_none(self):
        self.assertIsNone(TIERS["startup"]["vigil_bridge_limit"])

    def test_all_paid_tiers_full_alerts(self):
        for t in ["pro", "startup", "team", "business", "enterprise"]:
            self.assertTrue(
                TIERS[t]["vigil_alerts_full"],
                f"Tier '{t}' should have full alerts"
            )

    def test_all_paid_tiers_90d_history(self):
        for t in ["pro", "startup", "team", "business"]:
            self.assertEqual(
                TIERS[t]["vigil_vrs_days"], 90,
                f"Tier '{t}' should have 90-day VRS history"
            )


# ══════════════════════════════════════════════════════════════════════════════
# CERTIFICATION QUOTAS
# ══════════════════════════════════════════════════════════════════════════════

class TestCertificationQuotas(unittest.TestCase):

    def test_free_no_certifications(self):
        # Free: 1 Simple offerte à l'activation (cert_simple_once), pas de quota mensuel
        self.assertTrue(TIERS["free"]["cert_simple_once"])
        self.assertEqual(TIERS["free"]["cert_timestamp_month"], 0)
        self.assertEqual(TIERS["free"]["cert_pq_month"],        0)

    def test_pro_gets_simple_certifications(self):
        self.assertEqual(TIERS["pro"]["cert_simple_month"],    10)
        self.assertEqual(TIERS["pro"]["cert_timestamp_month"], 0)
        self.assertEqual(TIERS["pro"]["cert_pq_month"],        0)

    def test_startup_gets_timestamp_certifications(self):
        self.assertEqual(TIERS["startup"]["cert_simple_month"],    0)
        self.assertEqual(TIERS["startup"]["cert_timestamp_month"], 5)
        self.assertEqual(TIERS["startup"]["cert_pq_month"],        0)

    def test_team_gets_timestamp_certifications(self):
        self.assertEqual(TIERS["team"]["cert_timestamp_month"], 10)

    def test_business_gets_pq_certifications(self):
        self.assertEqual(TIERS["business"]["cert_pq_month"],  5)
        self.assertEqual(TIERS["business"]["cert_simple_month"], 0)

    def test_enterprise_certifications_custom(self):
        # None = custom volume (negotiated)
        self.assertIsNone(TIERS["enterprise"]["cert_simple_month"])
        self.assertIsNone(TIERS["enterprise"]["cert_timestamp_month"])
        self.assertIsNone(TIERS["enterprise"]["cert_pq_month"])

    def test_certification_upgrade_path(self):
        # Each tier gets a higher-value certification type
        # free: none → pro: Simple → startup: Timestamp → business: PQ
        self.assertEqual(TIERS["pro"]["cert_simple_month"],        10)
        self.assertEqual(TIERS["startup"]["cert_timestamp_month"],  5)
        self.assertEqual(TIERS["team"]["cert_timestamp_month"],    10)
        self.assertEqual(TIERS["business"]["cert_pq_month"],        5)


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE GATES — Free
# ══════════════════════════════════════════════════════════════════════════════

class TestFreeTierRestrictions(unittest.TestCase):

    def setUp(self):
        self.lic = _make_license("free")

    def test_free_cannot_quantum(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("quantum")

    def test_free_cannot_tsa(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("tsa_rfc3161")

    def test_free_cannot_pqz_certified(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("pqz_certified")

    def test_free_cannot_trustgate_manual(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require_trustgate("manual")

    def test_free_cannot_trustgate_full(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require_trustgate("full")

    def test_free_cannot_siem(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("siem")

    def test_free_cannot_sso(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("sso")

    def test_free_cannot_multi_org(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("multi_org")

    def test_free_cannot_team_workspace(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("team_workspace")

    def test_free_can_pqz_memory(self):
        self.assertTrue(self.lic.has_feature("pqz_memory"))

    def test_free_vigil_is_full(self):
        # v1.7.1: Vigil full (not readonly) for Free
        self.assertEqual(self.lic.get_feature_level("vigil"), "full")

    def test_free_vigil_alerts_not_full(self):
        self.assertFalse(TIERS["free"]["vigil_alerts_full"])

    def test_free_bridge_limit_is_2(self):
        self.assertEqual(TIERS["free"]["vigil_bridge_limit"], 2)

    def test_free_trustgate_is_none(self):
        self.assertIsNone(self.lic.get_feature_level("trustgate"))

    def test_free_validation_is_hmac(self):
        self.assertEqual(TIERS["free"]["validation"], "hmac")

    def test_free_vrs_history_7_days(self):
        self.assertEqual(TIERS["free"]["vigil_vrs_days"], 7)


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE GATES — Pro
# ══════════════════════════════════════════════════════════════════════════════

class TestProTierFeatures(unittest.TestCase):

    def setUp(self):
        self.lic = _make_license("pro")

    def test_pro_has_quantum(self):
        self.lic.require("quantum")

    def test_pro_has_tsa(self):
        self.lic.require("tsa_rfc3161")

    def test_pro_has_pqz_certified(self):
        self.lic.require("pqz_certified")

    def test_pro_has_trustgate_manual(self):
        self.lic.require_trustgate("manual")

    def test_pro_cannot_trustgate_full(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require_trustgate("full")

    def test_pro_cannot_siem(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("siem")

    def test_pro_cannot_sso(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("sso")

    def test_pro_cannot_multi_org(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("multi_org")

    def test_pro_cannot_team_workspace(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("team_workspace")

    def test_pro_vigil_is_full(self):
        self.assertEqual(self.lic.get_feature_level("vigil"), "full")

    def test_pro_trustgate_is_manual(self):
        self.assertEqual(self.lic.get_feature_level("trustgate"), "manual")

    def test_pro_full_alerts(self):
        self.assertTrue(TIERS["pro"]["vigil_alerts_full"])

    def test_pro_90_day_history(self):
        self.assertEqual(TIERS["pro"]["vigil_vrs_days"], 90)

    def test_pro_unlimited_bridges(self):
        self.assertIsNone(TIERS["pro"]["vigil_bridge_limit"])

    def test_pro_cert_simple_10(self):
        self.assertEqual(TIERS["pro"]["cert_simple_month"], 10)


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE GATES — Startup (nouveau tier v1.7.1)
# ══════════════════════════════════════════════════════════════════════════════

class TestStartupTierFeatures(unittest.TestCase):

    def setUp(self):
        self.lic = _make_license("startup")

    def test_startup_has_quantum(self):
        self.lic.require("quantum")

    def test_startup_has_tsa(self):
        self.lic.require("tsa_rfc3161")

    def test_startup_has_pqz_certified(self):
        self.lic.require("pqz_certified")

    def test_startup_has_trustgate_manual(self):
        self.lic.require_trustgate("manual")

    def test_startup_cannot_trustgate_full(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require_trustgate("full")

    def test_startup_has_team_workspace(self):
        self.lic.require("team_workspace")

    def test_startup_cannot_siem(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("siem")

    def test_startup_cannot_sso(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("sso")

    def test_startup_cannot_multi_org(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("multi_org")

    def test_startup_vigil_is_full(self):
        self.assertEqual(self.lic.get_feature_level("vigil"), "full")

    def test_startup_full_alerts(self):
        self.assertTrue(TIERS["startup"]["vigil_alerts_full"])

    def test_startup_90_day_history(self):
        self.assertEqual(TIERS["startup"]["vigil_vrs_days"], 90)

    def test_startup_cert_timestamp_5(self):
        self.assertEqual(TIERS["startup"]["cert_timestamp_month"], 5)

    def test_startup_more_events_than_pro(self):
        self.assertGreater(
            TIERS["startup"]["events_month"],
            TIERS["pro"]["events_month"]
        )

    def test_startup_is_above_pro(self):
        self.assertTrue(self.lic.is_tier_or_above("pro"))

    def test_startup_is_not_above_team(self):
        self.assertFalse(self.lic.is_tier_or_above("team"))


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE GATES — Team
# ══════════════════════════════════════════════════════════════════════════════

class TestTeamTierFeatures(unittest.TestCase):

    def setUp(self):
        self.lic = _make_license("team")

    def test_team_has_quantum(self):
        self.lic.require("quantum")

    def test_team_has_trustgate_manual(self):
        self.lic.require_trustgate("manual")

    def test_team_has_team_workspace(self):
        self.lic.require("team_workspace")

    def test_team_cannot_trustgate_full(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require_trustgate("full")

    def test_team_cannot_siem(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("siem")

    def test_team_cannot_sso(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("sso")

    def test_team_cert_timestamp_10(self):
        self.assertEqual(TIERS["team"]["cert_timestamp_month"], 10)

    def test_team_is_above_startup(self):
        self.assertTrue(self.lic.is_tier_or_above("startup"))

    def test_team_is_not_above_business(self):
        self.assertFalse(self.lic.is_tier_or_above("business"))


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE GATES — Business
# ══════════════════════════════════════════════════════════════════════════════

class TestBusinessTierFeatures(unittest.TestCase):

    def setUp(self):
        self.lic = _make_license("business")

    def test_business_has_trustgate_full(self):
        self.lic.require_trustgate("full")

    def test_business_has_siem(self):
        self.lic.require("siem")

    def test_business_has_multi_org(self):
        self.lic.require("multi_org")

    def test_business_cannot_sso(self):
        with self.assertRaises(FeatureNotAvailableError):
            self.lic.require("sso")

    def test_business_cert_pq_5(self):
        self.assertEqual(TIERS["business"]["cert_pq_month"], 5)

    def test_business_events_20m(self):
        self.assertEqual(TIERS["business"]["events_month"], 20_000_000)


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE GATES — Enterprise
# ══════════════════════════════════════════════════════════════════════════════

class TestEnterpriseTierFeatures(unittest.TestCase):

    def setUp(self):
        self.lic = _make_license("enterprise")

    def test_enterprise_has_all_features(self):
        for feature in ["quantum", "tsa_rfc3161", "pqz_certified",
                        "siem", "multi_org", "sso", "team_workspace"]:
            self.lic.require(feature)

    def test_enterprise_has_trustgate_full(self):
        self.lic.require_trustgate("full")

    def test_enterprise_agents_unlimited(self):
        self.assertIsNone(self.lic.agents_max)

    def test_enterprise_events_unlimited(self):
        self.assertIsNone(self.lic.events_month)

    def test_enterprise_vrs_unlimited(self):
        self.assertIsNone(TIERS["enterprise"]["vigil_vrs_days"])

    def test_enterprise_cert_custom(self):
        self.assertIsNone(TIERS["enterprise"]["cert_pq_month"])


# ══════════════════════════════════════════════════════════════════════════════
# QUOTAS
# ══════════════════════════════════════════════════════════════════════════════

class TestQuotaEnforcement(unittest.TestCase):

    def test_free_agents_quota_exceeded(self):
        lic = _make_license("free")
        with self.assertRaises(QuotaExceededError):
            lic.check_quota("agents", 3)

    def test_free_agents_quota_ok(self):
        lic = _make_license("free")
        lic.check_quota("agents", 2)

    def test_free_events_quota_exceeded(self):
        lic = _make_license("free")
        with self.assertRaises(QuotaExceededError):
            lic.check_quota("events_month", 10_000)

    def test_pro_agents_quota_exceeded(self):
        lic = _make_license("pro")
        with self.assertRaises(QuotaExceededError):
            lic.check_quota("agents", 50)

    def test_pro_agents_quota_ok(self):
        lic = _make_license("pro")
        lic.check_quota("agents", 49)

    def test_startup_events_quota(self):
        lic = _make_license("startup")
        with self.assertRaises(QuotaExceededError):
            lic.check_quota("events_month", 1_000_000)
        lic.check_quota("events_month", 999_999)  # just under → OK

    def test_team_agents_150(self):
        lic = _make_license("team")
        with self.assertRaises(QuotaExceededError):
            lic.check_quota("agents", 150)
        lic.check_quota("agents", 149)  # OK

    def test_enterprise_no_quota(self):
        lic = _make_license("enterprise")
        lic.check_quota("agents", 999_999)
        lic.check_quota("events_month", 999_999_999)

    def test_warn_at_80_percent(self):
        lic = _make_license("free")
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            lic.check_quota("agents", 2)  # 2/3 = 66% — under threshold
            quota_warnings = [x for x in w if issubclass(x.category, UserWarning)]
            self.assertEqual(len(quota_warnings), 0)

    def test_warn_triggered_near_limit(self):
        lic = _make_license("pro")  # 50 agents
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            lic.check_quota("agents", 41)  # 41/50 = 82% → warning
            quota_warnings = [x for x in w if issubclass(x.category, UserWarning)]
            self.assertGreater(len(quota_warnings), 0)
            self.assertIn("quota warning", str(quota_warnings[0].message).lower())


# ══════════════════════════════════════════════════════════════════════════════
# TIER COMPARISON — avec startup dans l'ordre
# ══════════════════════════════════════════════════════════════════════════════

class TestTierComparison(unittest.TestCase):

    def test_tier_order_startup_between_pro_and_team(self):
        idx_pro     = TIER_ORDER.index("pro")
        idx_startup = TIER_ORDER.index("startup")
        idx_team    = TIER_ORDER.index("team")
        self.assertLess(idx_pro, idx_startup)
        self.assertLess(idx_startup, idx_team)

    def test_startup_is_above_pro(self):
        lic = _make_license("startup")
        self.assertTrue(lic.is_tier_or_above("free"))
        self.assertTrue(lic.is_tier_or_above("pro"))
        self.assertTrue(lic.is_tier_or_above("startup"))
        self.assertFalse(lic.is_tier_or_above("team"))
        self.assertFalse(lic.is_tier_or_above("business"))
        self.assertFalse(lic.is_tier_or_above("enterprise"))

    def test_team_is_above_startup(self):
        lic = _make_license("team")
        self.assertTrue(lic.is_tier_or_above("startup"))
        self.assertFalse(lic.is_tier_or_above("business"))

    def test_is_paid_free(self):
        lic = _make_license("free")
        self.assertFalse(lic.is_tier_or_above("pro"))

    def test_is_paid_pro(self):
        lic = _make_license("pro")
        self.assertTrue(lic.is_tier_or_above("pro"))

    def test_is_paid_startup(self):
        lic = _make_license("startup")
        self.assertTrue(lic.is_tier_or_above("pro"))


# ══════════════════════════════════════════════════════════════════════════════
# EXPIRATION & GRACE PERIOD
# ══════════════════════════════════════════════════════════════════════════════

class TestExpiration(unittest.TestCase):

    def test_expired_within_grace_warns(self):
        import time
        import warnings
        lic = _make_license("pro")
        lic._payload = {
            "tier": "pro",
            "license_id": "test",
            "expires_at": time.time() - 3600,  # expired 1h ago
        }
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            lic._handle_expired(lic._payload["expires_at"])
            self.assertEqual(lic._tier, "pro")  # still pro during grace
            grace_warnings = [x for x in w if issubclass(x.category, UserWarning)]
            self.assertGreater(len(grace_warnings), 0)

    def test_expired_after_grace_downgrades_to_free(self):
        import time
        from aiss.license import GRACE_PERIOD_SECONDS
        lic = _make_license("pro")
        expired_ts = time.time() - GRACE_PERIOD_SECONDS - 3600
        lic._payload = {"tier": "pro", "license_id": "test", "expires_at": expired_ts}
        lic._handle_expired(expired_ts)
        self.assertEqual(lic._tier, "free")

    def test_startup_expired_downgrades_to_free(self):
        import time
        from aiss.license import GRACE_PERIOD_SECONDS
        lic = _make_license("startup")
        expired_ts = time.time() - GRACE_PERIOD_SECONDS - 7200
        lic._payload = {"tier": "startup", "license_id": "test", "expires_at": expired_ts}
        lic._handle_expired(expired_ts)
        self.assertEqual(lic._tier, "free")


# ══════════════════════════════════════════════════════════════════════════════
# DECORATEUR require_pro (compat legacy)
# ══════════════════════════════════════════════════════════════════════════════

class TestRequireProDecorator(unittest.TestCase):

    def test_decorator_blocks_on_free(self):
        import aiss.license as lic_module
        original = lic_module._license
        lic_module._license = _make_license("free")

        @require_pro("Test feature")
        def my_feature():
            return "ok"

        with self.assertRaises(FeatureNotAvailableError):
            my_feature()

        lic_module._license = original

    def test_decorator_passes_on_pro(self):
        import aiss.license as lic_module
        original = lic_module._license
        lic_module._license = _make_license("pro")

        @require_pro("Test feature")
        def my_feature():
            return "ok"

        result = my_feature()
        self.assertEqual(result, "ok")
        lic_module._license = original

    def test_decorator_passes_on_startup(self):
        import aiss.license as lic_module
        original = lic_module._license
        lic_module._license = _make_license("startup")

        @require_pro("Test feature")
        def my_feature():
            return "ok"

        result = my_feature()
        self.assertEqual(result, "ok")
        lic_module._license = original


# ══════════════════════════════════════════════════════════════════════════════
# INFO
# ══════════════════════════════════════════════════════════════════════════════

class TestLicenseInfo(unittest.TestCase):

    def test_info_has_required_keys(self):
        lic = _make_license("pro")
        info = lic.info()
        for key in ["tier", "license_id", "agents_max", "events_month",
                    "features", "local_first"]:
            self.assertIn(key, info)

    def test_local_first_always_true(self):
        for tier in TIER_ORDER:
            lic = _make_license(tier)
            self.assertTrue(lic.info()["local_first"])

    def test_repr(self):
        lic = _make_license("team")
        self.assertIn("team", repr(lic))

    def test_startup_info_correct_tier(self):
        lic = _make_license("startup")
        info = lic.info()
        self.assertEqual(info["tier"], "startup")
        self.assertEqual(info["agents_max"], 50)
        self.assertEqual(info["events_month"], 1_000_000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
