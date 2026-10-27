# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
"""Guard test: public pricing texts must match the code (no early-bird, correct prices)."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

EURO = "€"


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


# ── Early-bird guard ──────────────────────────────────────────────────────────

EARLY_BIRD_FILES = [
    "README.md",
    "TIERS_PRICING.md",
    "CERTIFICATION_PRICING.md",
    "docs/README.md",
    "docs/LICENSE-SYSTEM.md",
    "docs/WHITEPAPER_v2.0.md",
    "cli/main.py",
    "aiss/license.py",
]

@pytest.mark.parametrize("rel", EARLY_BIRD_FILES)
def test_no_early_bird(rel):
    text = _read(rel)
    hits = re.findall(r"early[-\s]*bird", text, re.IGNORECASE)
    assert not hits, f"{rel}: found early-bird mention(s): {hits}"


# ── Price accuracy ────────────────────────────────────────────────────────────

def test_tiers_pro_price():
    import aiss.license as _lic
    assert _lic.TIERS["pro"]["price_annual"] == 390

def test_tiers_startup_price():
    import aiss.license as _lic
    assert _lic.TIERS["startup"]["price_annual"] == 990

def test_readme_contains_pro_price():
    text = _read("README.md")
    assert EURO + "390" in text, "README.md must contain €390"

def test_readme_contains_startup_price():
    text = _read("README.md")
    assert EURO + "990" in text, "README.md must contain €990"

def test_tiers_pricing_contains_pro_price():
    text = _read("TIERS_PRICING.md")
    assert EURO + "390" in text, "TIERS_PRICING.md must contain €390"

def test_tiers_pricing_contains_startup_price():
    text = _read("TIERS_PRICING.md")
    assert EURO + "990" in text, "TIERS_PRICING.md must contain €990"


# ── CLI stale strings ─────────────────────────────────────────────────────────

CLI_BANNED = [
    "$1,990",
    "$99 one-time",
    "Included (unlimited)",
    "piqrypt.com/pro ",
]

@pytest.mark.parametrize("banned", CLI_BANNED)
def test_cli_no_stale_price(banned):
    text = _read("cli/main.py")
    assert banned not in text, f"cli/main.py still contains: {banned!r}"


# ── TrustGate locked message ──────────────────────────────────────────────────

def test_trustgate_no_locked_message():
    text = _read("trustgate/trustgate_server.py")
    assert "TRUSTGATE IS LOCKED" not in text


# ── Coming soon guard ─────────────────────────────────────────────────────────

def test_tiers_pricing_no_coming_soon():
    text = _read("TIERS_PRICING.md")
    hits = re.findall(r"coming soon", text, re.IGNORECASE)
    assert not hits, f"TIERS_PRICING.md still contains 'coming soon': {hits}"
