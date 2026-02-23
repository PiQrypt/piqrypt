"""
Visual Badges for PiQrypt

Generate verification badges for GitHub, websites, documentation.

Usage:
    from aiss.badges import generate_badge

    badge = generate_badge(agent_id, "pro")
    print(badge["markdown"])
"""

import time
from typing import Dict, Any
from aiss.license import get_tier


def generate_badge(agent_id: str, tier: str = None) -> Dict[str, Any]:
    """
    Generate verification badge for agent

    Args:
        agent_id: Agent ID
        tier: License tier (auto-detected if None)

    Returns:
        Dict with badge URLs and embed codes
    """
    if tier is None:
        tier = get_tier()

    # Badge configuration
    badge_configs = {
        "free": {
            "color": "blue",
            "label": "PiQrypt",
            "message": "Verified",
            "logo": "shield"
        },
        "pro": {
            "color": "gold",
            "label": "PiQrypt",
            "message": "Pro",
            "logo": "shield-check"
        },
        "oss": {
            "color": "green",
            "label": "PiQrypt",
            "message": "OSS",
            "logo": "open-source"
        },
        "enterprise": {
            "color": "purple",
            "label": "PiQrypt",
            "message": "Enterprise",
            "logo": "building"
        }
    }

    config = badge_configs.get(tier, badge_configs["free"])

    # Truncate agent ID for badge
    agent_id[:8]

    # Badge URLs (shields.io style)
    badge_url = f"https://img.shields.io/badge/{config['label']}-{config['message']}-{config['color']}?style=flat-square"

    # Verification URL
    verify_url = f"https://verify.piqrypt.com/{agent_id}"

    return {
        "agent_id": agent_id,
        "tier": tier,
        "badge_url": badge_url,
        "verification_url": verify_url,

        # Embed codes
        "markdown": f"[![PiQrypt {config['message']}]({badge_url})]({verify_url})",
        "html": f'<a href="{verify_url}"><img src="{badge_url}" alt="PiQrypt {config["message"]}"></a>',
        "rst": f".. image:: {badge_url}\n   :target: {verify_url}\n   :alt: PiQrypt {config['message']}",

        # Metadata
        "issued_at": int(time.time()),
        "visual_config": config
    }


def generate_badge_svg(agent_id: str, tier: str = None) -> str:
    """
    Generate SVG badge content

    Args:
        agent_id: Agent ID
        tier: License tier

    Returns:
        SVG content as string
    """
    if tier is None:
        tier = get_tier()

    colors = {
        "free": "#4A90E2",
        "pro": "#F5A623",
        "oss": "#7ED321",
        "enterprise": "#9013FE"
    }

    color = colors.get(tier, colors["free"])
    agent_id[:8]

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="120" height="20">
    <linearGradient id="b" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
        <stop offset="1" stop-opacity=".1"/>
    </linearGradient>

    <mask id="a">
        <rect width="120" height="20" rx="3" fill="#fff"/>
    </mask>

    <g mask="url(#a)">
        <path fill="#555" d="M0 0h60v20H0z"/>
        <path fill="{color}" d="M60 0h60v20H60z"/>
        <path fill="url(#b)" d="M0 0h120v20H0z"/>
    </g>

    <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
        <text x="30" y="15" fill="#010101" fill-opacity=".3">PiQrypt</text>
        <text x="30" y="14">PiQrypt</text>
        <text x="90" y="15" fill="#010101" fill-opacity=".3">{tier.upper()}</text>
        <text x="90" y="14">{tier.upper()}</text>
    </g>
</svg>'''

    return svg


def get_badge_embed_code(agent_id: str, format: str = "markdown") -> str:
    """
    Get badge embed code in specified format

    Args:
        agent_id: Agent ID
        format: "markdown", "html", "rst"

    Returns:
        Embed code as string
    """
    badge = generate_badge(agent_id)

    formats_map = {
        "markdown": badge["markdown"],
        "html": badge["html"],
        "rst": badge["rst"]
    }

    return formats_map.get(format, badge["markdown"])


# Public API
__all__ = [
    "generate_badge",
    "generate_badge_svg",
    "get_badge_embed_code",
]
