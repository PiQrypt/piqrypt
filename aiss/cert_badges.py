"""
Certification Badges

Generate public verification badges for PiQrypt certifications.
Each certification gets a unique badge that can be embedded on websites,
GitHub READMEs, documentation, etc.

Usage:
    from aiss.cert_badges import generate_cert_badge
    
    badge = generate_cert_badge("CERT-20260220-A3F7E8", "timestamp")
    # Save SVG
    with open("badge.svg", "w") as f:
        f.write(badge["svg"])
    
    # Get embed codes
    print(badge["markdown"])
    print(badge["html"])
"""

import time
from typing import Dict, Any


def generate_cert_badge_svg(cert_id: str, tier: str) -> str:
    """
    Generate SVG badge for certification.
    
    Args:
        cert_id: Certification ID (e.g., "CERT-20260220-A3F7E8")
        tier: Certification tier ("simple", "timestamp", "pq_bundle")
    
    Returns:
        SVG content as string
    """
    # Color scheme per tier
    colors = {
        "simple": "#0066cc",       # Blue
        "timestamp": "#ff9500",     # Orange
        "pq_bundle": "#ffd700"      # Gold
    }

    tier_labels = {
        "simple": "Simple",
        "timestamp": "Timestamp",
        "pq_bundle": "Post-Quantum"
    }

    color = colors.get(tier, colors["simple"])
    label = tier_labels.get(tier, "Verified")

    # Truncate cert_id for display
    short_cert = cert_id if len(cert_id) <= 20 else cert_id[:20] + "..."

    svg = f'''<svg width="240" height="80" xmlns="http://www.w3.org/2000/svg">
  <!-- Background -->
  <rect fill="{color}" width="240" height="80" rx="8"/>
  
  <!-- Gradient overlay -->
  <defs>
    <linearGradient id="gradient" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:rgba(255,255,255,0.1);stop-opacity:1" />
      <stop offset="100%" style="stop-color:rgba(0,0,0,0.1);stop-opacity:1" />
    </linearGradient>
  </defs>
  <rect fill="url(#gradient)" width="240" height="80" rx="8"/>
  
  <!-- Checkmark icon -->
  <circle cx="25" cy="25" r="12" fill="white" opacity="0.9"/>
  <path d="M 20 25 L 23 28 L 30 21" stroke="{color}" stroke-width="2" fill="none"/>
  
  <!-- Text: Title -->
  <text x="45" y="28" fill="white" font-size="16" font-family="Arial, sans-serif" font-weight="bold">
    Verified by PiQrypt
  </text>
  
  <!-- Text: Tier -->
  <text x="45" y="48" fill="white" font-size="12" font-family="Arial, sans-serif" opacity="0.9">
    {label} Certification
  </text>
  
  <!-- Text: Cert ID -->
  <text x="45" y="65" fill="white" font-size="9" font-family="monospace" opacity="0.7">
    {short_cert}
  </text>
</svg>'''

    return svg


def generate_cert_badge(cert_id: str, tier: str) -> Dict[str, Any]:
    """
    Generate complete certification badge with all formats.
    
    Args:
        cert_id: Certification ID
        tier: Certification tier ("simple", "timestamp", "pq_bundle")
    
    Returns:
        Dictionary containing:
        - svg: SVG content
        - badge_url: URL to hosted badge
        - verify_url: URL to verification page
        - markdown: Markdown embed code
        - html: HTML embed code
        - png_url: URL to PNG version (if applicable)
    """
    # Base URLs
    verify_url = f"https://verify.piqrypt.com/{cert_id}"
    badge_url = f"https://verify.piqrypt.com/badge/{cert_id}.svg"
    png_url = f"https://verify.piqrypt.com/badge/{cert_id}.png"

    # Generate SVG
    svg = generate_cert_badge_svg(cert_id, tier)

    # Tier display name
    tier_names = {
        "simple": "Simple",
        "timestamp": "Timestamp",
        "pq_bundle": "Post-Quantum"
    }
    tier_name = tier_names.get(tier, "Verified")

    return {
        "cert_id": cert_id,
        "tier": tier,
        "svg": svg,
        "badge_url": badge_url,
        "verify_url": verify_url,
        "png_url": png_url,

        # Embed codes
        "markdown": f"[![PiQrypt {tier_name} Certified]({badge_url})]({verify_url})",
        "html": f'<a href="{verify_url}"><img src="{badge_url}" alt="PiQrypt {tier_name} Certified"></a>',
        "rst": f".. image:: {badge_url}\n   :target: {verify_url}\n   :alt: PiQrypt {tier_name} Certified",

        # Metadata
        "issued_at": int(time.time()),
        "tier_display": tier_name
    }


def generate_badge_snippets(cert_id: str, tier: str) -> str:
    """
    Generate ready-to-copy snippets for user.
    
    Args:
        cert_id: Certification ID
        tier: Certification tier
    
    Returns:
        Formatted string with all embed codes
    """
    badge = generate_cert_badge(cert_id, tier)

    snippets = f"""
🎨 PiQrypt Certification Badge

Cert ID: {cert_id}
Tier: {badge['tier_display']}
Verify: {badge['verify_url']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📝 MARKDOWN (GitHub, GitLab, etc.)

{badge['markdown']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🌐 HTML (Website, Blog, etc.)

{badge['html']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📄 RESTRUCTUREDTEXT (Sphinx, ReadTheDocs)

{badge['rst']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💾 DOWNLOAD

SVG: {badge['badge_url']}
PNG: {badge['png_url']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

    return snippets


__all__ = [
    "generate_cert_badge_svg",
    "generate_cert_badge",
    "generate_badge_snippets",
]
