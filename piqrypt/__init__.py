# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
PiQrypt -- Trust & Continuity Layer for Autonomous AI Agents
AISS v2.0 Reference Implementation
"""

__version__ = "1.8.2"
__author__ = "PiQrypt Inc."
__email__ = "contact@piqrypt.com"
__license__ = "Elastic-2.0"
__url__ = "https://piqrypt.com"

try:
    from aiss import (  # noqa: F401
        generate_keypair, derive_agent_id,
        stamp_event, stamp_genesis_event,
        verify_signature, verify_event, export_identity,
    )
    from aiss.license import (  # noqa: F401
        get_tier, get_license_info, activate_license, is_pro,
    )
except ImportError:
    pass

__all__ = [
    "__version__",
    "generate_keypair", "derive_agent_id",
    "stamp_event", "stamp_genesis_event",
    "verify_signature", "verify_event", "export_identity",
    "get_tier", "get_license_info", "activate_license", "is_pro",
]
