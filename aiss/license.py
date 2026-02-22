"""
License Verification for PiQrypt Pro

Simple license key validation (offline, no server required).

Tiers:
  - Free: AISS-1 (Ed25519), basic features
  - Pro: AISS-2 hybrid, certified exports, badges ($1,990/year)
  - OSS: All Pro features for open-source (free)
"""

import os
import hashlib
import json
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime


class License:
    """
    License verification for Pro features
    
    License key format: pk_<tier>_<uuid>_<signature>
    Examples:
      - pk_pro_a3f29b4c_8d7e6f5a
      - pk_oss_12345678_abcdef01
    """
    
    def __init__(self):
        self.config_dir = Path.home() / ".piqrypt"
        self.license_file = self.config_dir / "license.json"
        self._license_data = self._load_license()
    
    def _load_license(self) -> Optional[Dict[str, Any]]:
        """Load license from environment variable or file"""
        
        # Priority 1: Environment variable
        env_key = os.getenv("PIQRYPT_LICENSE_KEY") or os.getenv("AISS2_LICENSE_KEY")
        if env_key:
            return self._verify_license_key(env_key)
        
        # Priority 2: License file
        if self.license_file.exists():
            try:
                with open(self.license_file) as f:
                    data = json.load(f)
                    # Re-verify on load
                    if data.get("key"):
                        return self._verify_license_key(data["key"])
                    return data
            except:
                pass
        
        return None
    
    def _verify_license_key(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Verify license key format and signature
        
        Format: pk_<tier>_<license_id>_<signature>
        Signature: HMAC-SHA256(tier:license_id:secret)[:8]
        """
        try:
            parts = key.split("_")
            if len(parts) != 4 or parts[0] != "pk":
                return None
            
            tier = parts[1]  # "pro", "oss", "enterprise"
            license_id = parts[2]
            provided_sig = parts[3]
            
            # Verify signature
            # NOTE: In production, use a proper secret stored securely
            secret = "piqrypt_hmac_secret_v1_change_in_production"
            expected_sig = hashlib.sha256(
                f"{tier}:{license_id}:{secret}".encode()
            ).hexdigest()[:8]
            
            if provided_sig != expected_sig:
                return None
            
            # Valid license
            return {
                "tier": tier,
                "license_id": license_id,
                "key": key,
                "verified": True,
                "verified_at": datetime.utcnow().isoformat() + "Z"
            }
        
        except Exception:
            return None
    
    def is_pro(self) -> bool:
        """Check if Pro/OSS/Enterprise license is active"""
        if not self._license_data:
            return False
        
        tier = self._license_data.get("tier", "")
        return tier in ["pro", "oss", "enterprise"]
    
    def is_oss(self) -> bool:
        """Check if OSS license is active"""
        if not self._license_data:
            return False
        
        return self._license_data.get("tier") == "oss"
    
    def get_tier(self) -> str:
        """Get license tier: free, pro, oss, enterprise"""
        if not self._license_data:
            return "free"
        
        return self._license_data.get("tier", "free")
    
    def get_info(self) -> Dict[str, Any]:
        """Get detailed license information"""
        tier = self.get_tier()
        
        # Feature matrix
        features = {
            "free": {
                "aiss1_ed25519": True,
                "aiss2_hybrid": False,
                "certified_exports": False,
                "pro_badges": False,
                "encrypted_memory": False,
                "witness_network": False,
                "blockchain_anchoring": False,
                "trusted_timestamps": False,
            },
            "pro": {
                "aiss1_ed25519": True,
                "aiss2_hybrid": True,
                "certified_exports": True,
                "pro_badges": True,
                "encrypted_memory": False,  # v1.2.0
                "witness_network": False,   # v1.3.0
                "blockchain_anchoring": False,  # v1.3.0
                "trusted_timestamps": False,  # v1.2.0
            }
        }
        
        # OSS and Enterprise have all Pro features
        features["oss"] = features["pro"].copy()
        features["enterprise"] = features["pro"].copy()
        
        info = {
            "tier": tier,
            "features": features.get(tier, features["free"])
        }
        
        if self._license_data:
            info["license_id"] = self._license_data.get("license_id", "N/A")
            info["verified"] = True
            info["verified_at"] = self._license_data.get("verified_at")
        
        return info
    
    def activate(self, license_key: str) -> bool:
        """
        Activate Pro license
        
        Args:
            license_key: License key from piqrypt.com
            
        Returns:
            True if activation successful
        """
        license_data = self._verify_license_key(license_key)
        
        if not license_data:
            return False
        
        # Save to file
        self.config_dir.mkdir(exist_ok=True)
        
        with open(self.license_file, 'w') as f:
            json.dump(license_data, f, indent=2)
        
        self._license_data = license_data
        return True
    
    def deactivate(self):
        """Deactivate license (return to Free tier)"""
        if self.license_file.exists():
            self.license_file.unlink()
        
        self._license_data = None


# Global instance
_license = License()


def is_pro() -> bool:
    """Check if Pro license is active"""
    return _license.is_pro()


def is_oss() -> bool:
    """Check if OSS license is active"""
    return _license.is_oss()


def get_tier() -> str:
    """Get current tier: free, pro, oss, enterprise"""
    return _license.get_tier()


def get_license_info() -> Dict[str, Any]:
    """Get license information"""
    return _license.get_info()


def activate_license(key: str) -> bool:
    """Activate Pro license"""
    return _license.activate(key)


def deactivate_license():
    """Deactivate license"""
    _license.deactivate()


def require_pro(feature_name: str = "This feature"):
    """
    Decorator to require Pro license
    
    Example:
        @require_pro("Hybrid signatures")
        def stamp_event_aiss2_hybrid(...):
            ...
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not is_pro():
                from aiss.exceptions import AISSError
                tier = get_tier()
                raise AISSError(
                    f"{feature_name} requires PiQrypt Pro.\n"
                    f"Current tier: {tier}\n"
                    f"\n"
                    f"Activate Pro:\n"
                    f"  piqrypt license activate <key>\n"
                    f"\n"
                    f"Get license:\n"
                    f"  Pro: https://piqrypt.com/pro ($1,990/year)\n"
                    f"  OSS: https://piqrypt.com/oss (free for open-source)"
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Public API
__all__ = [
    "is_pro",
    "is_oss",
    "get_tier",
    "get_license_info",
    "activate_license",
    "deactivate_license",
    "require_pro",
]
