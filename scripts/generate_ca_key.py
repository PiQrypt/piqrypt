#!/usr/bin/env python3
"""
Generate PiQrypt Certification Authority (CA) keypair

This creates the master keypair used to sign external certifications.
The private key MUST be stored securely (offline, HSM, or encrypted backup).

Usage:
    python generate_ca_key.py

Outputs:
    piqrypt-ca-private.key  (KEEP SECRET)
    piqrypt-ca-public.key   (distribute with PiQrypt)
    piqrypt-ca-info.json    (metadata)
"""

import sys
sys.path.insert(0, '.')

import aiss
from aiss.crypto import ed25519
import json
from datetime import datetime, timezone
from pathlib import Path


def generate_ca_keypair():
    """Generate PiQrypt CA keypair."""
    print("Generating PiQrypt Certification Authority keypair...")
    print("(This should be done ONCE and stored securely)")
    print()
    
    # Generate Ed25519 keypair
    private_key, public_key = aiss.generate_keypair()
    
    # Derive CA ID
    ca_id = aiss.derive_agent_id(public_key)
    
    # Metadata
    ca_info = {
        "version": "PIQRYPT-CA-1.0",
        "ca_id": ca_id,
        "algorithm": "Ed25519",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "issuer": "PiQrypt Inc.",
        "purpose": "External certification of PiQrypt audit exports",
        "validity": "Perpetual (revocation list maintained separately)",
        "public_key": ed25519.encode_base64(public_key),
    }
    
    # Save private key (CRITICAL — keep secret)
    private_path = Path("piqrypt-ca-private.key")
    private_data = {
        "version": "PIQRYPT-CA-PRIVATE-1.0",
        "ca_id": ca_id,
        "private_key": ed25519.encode_base64(private_key),
        "created_at": ca_info["created_at"],
        "WARNING": "KEEP THIS FILE SECRET. Do not commit to git. Store in secure location.",
    }
    private_path.write_text(json.dumps(private_data, indent=2))
    private_path.chmod(0o600)
    
    # Save public key (distribute with PiQrypt)
    public_path = Path("piqrypt-ca-public.key")
    public_data = {
        "version": "PIQRYPT-CA-PUBLIC-1.0",
        "ca_id": ca_id,
        "public_key": ed25519.encode_base64(public_key),
        "issuer": "PiQrypt Inc.",
        "purpose": "Verify PiQrypt external certifications",
    }
    public_path.write_text(json.dumps(public_data, indent=2))
    
    # Save info
    info_path = Path("piqrypt-ca-info.json")
    info_path.write_text(json.dumps(ca_info, indent=2))
    
    print("✅ PiQrypt CA keypair generated")
    print()
    print(f"📁 Files created:")
    print(f"   {private_path}  (🔒 KEEP SECRET)")
    print(f"   {public_path}   (distribute with PiQrypt)")
    print(f"   {info_path}")
    print()
    print(f"🆔 CA ID: {ca_id}")
    print()
    print("⚠️  CRITICAL SECURITY:")
    print("   1. Backup piqrypt-ca-private.key to secure offline storage")
    print("   2. Never commit private key to git")
    print("   3. Add to .gitignore: piqrypt-ca-private.key")
    print("   4. Copy piqrypt-ca-public.key to aiss/ca/ for distribution")
    print()


if __name__ == "__main__":
    generate_ca_keypair()
