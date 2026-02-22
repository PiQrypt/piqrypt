#!/usr/bin/env python3
"""
PiQrypt Certification Request Validator

Run by PiQrypt staff to validate and certify user exports.

Usage:
    python validate_certification_request.py certification-request-XXXXX.zip

Requirements:
    - piqrypt-ca-private.key in current directory (or specify path)
    - PiQrypt package installed

Output:
    - audit-CERT-XXXXX.piqrypt-certified (send back to user)
"""

import sys
import argparse
from pathlib import Path

# Add parent to path if running standalone
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent))

from aiss.external_cert import validate_and_certify, CertificationError
from aiss.logger import get_logger

logger = get_logger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="Validate and certify a PiQrypt export request"
    )
    parser.add_argument(
        "request_zip",
        help="Path to certification-request-XXXXX.zip"
    )
    parser.add_argument(
        "--ca-key",
        default="piqrypt-ca-private.key",
        help="Path to CA private key (default: piqrypt-ca-private.key)"
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Output directory for certified file (default: current dir)"
    )
    
    args = parser.parse_args()
    
    # Check CA key exists
    ca_key_path = Path(args.ca_key)
    if not ca_key_path.exists():
        print(f"❌ CA private key not found: {ca_key_path}")
        print(f"   Expected location: {ca_key_path.absolute()}")
        print()
        print("   Generate CA key with: python scripts/generate_ca_key.py")
        sys.exit(1)
    
    # Validate request
    print("=" * 70)
    print("PiQrypt Certification Request Validator")
    print("=" * 70)
    print()
    print(f"Request: {args.request_zip}")
    print(f"CA Key:  {ca_key_path}")
    print()
    print("Validating...")
    print()
    
    try:
        certified_path = validate_and_certify(
            args.request_zip,
            str(ca_key_path),
            output_dir=args.output_dir
        )
        
        print()
        print("=" * 70)
        print("✅ CERTIFICATION SUCCESSFUL")
        print("=" * 70)
        print()
        print(f"Certified file: {certified_path}")
        print()
        print("📧 Next steps:")
        print(f"   1. Email {Path(certified_path).name} to user")
        print(f"   2. Include verification instructions:")
        print(f"      piqrypt certify-verify {Path(certified_path).name}")
        print()
        
        # Show certificate ID for records
        import json
        certified_data = json.loads(Path(certified_path).read_text())
        cert_id = certified_data["piqrypt_attestation"]["certificate_id"]
        user_email = "unknown"
        
        # Try to extract user email from request
        import zipfile
        try:
            with zipfile.ZipFile(args.request_zip, 'r') as zf:
                request_meta = json.loads(zf.read("request.json"))
                user_email = request_meta.get("user_email", "unknown")
        except:
            pass
        
        print(f"📋 Record for tracking:")
        print(f"   Certificate ID: {cert_id}")
        print(f"   User Email:     {user_email}")
        print()
    
    except CertificationError as e:
        print()
        print("=" * 70)
        print("❌ CERTIFICATION FAILED")
        print("=" * 70)
        print()
        print(f"Error: {e}")
        print()
        print("📧 Next steps:")
        print("   1. Email user explaining why certification failed")
        print("   2. Request corrected export if fixable")
        print()
        sys.exit(1)
    
    except Exception as e:
        print()
        print("=" * 70)
        print("❌ UNEXPECTED ERROR")
        print("=" * 70)
        print()
        print(f"Error: {e}")
        print()
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
