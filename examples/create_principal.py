"""
create_principal.py — Crée un principal TrustGate (human reviewer)
===================================================================
Usage :
    python create_principal.py                         # crée admin L3 par défaut
    python create_principal.py --name alice --clearance L2 --email alice@corp.com
    python create_principal.py --list                  # liste les principals existants

Clearance levels :
    L1 — peut approuver VRS jusqu'à 0.75
    L2 — peut approuver VRS jusqu'à 0.90
    L3 — peut approuver tout (VRS jusqu'à 1.0)
"""

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

try:
    from trustgate.human_principal import HumanPrincipal, DEFAULT_PRINCIPALS_DIR
except ImportError as e:
    print(f"Erreur import: {e}")
    print("Lance depuis piqrypt/ : python create_principal.py")
    sys.exit(1)


def list_principals():
    principals = HumanPrincipal.list_all(principals_dir=DEFAULT_PRINCIPALS_DIR)
    if not principals:
        print("Aucun principal enregistré.")
        print(f"Dossier : {DEFAULT_PRINCIPALS_DIR}")
        return
    print(f"\n{len(principals)} principal(s) dans {DEFAULT_PRINCIPALS_DIR}\n")
    for p in principals:
        r = p.record
        print(f"  {r.name:<20} clearance={r.clearance}  email={r.email}  mode={r.mode}")
    print()


def create_principal(name, email, clearance):
    try:
        existing = [p for p in HumanPrincipal.list_all(DEFAULT_PRINCIPALS_DIR)
                    if p.record.name == name]
        if existing:
            print(f"Principal '{name}' existe déjà (clearance={existing[0].record.clearance})")
            return

        p = HumanPrincipal.create(
            name=name,
            email=email,
            clearance=clearance,
            mode="sso",
            created_by="cli",
            principals_dir=DEFAULT_PRINCIPALS_DIR,
        )
        print(f"\n✓ Principal créé :")
        print(f"  name      : {p.record.name}")
        print(f"  email     : {p.record.email}")
        print(f"  clearance : {p.record.clearance}")
        print(f"  id        : {p.record.principal_id}")
        print(f"\nTu peux maintenant approuver des décisions dans la console TrustGate.")
        print(f"Sélectionne '{name}' dans le dropdown du modal Approve/Reject.\n")
    except Exception as e:
        print(f"Erreur : {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Gestion des principals TrustGate")
    parser.add_argument("--name",      default="admin",                  help="Nom du principal")
    parser.add_argument("--email",     default="admin@trustgate.local",  help="Email")
    parser.add_argument("--clearance", default="L3",
                        choices=["L1", "L2", "L3"],                      help="Niveau de clearance")
    parser.add_argument("--list",      action="store_true",               help="Lister les principals")
    args = parser.parse_args()

    if args.list:
        list_principals()
    else:
        create_principal(args.name, args.email, args.clearance)


if __name__ == "__main__":
    main()
