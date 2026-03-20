# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
Migration v1.6.0 → v1.7.0 — PiQrypt

Détecte les structures legacy et migre vers l'architecture
isolée par agent (~/.piqrypt/agents/<name>/).

Flow :
    1. Détection automatique au premier lancement v1.7.0
    2. Proposition interactive (ou silencieuse en mode --non-interactive)
    3. Migration non-destructive : backup conservé
    4. Chiffrement optionnel de la clé privée existante

Ce que la migration fait :
    ~/.piqrypt/events/plain/     → ~/.piqrypt/agents/<n>/events/plain/
    ~/.piqrypt/events/encrypted/ → ~/.piqrypt/agents/<n>/events/encrypted/
    ~/.piqrypt/keys/             → ~/.piqrypt/agents/<n>/keys/
    ~/.piqrypt/tsi/              → ~/.piqrypt/agents/<n>/tsi/

Ce que la migration ne fait PAS :
    - Modifier les événements (intégrité préservée)
    - Supprimer les anciens fichiers (backup conservé)
    - Changer les agent_ids existants
"""

import json
import shutil
import time
from pathlib import Path
from typing import Any, Dict, Optional

from aiss.logger import get_logger
from aiss.agent_registry import (
    init_agent_dirs,
    register_agent,
    detect_legacy_structure,
    get_legacy_event_counts,
    PIQRYPT_DIR,
    AGENTS_DIR,
)

logger = get_logger(__name__)

BACKUP_DIR_NAME = ".piqrypt_backup_v160"


# ─── Détection ────────────────────────────────────────────────────────────────

def needs_migration() -> bool:
    """
    Retourne True si une migration est nécessaire.
    Conditions :
        - Structure legacy détectée (events/ à la racine)
        - Pas encore de répertoire agents/ peuplé
    """
    if not detect_legacy_structure():
        return False
    # Si agents/ existe déjà et contient des agents → déjà migré
    if AGENTS_DIR.exists() and any(AGENTS_DIR.iterdir()):
        return False
    return True


def get_migration_preview() -> Dict[str, Any]:
    """
    Retourne un aperçu de ce qui sera migré.
    Utilisé pour informer l'utilisateur avant confirmation.
    """
    counts = get_legacy_event_counts()
    legacy_key = PIQRYPT_DIR / "keys" / "identity.json"
    legacy_tsi = PIQRYPT_DIR / "tsi"

    return {
        "plain_events":    counts["plain"],
        "encrypted_files": counts["encrypted"],
        "has_identity":    legacy_key.exists(),
        "has_tsi":         legacy_tsi.exists(),
        "source_dir":      str(PIQRYPT_DIR),
        "backup_dir":      str(Path.home() / BACKUP_DIR_NAME),
    }


# ─── Migration ────────────────────────────────────────────────────────────────

def run_migration(
    agent_name: str,
    passphrase: Optional[str] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Exécute la migration v1.6.0 → v1.7.0.

    Args:
        agent_name:  Nom de l'agent pour les données existantes
        passphrase:  Si fournie, chiffre la clé privée existante
        dry_run:     Si True, simule sans modifier les fichiers

    Returns:
        Rapport de migration {success, moved_files, errors, backup_path}
    """
    report: Dict[str, Any] = {
        "success":     False,
        "agent_name":  agent_name,
        "moved_files": [],
        "errors":      [],
        "backup_path": str(Path.home() / BACKUP_DIR_NAME),
        "dry_run":     dry_run,
    }

    if dry_run:
        logger.info("[Migration] Mode dry-run — aucune modification")

    # ── Étape 1 : Créer la structure du nouvel agent ───────────────────────
    if not dry_run:
        init_agent_dirs(agent_name)
        logger.info(f"[Migration] Structure créée pour '{agent_name}'")

    # ── Étape 2 : Déplacer events/plain/ ──────────────────────────────────
    old_plain = PIQRYPT_DIR / "events" / "plain"
    new_plain = AGENTS_DIR / agent_name / "events" / "plain"

    if old_plain.exists():
        moved = _move_directory(old_plain, new_plain, dry_run)
        report["moved_files"].extend(moved)
        logger.info(f"[Migration] events/plain/ → {new_plain} ({len(moved)} fichiers)")

    # ── Étape 3 : Déplacer events/encrypted/ ──────────────────────────────
    old_enc = PIQRYPT_DIR / "events" / "encrypted"
    new_enc = AGENTS_DIR / agent_name / "events" / "encrypted"

    if old_enc.exists():
        moved = _move_directory(old_enc, new_enc, dry_run)
        report["moved_files"].extend(moved)
        logger.info(f"[Migration] events/encrypted/ → {new_enc} ({len(moved)} fichiers)")

    # ── Étape 4 : Migrer la clé privée ────────────────────────────────────
    old_key = PIQRYPT_DIR / "keys" / "identity.json"
    if old_key.exists():
        result = _migrate_key(old_key, agent_name, passphrase, dry_run)
        if result.get("error"):
            report["errors"].append(result["error"])
        else:
            report["moved_files"].append(result.get("dest", ""))
            report["key_encrypted"] = result.get("encrypted", False)

    # ── Étape 5 : Déplacer tsi/ ───────────────────────────────────────────
    old_tsi = PIQRYPT_DIR / "tsi"
    new_tsi = AGENTS_DIR / agent_name / "tsi"

    if old_tsi.exists():
        moved = _move_directory(old_tsi, new_tsi, dry_run)
        report["moved_files"].extend(moved)

    # ── Étape 6 : Lire l'agent_id existant ───────────────────────────────
    agent_id = _read_agent_id(agent_name)

    # ── Étape 7 : Enregistrer dans le registre ────────────────────────────
    if not dry_run:
        register_agent(
            agent_name=agent_name,
            agent_id=agent_id or "unknown",
            metadata={"migrated_from": "v1.6.0", "migrated_at": int(time.time())},
        )

    # ── Étape 8 : Backup de l'ancien répertoire ───────────────────────────
    backup_path = Path.home() / BACKUP_DIR_NAME
    if not dry_run:
        _create_backup(backup_path, report)

    report["success"] = len(report["errors"]) == 0
    report["agent_id"] = agent_id

    logger.info(
        f"[Migration] Terminée — {len(report['moved_files'])} fichiers déplacés, "
        f"{len(report['errors'])} erreurs"
    )

    return report


# ─── Helpers migration ────────────────────────────────────────────────────────

def _move_directory(
    src: Path,
    dst: Path,
    dry_run: bool,
) -> list:
    """Déplace les fichiers de src vers dst. Retourne la liste des fichiers déplacés."""
    moved = []

    if not src.exists():
        return moved

    if not dry_run:
        dst.mkdir(parents=True, exist_ok=True)

    for f in src.iterdir():
        if f.is_file():
            dest_file = dst / f.name
            if not dry_run:
                shutil.copy2(str(f), str(dest_file))
            moved.append(str(f.name))

    return moved


def _migrate_key(
    old_key_path: Path,
    agent_name: str,
    passphrase: Optional[str],
    dry_run: bool,
) -> Dict[str, Any]:
    """
    Migre la clé privée legacy (JSON en clair) vers le format v1.7.0.

    Si passphrase fournie → chiffre avec key_store.
    Sinon → copie en format plaintext v1.7.0.
    """
    result: Dict[str, Any] = {}

    try:
        # Lire la clé legacy
        data = json.loads(old_key_path.read_text())
        from aiss.crypto import ed25519 as _ed

        raw_key = _ed.decode_base64(data.get("private_key", ""))

        agent_dir = AGENTS_DIR / agent_name

        if passphrase:
            # Chiffrer avec key_store
            dest = agent_dir / "private.key.enc"
            if not dry_run:
                from aiss.key_store import save_encrypted_key
                save_encrypted_key(raw_key, passphrase, dest)
            result["encrypted"] = True
        else:
            # Format plaintext v1.7.0
            dest = agent_dir / "private.key.json"
            if not dry_run:
                from aiss.key_store import save_plaintext_key
                save_plaintext_key(raw_key, dest)
            result["encrypted"] = False

        # Copier aussi identity.json
        identity_src = old_key_path.parent / "identity.json"
        if identity_src.exists():
            identity_dst = agent_dir / "identity.json"
            if not dry_run:
                shutil.copy2(str(identity_src), str(identity_dst))

        result["dest"] = str(dest)
        logger.info(
            f"[Migration] Clé migrée → {dest} "
            f"({'chiffrée' if passphrase else 'non chiffrée'})"
        )

    except Exception as e:
        result["error"] = f"Erreur migration clé : {e}"
        logger.error(f"[Migration] {result['error']}")

    return result


def _read_agent_id(agent_name: str) -> Optional[str]:
    """Tente de lire l'agent_id depuis identity.json migré."""
    paths = [
        AGENTS_DIR / agent_name / "identity.json",
        PIQRYPT_DIR / "keys" / "identity.json",
    ]
    for p in paths:
        if p.exists():
            try:
                data = json.loads(p.read_text())
                aid = data.get("identity", {}).get("agent_id") or data.get("agent_id")
                if aid:
                    return aid
            except Exception:
                pass
    return None


def _create_backup(backup_path: Path, report: Dict[str, Any]) -> None:
    """Crée un backup de l'ancienne structure dans ~/.piqrypt_backup_v160/."""
    try:
        if backup_path.exists():
            shutil.rmtree(str(backup_path))

        backup_path.mkdir(parents=True)

        # Copier events/ legacy
        for subdir in ["events", "keys", "tsi"]:
            src = PIQRYPT_DIR / subdir
            if src.exists():
                shutil.copytree(str(src), str(backup_path / subdir))

        # Écrire le rapport de migration
        (backup_path / "migration_report.json").write_text(
            json.dumps({
                **report,
                "backup_created_at": int(time.time()),
                "instructions": (
                    "Ce répertoire est un backup de votre ancienne installation PiQrypt v1.6.0. "
                    "Vous pouvez le supprimer après avoir vérifié que la migration est correcte. "
                    "Pour supprimer : rm -rf ~/.piqrypt_backup_v160"
                ),
            }, indent=2)
        )

        report["backup_path"] = str(backup_path)
        logger.info(f"[Migration] Backup créé : {backup_path}")

    except Exception as e:
        logger.warning(f"[Migration] Impossible de créer le backup : {e}")


# ─── Interface interactive ────────────────────────────────────────────────────

def prompt_migration(non_interactive: bool = False) -> Optional[Dict[str, Any]]:
    """
    Interface interactive de migration.
    Appelée automatiquement au premier lancement v1.7.0 si legacy détecté.

    Args:
        non_interactive: Si True, utilise les variables d'environnement
                         PIQRYPT_AGENT_NAME et PIQRYPT_PASSPHRASE

    Returns:
        Rapport de migration, ou None si migration refusée/inapplicable
    """
    if not needs_migration():
        return None

    preview = get_migration_preview()

    if non_interactive:
        import os
        agent_name = os.environ.get("PIQRYPT_AGENT_NAME", "default")
        passphrase = os.environ.get("PIQRYPT_PASSPHRASE")
        return run_migration(agent_name, passphrase)

    # Mode interactif
    print("\n" + "─" * 50)
    print("  PiQrypt v1.7.0 — Migration détectée")
    print("─" * 50)
    print(f"\n  Structure v1.6.0 trouvée dans : {preview['source_dir']}")
    print(f"  Événements plain  : {preview['plain_events']}")
    print(f"  Fichiers chiffrés : {preview['encrypted_files']}")
    print(f"  Clé privée        : {'trouvée' if preview['has_identity'] else 'non trouvée'}")
    print(f"\n  Un backup sera conservé dans : {preview['backup_dir']}")

    # Confirmation
    try:
        answer = input("\n  Migrer vers v1.7.0 maintenant ? [O/n] ").strip().lower()
        if answer == "n":
            print("  Migration annulée. Vous pouvez relancer avec : piqrypt migrate")
            return None
    except (KeyboardInterrupt, EOFError):
        print("\n  Migration annulée.")
        return None

    # Nom de l'agent
    try:
        agent_name = input(
            "\n  Nom pour cet agent [default] : "
        ).strip() or "default"
    except (KeyboardInterrupt, EOFError):
        agent_name = "default"

    # Passphrase optionnelle
    passphrase = None
    if preview["has_identity"]:
        try:
            import getpass
            pp = getpass.getpass(
                "  Passphrase pour chiffrer la clé privée (Entrée = sans) : "
            )
            if pp:
                pp2 = getpass.getpass("  Confirmer la passphrase : ")
                if pp != pp2:
                    print("  ⚠️  Passphrases différentes — clé non chiffrée")
                else:
                    passphrase = pp
        except (KeyboardInterrupt, EOFError):
            pass

    print(f"\n  Migration de '{agent_name}' en cours...")
    report = run_migration(agent_name, passphrase)

    if report["success"]:
        print("\n  ✅ Migration terminée !")
        print(f"     {len(report['moved_files'])} fichiers déplacés")
        if report.get("key_encrypted"):
            print("     Clé privée chiffrée avec succès")
        print(f"     Backup : {report['backup_path']}")
        print(f"     Suppression manuelle : rm -rf {report['backup_path']}\n")
    else:
        print("\n  ⚠️  Migration terminée avec erreurs :")
        for err in report["errors"]:
            print(f"     • {err}")

    return report


# ─── Alias compat tests ───────────────────────────────────────────────────────

def migrate_agent(
    base_dir: str,
    agent_name: str,
    passphrase: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Alias de run_migration pour compat tests et usage externe.

    Args:
        base_dir:   Répertoire racine de l'installation (ignoré — utilise ~/.piqrypt)
        agent_name: Nom de l'agent à créer
        passphrase: Passphrase optionnelle pour chiffrer la clé

    Returns:
        Rapport de migration
    """
    return run_migration(agent_name=agent_name, passphrase=passphrase)


# ─── Public API ───────────────────────────────────────────────────────────────
__all__ = [
    "needs_migration",
    "get_migration_preview",
    "run_migration",
    "migrate_agent",
    "prompt_migration",
    "BACKUP_DIR_NAME",
]
