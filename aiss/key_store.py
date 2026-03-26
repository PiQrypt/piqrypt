# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
Key Store — PiQrypt v1.8.1

Chiffrement et déchiffrement de la clé privée Ed25519 au repos.

Algorithmes :
    KDF      : scrypt (memory-hard, résistant GPU — RFC 7914)
               N=2^17 (131072), r=8, p=1 → ~128 MB RAM par tentative
    Chiffrement : AES-256-GCM (authentifié, intègre, standard NIST)

Format du fichier .enc :
    [4 bytes]  magic   = b"PQKY"
    [1 byte]   version = 0x01
    [32 bytes] salt    (aléatoire, généré à la création)
    [12 bytes] nonce   AES-GCM (aléatoire, généré à chaque chiffrement)
    [48 bytes] ciphertext (32 bytes clé + 16 bytes tag GCM)
    ──────────
    97 bytes total

Pourquoi scrypt et pas PBKDF2 ?
    PBKDF2 est parallélisable sur GPU → millions de tentatives/seconde.
    scrypt est memory-hard → chaque tentative coûte ~128 MB RAM.
    Avec N=2^17, un GPU haut de gamme ne peut tester que ~100 passphrases/s.

Pourquoi AES-256-GCM ?
    Chiffrement authentifié — toute modification du fichier est détectée.
    Standard NIST, hardware-accelerated sur x86/ARM modernes.

Philosophie :
    - Aucune clé privée jamais en clair sur disque
    - Effacement sécurisé de la RAM après usage
    - Format auto-descriptif et versionné
    - Compatible futures migrations (version byte)
"""

import os
import secrets
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from aiss.logger import get_logger

logger = get_logger(__name__)

# ─── Constantes format ────────────────────────────────────────────────────────
MAGIC = b"PQKY"
VERSION = 0x01
SALT_SIZE = 32       # bytes
NONCE_SIZE = 12      # bytes AES-GCM
KEY_SIZE = 32        # bytes Ed25519 private key
TAG_SIZE = 16        # bytes AES-GCM authentication tag
CIPHERTEXT_SIZE = KEY_SIZE + TAG_SIZE  # 48 bytes

EXPECTED_FILE_SIZE = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE + CIPHERTEXT_SIZE
# = 4 + 1 + 32 + 12 + 48 = 97 bytes

# ─── Paramètres scrypt ────────────────────────────────────────────────────────
# N=2^17 : ~128 MB RAM, ~0.5s sur CPU moderne
# Réduit à N=2^14 pour les tests (via SCRYPT_TEST_MODE=1)
_SCRYPT_N = int(os.environ.get("PIQRYPT_SCRYPT_N", 2**17))
_SCRYPT_R = 8
_SCRYPT_P = 1


# ─── Exceptions ───────────────────────────────────────────────────────────────

class KeyStoreError(Exception):
    """Erreur générique du Key Store."""


class InvalidPassphraseError(KeyStoreError):
    """Passphrase incorrecte — déchiffrement impossible."""


class KeyFileCorruptedError(KeyStoreError):
    """Fichier de clé corrompu ou format invalide."""


# ─── Dérivation de clé ────────────────────────────────────────────────────────

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """
    Dérive une clé AES-256 depuis la passphrase avec scrypt.

    Args:
        passphrase: Passphrase en clair
        salt:       32 bytes aléatoires (depuis le fichier .enc)

    Returns:
        32 bytes — clé AES-256
    """
    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
    )
    return kdf.derive(passphrase.encode("utf-8"))


# ─── Effacement sécurisé RAM ──────────────────────────────────────────────────

def _secure_erase(data: bytearray) -> None:
    """
    Remplace le contenu d'un bytearray par des zéros.
    Atténue les risques de fuite de clé en mémoire.

    Note : Python ne garantit pas l'absence de copies internes (GC, copy-on-write).
    C'est une atténuation, pas une garantie absolue sans TEE/HSM.
    """
    for i in range(len(data)):
        data[i] = 0


# ─── Chiffrement ──────────────────────────────────────────────────────────────

def encrypt_private_key(private_key_bytes: bytes, passphrase: str) -> bytes:
    """
    Chiffre une clé privée Ed25519 avec scrypt + AES-256-GCM.

    Args:
        private_key_bytes: 32 bytes de clé privée Ed25519
        passphrase:        Passphrase en clair (min recommandé : 12 chars)

    Returns:
        97 bytes du fichier chiffré (format PQKY v1)

    Raises:
        ValueError: Si la clé n'est pas de 32 bytes
    """
    if len(private_key_bytes) != KEY_SIZE:
        raise ValueError(
            f"Clé privée invalide : {len(private_key_bytes)} bytes "
            f"(attendu {KEY_SIZE})"
        )

    # Générer salt et nonce aléatoires
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)

    # Dériver la clé AES depuis la passphrase
    aes_key = bytearray(_derive_key(passphrase, salt))

    try:
        # Chiffrer avec AES-256-GCM
        aesgcm = AESGCM(bytes(aes_key))
        ciphertext = aesgcm.encrypt(nonce, private_key_bytes, None)
        # ciphertext = 32 bytes chiffrés + 16 bytes tag GCM = 48 bytes
    finally:
        _secure_erase(aes_key)

    # Construire le fichier
    result = (
        MAGIC
        + bytes([VERSION])
        + salt
        + nonce
        + ciphertext
    )

    assert len(result) == EXPECTED_FILE_SIZE, (
        f"Taille fichier inattendue : {len(result)} bytes"
    )

    logger.debug("[KeyStore] Clé privée chiffrée (scrypt+AES-256-GCM)")
    return result


# ─── Déchiffrement ────────────────────────────────────────────────────────────

def decrypt_private_key(encrypted_data: bytes, passphrase: str) -> bytes:
    """
    Déchiffre une clé privée Ed25519.

    Args:
        encrypted_data: Contenu du fichier .enc (97 bytes)
        passphrase:     Passphrase en clair

    Returns:
        32 bytes de clé privée Ed25519

    Raises:
        KeyFileCorruptedError:  Format invalide ou fichier corrompu
        InvalidPassphraseError: Passphrase incorrecte
    """
    # Vérifier le magic et la taille
    if len(encrypted_data) != EXPECTED_FILE_SIZE:
        raise KeyFileCorruptedError(
            f"Taille invalide : {len(encrypted_data)} bytes "
            f"(attendu {EXPECTED_FILE_SIZE})"
        )

    if encrypted_data[:4] != MAGIC:
        raise KeyFileCorruptedError(
            f"Magic invalide : {encrypted_data[:4]} (attendu {MAGIC})"
        )

    version = encrypted_data[4]
    if version != VERSION:
        raise KeyFileCorruptedError(
            f"Version non supportée : {version} (supporté : {VERSION})"
        )

    # Extraire les composantes
    offset = 5
    salt = encrypted_data[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = encrypted_data[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = encrypted_data[offset:]

    # Dériver la clé AES
    aes_key = bytearray(_derive_key(passphrase, salt))

    try:
        aesgcm = AESGCM(bytes(aes_key))
        try:
            private_key_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag:
            raise InvalidPassphraseError(
                "Passphrase incorrecte ou fichier corrompu"
            )
    finally:
        _secure_erase(aes_key)

    if len(private_key_bytes) != KEY_SIZE:
        raise KeyFileCorruptedError(
            f"Clé déchiffrée invalide : {len(private_key_bytes)} bytes"
        )

    logger.debug("[KeyStore] Clé privée déchiffrée avec succès")
    return private_key_bytes


# ─── Fichier .enc ─────────────────────────────────────────────────────────────

def save_encrypted_key(
    private_key_bytes: bytes,
    passphrase: str,
    path: Path,
) -> None:
    """
    Chiffre et sauvegarde une clé privée dans un fichier .enc.

    Args:
        private_key_bytes: 32 bytes de clé privée
        passphrase:        Passphrase de protection
        path:              Chemin du fichier de destination

    Le fichier est créé avec permissions 0o600 (lecture seule par l'owner).
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    encrypted = encrypt_private_key(private_key_bytes, passphrase)

    path.write_bytes(encrypted)
    path.chmod(0o600)

    logger.info(f"[KeyStore] Clé chiffrée sauvegardée : {path}")


def load_encrypted_key(path: Path, passphrase: str) -> bytes:
    """
    Charge et déchiffre une clé privée depuis un fichier .enc.

    Args:
        path:       Chemin du fichier .enc
        passphrase: Passphrase de déchiffrement

    Returns:
        32 bytes de clé privée Ed25519

    Raises:
        FileNotFoundError:     Fichier introuvable
        KeyFileCorruptedError: Format invalide
        InvalidPassphraseError: Passphrase incorrecte
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Fichier de clé introuvable : {path}")

    encrypted_data = path.read_bytes()
    return decrypt_private_key(encrypted_data, passphrase)


def save_plaintext_key(private_key_bytes: bytes, path: Path) -> None:
    """
    Sauvegarde une clé privée en clair (Free tier sans passphrase).

    ⚠️  Déconseillé en production — utiliser save_encrypted_key si possible.

    Format : base64 standard, un seul champ JSON minimaliste.
    """
    import base64
    import json

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "format":      "plaintext",
        "version":     "1.8.1",
        "private_key": base64.b64encode(private_key_bytes).decode("ascii"),
        "warning":     "UNENCRYPTED — do not share or commit",
    }
    path.write_text(json.dumps(data, indent=2))
    path.chmod(0o600)

    logger.warning(
        f"[KeyStore] Clé sauvegardée en clair (non chiffrée) : {path}"
    )


def load_plaintext_key(path: Path) -> bytes:
    """
    Charge une clé privée en clair (Free tier sans passphrase).

    Raises:
        FileNotFoundError:    Fichier introuvable
        KeyFileCorruptedError: Format invalide
    """
    import base64
    import json

    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Fichier de clé introuvable : {path}")

    try:
        data = json.loads(path.read_text())
        return base64.b64decode(data["private_key"])
    except Exception as e:
        raise KeyFileCorruptedError(f"Format de clé invalide : {e}")


def is_encrypted(path: Path) -> bool:
    """
    Détecte si un fichier de clé est chiffré (magic PQKY)
    ou en clair (JSON).
    """
    path = Path(path)
    if not path.exists():
        return False
    try:
        header = path.read_bytes()[:4]
        return header == MAGIC
    except Exception:
        return False


def re_encrypt_key(
    path: Path,
    old_passphrase: Optional[str],
    new_passphrase: str,
) -> None:
    """
    Rechiffre une clé avec une nouvelle passphrase.
    Utile pour la migration v1.6.0 → v1.8.1.

    Args:
        path:           Fichier .enc ou JSON en clair
        old_passphrase: Ancienne passphrase (None si clé en clair)
        new_passphrase: Nouvelle passphrase
    """
    # Charger la clé existante
    if is_encrypted(path):
        if old_passphrase is None:
            raise InvalidPassphraseError(
                "Passphrase requise pour déchiffrer la clé existante"
            )
        private_key = load_encrypted_key(path, old_passphrase)
    else:
        private_key = load_plaintext_key(path)

    # Sauvegarder avec la nouvelle passphrase
    # Backup de l'ancien fichier
    backup = path.with_suffix(".key.bak")
    path.rename(backup)

    try:
        save_encrypted_key(private_key, new_passphrase, path)
        logger.info(f"[KeyStore] Clé rechiffrée. Backup : {backup}")
    except Exception:
        # Restaurer le backup en cas d'erreur
        backup.rename(path)
        raise
    finally:
        # Effacer la clé de la RAM
        if isinstance(private_key, bytearray):
            _secure_erase(private_key)

# ─── Aliases courts (compat tests) ───────────────────────────────────────────
# encrypt_key(private_key, passphrase, path) → save_encrypted_key
# load_key(passphrase, path)                 → load_encrypted_key

def encrypt_key(private_key: bytes, passphrase: str, path: "Path") -> None:
    """Alias court : chiffre et sauvegarde la clé privée."""
    save_encrypted_key(private_key, passphrase, path)


def load_key(passphrase: str, path: "Path") -> bytes:
    """Alias court : charge et déchiffre la clé privée."""
    return load_encrypted_key(path, passphrase)

# ─── Public API ───────────────────────────────────────────────────────────────
__all__ = [
    "encrypt_private_key",
    "decrypt_private_key",
    "save_encrypted_key",
    "load_encrypted_key",
    "save_plaintext_key",
    "load_plaintext_key",
    "is_encrypted",
    "re_encrypt_key",
    "_secure_erase",
    "encrypt_key",       # ← ajouté
    "load_key",
    "KeyStoreError",
    "InvalidPassphraseError",
    "KeyFileCorruptedError",
]
