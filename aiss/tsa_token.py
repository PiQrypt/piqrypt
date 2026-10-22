# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute -- see root LICENSE for details.

"""
Détection STRUCTURELLE d'un jeton d'horodatage dans un événement.

Le champ trusted_timestamp est détaché : il n'est couvert par aucune signature, donc
n'importe qui peut l'ajouter ou le modifier. Sa seule présence ne prouve rien. has_tsa_token
répond uniquement à la question « y a-t-il un jeton non vide ? » ; elle ne vérifie ni la
signature du jeton, ni l'empreinte, ni la chaîne de certificats. Toute décision de confiance
(résolution de fork, rapports) doit passer par un vérificateur fourni par l'appelant (voir
aiss.rfc3161.make_tsa_verifier) et ne jamais se fonder sur le champ « status » auto-déclaré.

Les vrais jetons sont stockés sous "token" ; l'ancienne clé "rfc3161_token" reste acceptée en
lecture.
"""
from typing import Any, Dict, Optional

TOKEN_KEYS = ("token", "rfc3161_token")


def tsa_token_value(event: Any) -> Optional[str]:
    """Valeur brute du jeton ("base64:..." ou ancien format), ou None si absent ou vide."""
    if not isinstance(event, dict):
        return None
    trusted = event.get("trusted_timestamp")
    if not isinstance(trusted, dict):
        return None
    for key in TOKEN_KEYS:
        value = trusted.get(key)
        if isinstance(value, str):
            stripped = value.strip()
            if stripped and stripped != "base64:":
                return value
    return None


def has_tsa_token(event: Dict[str, Any]) -> bool:
    """True si l'événement porte un jeton non vide (contrôle structurel, sans confiance)."""
    return tsa_token_value(event) is not None


__all__ = ["TOKEN_KEYS", "has_tsa_token", "tsa_token_value"]
