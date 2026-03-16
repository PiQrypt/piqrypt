#!/usr/bin/env python3
"""
piqrypt_start.py — Launcher unique PiQrypt
==========================================

Démarre le stack PiQrypt selon le tier de licence actuel.

Usage :
    python piqrypt_start.py              # stack complet selon tier
    python piqrypt_start.py --vigil      # Vigil uniquement
    python piqrypt_start.py --trustgate  # TrustGate uniquement (Pro+ requis)
    python piqrypt_start.py --all        # force tout (si droits suffisants)
    python piqrypt_start.py --check      # vérifie la config sans démarrer
    python piqrypt_start.py --gen-tokens # génère des tokens sécurisés

Variables d'environnement :
    VIGIL_TOKEN         Token Bearer pour Vigil (obligatoire)
    TRUSTGATE_TOKEN     Token Bearer pour TrustGate (obligatoire si Pro+)
    PIQRYPT_HOME        Répertoire de données (défaut: ~/.piqrypt)
    VIGIL_PORT          Port Vigil (défaut: 8421)
    TRUSTGATE_PORT      Port TrustGate (défaut: 8422)
    VIGIL_HOST          Host Vigil (défaut: 127.0.0.1)
    TRUSTGATE_HOST      Host TrustGate (défaut: 127.0.0.1)

Tier → services disponibles :
    Free        → Vigil (lecture seule), TrustGate absent
    Pro / Team  → Vigil (complet), TrustGate (manuel)
    Business+   → Vigil (complet), TrustGate (complet)
    Enterprise  → Tout, illimité

IP : e-Soleau DSO2026006483 (INPI France — 19/02/2026)
"""

from __future__ import annotations

import argparse
import logging
import os
import secrets
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional

# ── Résolution des chemins ────────────────────────────────────────────────────
_LAUNCHER_DIR = Path(__file__).resolve().parent
for _p in [str(_LAUNCHER_DIR), str(_LAUNCHER_DIR / "aiss")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PIQRYPT] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("piqrypt.start")

# ── Ports par défaut ──────────────────────────────────────────────────────────
DEFAULT_VIGIL_PORT      = int(os.getenv("VIGIL_PORT",      "8421"))
DEFAULT_TRUSTGATE_PORT  = int(os.getenv("TRUSTGATE_PORT",  "8422"))
DEFAULT_HOST            = os.getenv("VIGIL_HOST",          "127.0.0.1")
DEFAULT_TRUSTGATE_HOST  = os.getenv("TRUSTGATE_HOST",      "127.0.0.1")

# ── Couleurs terminal ─────────────────────────────────────────────────────────
_USE_COLOR = sys.stdout.isatty()

def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

def green(t):  return _c(t, "32")
def yellow(t): return _c(t, "33")
def red(t):    return _c(t, "31")
def bold(t):   return _c(t, "1")
def cyan(t):   return _c(t, "36")
def dim(t):    return _c(t, "2")


# ══════════════════════════════════════════════════════════════════════════════
# TIER & LICENCE
# ══════════════════════════════════════════════════════════════════════════════

def get_current_tier() -> str:
    """Récupère le tier depuis aiss/license.py."""
    try:
        from aiss.license import get_tier
        return get_tier()
    except ImportError:
        try:
            from license import get_tier
            return get_tier()
        except ImportError:
            return "free"


def tier_allows_trustgate(tier: str) -> bool:
    """True si le tier permet TrustGate (Pro ou supérieur)."""
    return tier in ("pro", "team", "business", "enterprise")


def tier_allows_vigil_full(tier: str) -> bool:
    """True si le tier permet Vigil en mode complet."""
    return tier != "free"


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION CHECK
# ══════════════════════════════════════════════════════════════════════════════

class StartupCheck:
    """Vérifie la configuration avant démarrage."""

    def __init__(self, tier: str, want_vigil: bool = True, want_trustgate: bool = False):
        self.tier = tier
        self.want_vigil = want_vigil
        self.want_trustgate = want_trustgate
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def run(self) -> bool:
        """Lance tous les checks. Retourne True si OK pour démarrer."""
        self._check_python_version()
        self._check_auth_middleware()
        self._check_aiss_importable()
        self._check_tokens()
        self._check_ports()
        self._check_vigil_files()
        if self.want_trustgate:
            self._check_trustgate_available()
            self._check_trustgate_files()
        return len(self.errors) == 0

    def _check_python_version(self):
        if sys.version_info < (3, 9):
            self.errors.append(
                f"Python 3.9+ requis — version actuelle : {sys.version.split()[0]}"
            )

    def _check_auth_middleware(self):
        auth_path = _LAUNCHER_DIR / "auth_middleware.py"
        if not auth_path.exists():
            self.errors.append(
                f"auth_middleware.py introuvable dans {_LAUNCHER_DIR}. "
                "Placez auth_middleware.py à la racine du repo piqrypt/."
            )

    def _check_aiss_importable(self):
        try:
            import aiss
        except ImportError:
            self.errors.append(
                "Package 'aiss' non importable. "
                "Lancez depuis la racine du repo ou installez : pip install piqrypt"
            )

    def _check_tokens(self):
        if self.want_vigil:
            vigil_token = os.getenv("VIGIL_TOKEN", "").strip()
            if not vigil_token:
                self.errors.append(
                    "VIGIL_TOKEN non défini.\n"
                    "  Générez un token : python piqrypt_start.py --gen-tokens\n"
                    "  Puis : export VIGIL_TOKEN=<token>"
                )

        if self.want_trustgate and tier_allows_trustgate(self.tier):
            tg_token = os.getenv("TRUSTGATE_TOKEN", "").strip()
            if not tg_token:
                self.errors.append(
                    "TRUSTGATE_TOKEN non défini.\n"
                    "  export TRUSTGATE_TOKEN=<token>"
                )

    def _check_ports(self):
        import socket
        for port, name in [
            (DEFAULT_VIGIL_PORT if self.want_vigil else None, "Vigil"),
            (DEFAULT_TRUSTGATE_PORT if self.want_trustgate else None, "TrustGate"),
        ]:
            if port is None:
                continue
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind(("127.0.0.1", port))
                except OSError:
                    self.warnings.append(
                        f"Port {port} ({name}) déjà utilisé. "
                        f"Définissez {name.upper()}_PORT pour changer."
                    )

    def _check_vigil_files(self):
        vigil_server = _LAUNCHER_DIR / "vigil" / "vigil_server.py"
        vigil_html   = _LAUNCHER_DIR / "vigil" / "vigil_v4_final.html"

        if not vigil_server.exists():
            self.errors.append(f"vigil_server.py introuvable : {vigil_server}")
        if not vigil_html.exists():
            self.warnings.append(
                f"vigil_v4_final.html introuvable — le dashboard affichera le fallback HTML. "
                f"Attendu : {vigil_html}"
            )

    def _check_trustgate_available(self):
        if not tier_allows_trustgate(self.tier):
            self.errors.append(
                f"TrustGate non disponible sur le tier '{self.tier}'.\n"
                f"  Disponible à partir du tier Pro. https://piqrypt.com/pricing"
            )

    def _check_trustgate_files(self):
        candidates = [
            _LAUNCHER_DIR / "trustgate" / "trustgate_server.py",
        ]
        if not any(c.exists() for c in candidates):
            self.errors.append(
                "trustgate_server.py introuvable dans piqrypt/trustgate/. "
                "Vérifiez votre structure de repo."
            )

    def print_report(self):
        print()
        print(bold("PiQrypt Stack Launcher v1.7.0"))
        print(dim("─" * 50))
        print(f"  Tier      : {bold(self.tier.upper())}")
        print(f"  Vigil     : {'✅ complet' if tier_allows_vigil_full(self.tier) else '📖 lecture seule (Free)'}")
        print(f"  TrustGate : {('✅ ' + ('complet' if self.tier in ('business','enterprise') else 'manuel')) if tier_allows_trustgate(self.tier) else red('non disponible — upgrade Pro')}")
        print()

        if self.warnings:
            for w in self.warnings:
                print(yellow(f"  ⚠️  {w}"))
            print()

        if self.errors:
            for e in self.errors:
                print(red(f"  ❌ {e}"))
            print()
            print(red("  Startup annulé — corrigez les erreurs ci-dessus."))
        else:
            print(green("  ✅ Configuration valide — prêt à démarrer."))
        print()


# ══════════════════════════════════════════════════════════════════════════════
# PROCESS MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class ServiceProcess:
    """Gère un processus serveur (Vigil ou TrustGate)."""

    def __init__(self, name: str, script: Path, host: str, port: int,
                 extra_args: Optional[List[str]] = None):
        self.name  = name
        self.script = script
        self.host  = host
        self.port  = port
        self.extra_args = extra_args or []
        self._process: Optional[subprocess.Popen] = None

    def start(self) -> bool:
        """Démarre le processus. Retourne True si démarré."""
        cmd = [
            sys.executable, str(self.script),
            "--host", self.host,
            "--port", str(self.port),
        ] + self.extra_args

        try:
            env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
            self._process = subprocess.Popen(
                cmd, env=env,
                stdout=subprocess.PIPE, encoding="utf-8", errors="replace",
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            # Lire les premières lignes pour confirmer le démarrage
            threading.Thread(
                target=self._log_output,
                daemon=True,
                name=f"{self.name}-logger"
            ).start()

            # Attendre max 3s pour confirmer que le process ne crashe pas immédiatement
            time.sleep(0.5)
            if self._process.poll() is not None:
                log.error("[%s] Processus terminé prématurément (code %d)",
                          self.name, self._process.returncode)
                return False

            log.info("[%s] ✅ Démarré — http://%s:%d", self.name, self.host, self.port)
            return True

        except Exception as e:
            log.error("[%s] ❌ Échec démarrage : %s", self.name, e)
            return False

    def _log_output(self):
        if self._process and self._process.stdout:
            for line in self._process.stdout:
                line = line.rstrip()
                if line:
                    log.info("[%s] %s", self.name, line)

    def stop(self):
        if self._process and self._process.poll() is None:
            log.info("[%s] Arrêt en cours…", self.name)
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            log.info("[%s] ✅ Arrêté.", self.name)

    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def url(self) -> str:
        display_host = "localhost" if self.host in ("127.0.0.1", "0.0.0.0") else self.host
        return f"http://{display_host}:{self.port}"


# ══════════════════════════════════════════════════════════════════════════════
# LAUNCHER PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

class PiQryptLauncher:
    """Orchestre le démarrage et l'arrêt du stack complet."""

    def __init__(self, args: argparse.Namespace):
        self.args      = args
        self.tier      = get_current_tier()
        self.services: List[ServiceProcess] = []
        self._stopped  = False

    def _resolve_script(self, *candidates: Path) -> Optional[Path]:
        for c in candidates:
            if c.exists():
                return c
        return None

    def _build_services(self) -> List[ServiceProcess]:
        services = []

        # ── Vigil ──
        if not self.args.trustgate_only:
            vigil_script = self._resolve_script(
                _LAUNCHER_DIR / "vigil" / "vigil_server.py",
            )
            if vigil_script:
                services.append(ServiceProcess(
                    name="Vigil",
                    script=vigil_script,
                    host=DEFAULT_HOST,
                    port=DEFAULT_VIGIL_PORT,
                ))
            else:
                log.error("vigil_server.py introuvable — Vigil non démarré")

        # ── TrustGate ──
        launch_tg = (
            (self.args.trustgate or self.args.all or not self.args.vigil_only)
            and tier_allows_trustgate(self.tier)
            and not self.args.vigil_only
        )
        if launch_tg:
            tg_script = self._resolve_script(
                _LAUNCHER_DIR / "trustgate" / "trustgate_server.py",
            )
            if tg_script:
                services.append(ServiceProcess(
                    name="TrustGate",
                    script=tg_script,
                    host=DEFAULT_TRUSTGATE_HOST,
                    port=DEFAULT_TRUSTGATE_PORT,
                ))
            else:
                log.warning("trustgate_server.py introuvable — TrustGate non démarré")
        elif not tier_allows_trustgate(self.tier) and not self.args.vigil_only:
            log.info(
                "TrustGate non disponible sur le tier '%s'. "
                "Disponible à partir du tier Pro — https://piqrypt.com/pricing",
                self.tier
            )

        return services

    def run(self) -> int:
        """Lance le stack. Retourne le code de sortie."""

        # ── Check config ──
        want_tg = tier_allows_trustgate(self.tier) and not self.args.vigil_only
        check = StartupCheck(
            tier=self.tier,
            want_vigil=not self.args.trustgate_only,
            want_trustgate=want_tg,
        )
        check.print_report()

        if not check.run():
            return 1

        if self.args.check:
            return 0

        # ── Démarrer les services ──
        self.services = self._build_services()
        if not self.services:
            log.error("Aucun service à démarrer.")
            return 1

        print(bold("\n  Démarrage du stack PiQrypt…"))
        print()

        started = []
        for svc in self.services:
            if svc.start():
                started.append(svc)
            else:
                log.error("Échec démarrage %s — arrêt.", svc.name)
                self._shutdown_all()
                return 1

        # ── Résumé ──
        print()
        print(bold("  Stack PiQrypt operationnel"))
        # Ouverture navigateur geree par les launchers (start_*.ps1)
        print(dim("  " + "─" * 46))
        for svc in started:
            # Afficher l'URL avec token pour acces direct au dashboard
            _token = os.getenv("VIGIL_TOKEN", "") if svc.name == "Vigil" else os.getenv("TRUSTGATE_TOKEN", "")
            _tg_path = "/console" if svc.name == "TrustGate" else ""
            _display_url = f"{svc.url}{_tg_path}?token={_token}" if _token else svc.url
            print(f"  {green('●')} {svc.name:<12} {cyan(_display_url)}")
        tier_label = self.tier.upper()
        print(f"  {'Tier':<12} {bold(tier_label)}")
        print(f"  {'Auth':<12} {'✅ Bearer token' if os.getenv('VIGIL_TOKEN') else red('⚠️  non configuré')}")
        print()
        print(dim("  Ctrl+C pour arrêter."))
        print()

        # ── Graceful shutdown ──
        def _shutdown(sig, frame):
            if not self._stopped:
                self._stopped = True
                print()
                log.info("Signal %d reçu — arrêt en cours…", sig)
                self._shutdown_all()
                sys.exit(0)

        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT, _shutdown)

        # ── Boucle principale — surveiller les processus ──
        try:
            while True:
                time.sleep(5)
                for svc in started:
                    if not svc.is_running():
                        log.error(
                            "%s s'est arrêté de façon inattendue. "
                            "Relancez piqrypt_start.py.", svc.name
                        )
                        self._shutdown_all()
                        return 1
        except KeyboardInterrupt:
            pass
        finally:
            self._shutdown_all()

        return 0

    def _shutdown_all(self):
        for svc in self.services:
            try:
                svc.stop()
            except Exception as e:
                log.warning("Erreur arrêt %s : %s", svc.name, e)
        log.info("Stack PiQrypt arrêté.")


# ══════════════════════════════════════════════════════════════════════════════
# COMMANDES UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════

def cmd_gen_tokens():
    """Génère des tokens sécurisés pour VIGIL_TOKEN et TRUSTGATE_TOKEN."""
    vigil_token     = secrets.token_urlsafe(32)
    trustgate_token = secrets.token_urlsafe(32)

    print()
    print(bold("  Tokens PiQrypt générés"))
    print(dim("  " + "─" * 50))
    print()
    print("  Copiez ces lignes dans votre .env ou votre shell :\n")
    print(f"  export VIGIL_TOKEN={vigil_token}")
    print(f"  export TRUSTGATE_TOKEN={trustgate_token}")
    print()
    print(dim("  Ces tokens ne sont pas sauvegardés — notez-les maintenant."))
    print()

    # Proposer de créer un fichier .env
    env_file = _LAUNCHER_DIR / ".env.piqrypt"
    try:
        if not env_file.exists():
            env_file.write_text(
                f"# PiQrypt tokens — ne jamais committer ce fichier\n"
                f"VIGIL_TOKEN={vigil_token}\n"
                f"TRUSTGATE_TOKEN={trustgate_token}\n"
            )
            print(green(f"  ✅ Fichier créé : {env_file}"))
            print(dim("  Source : source .env.piqrypt  (bash/zsh)"))
            print()
    except OSError:
        pass


def cmd_status():
    """Affiche l'état de la configuration sans démarrer."""
    tier = get_current_tier()
    vigil_token = os.getenv("VIGIL_TOKEN", "")
    tg_token    = os.getenv("TRUSTGATE_TOKEN", "")

    print()
    print(bold("  PiQrypt Stack — État de la configuration"))
    print(dim("  " + "─" * 50))
    print(f"  Tier          : {bold(tier.upper())}")
    print(f"  VIGIL_TOKEN   : {'✅ défini' if vigil_token else red('❌ absent')}")
    print(f"  TRUSTGATE_TOKEN: {'✅ défini' if tg_token else (yellow('⚠️  absent') if tier_allows_trustgate(tier) else dim('non requis (Free)'))}")
    print()

    try:
        from aiss.license import get_license_info
        info = get_license_info()
        print(f"  Agents max    : {info.get('agents_max') or '∞'}")
        print(f"  Events/mois   : {info.get('events_month') or '∞'}")
        print(f"  TrustGate     : {info['features'].get('trustgate') or red('non disponible')}")
        print(f"  Quantum       : {'✅' if info['features'].get('quantum') else '—'}")
    except Exception:
        pass
    print()


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="PiQrypt Stack Launcher — démarre Vigil et TrustGate selon le tier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--vigil", dest="vigil_only", action="store_true",
        help="Démarrer Vigil uniquement"
    )
    parser.add_argument(
        "--trustgate", dest="trustgate", action="store_true",
        help="Inclure TrustGate (Pro+ requis)"
    )
    parser.add_argument(
        "--trustgate-only", dest="trustgate_only", action="store_true",
        help="TrustGate uniquement (Pro+ requis)"
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Démarrer tous les services disponibles selon le tier"
    )
    parser.add_argument(
        "--check", action="store_true",
        help="Vérifier la configuration sans démarrer"
    )
    parser.add_argument(
        "--gen-tokens", action="store_true",
        help="Générer des tokens d'authentification sécurisés"
    )
    parser.add_argument(
        "--status", action="store_true",
        help="Afficher l'état de la configuration"
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Logging verbose"
    )

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Commandes utilitaires
    if args.gen_tokens:
        cmd_gen_tokens()
        return 0

    if args.status:
        cmd_status()
        return 0

    # Lancer le stack
    launcher = PiQryptLauncher(args)
    return launcher.run()


if __name__ == "__main__":
    sys.exit(main())







