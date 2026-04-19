# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Apache License, Version 2.0.
# See cli/LICENSE for full terms.

"""
piqrypt demo / piqrypt init — Onboarding UX commands.
"""

import os
import sys
import json
import time
import getpass
import subprocess
import webbrowser
from pathlib import Path


# ── Couleurs ──────────────────────────────────────────────────────────────────

def _c(t, code):
    return f"\033[{code}m{t}\033[0m" if sys.stdout.isatty() else t

def bold(t):   return _c(t, "1")
def green(t):  return _c(t, "92")
def cyan(t):   return _c(t, "96")
def yellow(t): return _c(t, "33")
def dim(t):    return _c(t, "2")
def red(t):    return _c(t, "91")


# ── Constantes ────────────────────────────────────────────────────────────────

BRIDGES = [
    ("langchain", "LangChain",     "🦜"),
    ("crewai",    "CrewAI",        "🤖"),
    ("autogen",   "AutoGen",       "⚡"),
    ("mcp",       "MCP",           "🔌"),
    ("ollama",    "Ollama",        "🦙"),
    ("ros2",      "ROS2",          "🦾"),
    ("rpi",       "Raspberry Pi",  "🍓"),
    ("nocode",    "No-Code / MCP", "✨"),
]

FAMILIES = [
    ("nexus",      "Nexus Labs    — DevOps / Infra   (Ollama + LangGraph)"),
    ("pixelflow",  "PixelFlow     — Digital Agency   (CrewAI)"),
    ("alphacore",  "AlphaCore     — Quant Trading    (AutoGen)"),
]

VIGIL_URL   = "http://localhost:8421"
VIGIL_TOKEN = "test_token_local_dev"

SNIPPETS = {
    "langchain": """\
from piqrypt.bridges.langchain import PiQryptCallbackHandler

handler = PiQryptCallbackHandler(agent_name="{name}")
chain = your_chain.with_config(callbacks=[handler])
""",
    "crewai": """\
from piqrypt.bridges.crewai import AuditedAgent as Agent

agent = Agent(
    role="Analyst",
    goal="...",
    agent_name="{name}",
)
""",
    "autogen": """\
from piqrypt.bridges.autogen import AuditedAssistant

assistant = AuditedAssistant(
    name="{name}",
    agent_name="{name}",
)
""",
    "mcp": """\
# claude_desktop_config.json
{
  "mcpServers": {
    "piqrypt": {
      "command": "piqrypt",
      "args": ["mcp-server"],
      "env": {
        "PIQRYPT_IDENTITY": "~/.piqrypt/{name}.json"
      }
    }
  }
}
""",
    "ollama": """\
from piqrypt.bridges.ollama import AuditedOllama

llm = AuditedOllama(
    model="llama3.2",
    agent_name="{name}",
)
""",
    "ros2": """\
from piqrypt.bridges.ros2 import AuditedLifecycleNode

class MyNode(AuditedLifecycleNode):
    def __init__(self):
        super().__init__("my_node", agent_name="{name}")
""",
    "rpi": """\
from piqrypt.bridges.rpi import AuditedPiAgent

agent = AuditedPiAgent(
    agent_name="{name}",
    gpio_pin=18,
)
""",
    "nocode": """\
# 3 steps — no code required
# 1. pip install piqrypt
# 2. piqrypt mcp-config --name {name}
# 3. Open Claude Desktop → Settings → MCP → Refresh
""",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _launcher_path() -> Path:
    root = _repo_root()
    candidate = root / "cli" / "piqrypt_start.py"
    if candidate.exists():
        return candidate
    fallback = root / "piqrypt_start.py"
    if fallback.exists():
        return fallback
    raise FileNotFoundError("piqrypt_start.py not found")


def _start_vigil_bg() -> subprocess.Popen:
    launcher = _launcher_path()
    env = {
        **os.environ,
        "VIGIL_TOKEN":         VIGIL_TOKEN,
        "VIGIL_DEV_DELETE":    "1",
        "PIQRYPT_SCRYPT_N":    "16384",
        "VIGIL_NO_BROWSER":    "1",
        "PYTHONIOENCODING":    "utf-8",
    }
    return subprocess.Popen(
        [sys.executable, str(launcher), "--vigil"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _wait_vigil(timeout: int = 12) -> bool:
    import urllib.request
    import urllib.error
    url = f"{VIGIL_URL}/health"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return True
        except Exception:
            time.sleep(0.5)
    return False


def _open_vigil(no_browser: bool = False) -> None:
    if no_browser:
        return
    url = f"{VIGIL_URL}/?token={VIGIL_TOKEN}"
    try:
        webbrowser.open(url)
    except Exception:
        pass


def _copy_to_clipboard(text: str) -> bool:
    try:
        if sys.platform == "win32":
            proc = subprocess.Popen(
                ["clip"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            proc.communicate(input=text.encode("utf-16-le"))
            return proc.returncode == 0
        elif sys.platform == "darwin":
            proc = subprocess.Popen(
                ["pbcopy"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            proc.communicate(input=text.encode("utf-8"))
            return proc.returncode == 0
        else:
            for tool in ("xclip -selection clipboard", "xsel --clipboard --input"):
                parts = tool.split()
                proc = subprocess.Popen(
                    parts, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                proc.communicate(input=text.encode("utf-8"))
                if proc.returncode == 0:
                    return True
    except Exception:
        pass
    return False


# ── cmd_demo ──────────────────────────────────────────────────────────────────

def cmd_demo(args):
    """piqrypt demo [--family nexus|pixelflow|alphacore] [--no-browser]"""
    family = getattr(args, 'family', None)
    no_browser = getattr(args, 'no_browser', False)

    print()
    print(bold("  ╔══════════════════════════════════════╗"))
    print(bold("  ║       PiQrypt — Live Demo            ║"))
    print(bold("  ╚══════════════════════════════════════╝"))
    print()

    if not family:
        print("  Choisissez une famille d'agents :\n")
        for i, (fid, label) in enumerate(FAMILIES, 1):
            print(f"    {bold(str(i))}.  {label}")
        print()
        while True:
            try:
                choice = input("  Votre choix [1-3] : ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n  Annulé.")
                return 0
            if choice in ("1", "2", "3"):
                family = FAMILIES[int(choice) - 1][0]
                break
            print(red("  Choix invalide."))

    family_label = next((label for fid, label in FAMILIES if fid == family), family)
    print(f"  Famille : {cyan(family_label.strip())}")
    print()

    # Démarrage Vigil
    print(f"  {dim('Démarrage Vigil...')}", end="", flush=True)
    vigil_proc = _start_vigil_bg()

    ok = _wait_vigil(timeout=12)
    if not ok:
        print(red(" ✗"))
        print(red("\n  Vigil n'a pas démarré dans les 12 secondes."))
        print(dim("  Vérifiez que le port 8421 est libre."))
        vigil_proc.terminate()
        return 1
    print(green(" ✓"))

    # Reset + lancement démo
    root = _repo_root()
    demo_script = root / "demos" / "demo_families.py"

    print(f"  {dim('Reset des agents demo...')}", end="", flush=True)
    try:
        subprocess.run(
            [sys.executable, str(demo_script), "--reset"],
            cwd=str(root),
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        print(green(" ✓"))
    except Exception:
        print(dim(" (skip)"))

    print(f"  {dim('Lancement des agents...')}", end="", flush=True)
    demo_env = {
        **os.environ,
        "VIGIL_TOKEN":       VIGIL_TOKEN,
        "PIQRYPT_SCRYPT_N":  "16384",
        "PYTHONIOENCODING":  "utf-8",
    }
    demo_proc = subprocess.Popen(
        [sys.executable, str(demo_script), "--family", family, "--loop", "--fast"],
        cwd=str(root),
        env=demo_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(green(" ✓"))

    time.sleep(2)

    print()
    print(f"  {green('✓')} Vigil       : {cyan(f'{VIGIL_URL}/?token={VIGIL_TOKEN}')}")
    print(f"  {green('✓')} Famille     : {cyan(family)}")
    print()

    _open_vigil(no_browser)

    print(bold(f"  {'━' * 44}"))
    print(f"  Agents en live dans Vigil — Ctrl+C pour arrêter")
    print(bold(f"  {'━' * 44}"))
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    print()
    print(dim("  Arrêt..."))
    for proc in (demo_proc, vigil_proc):
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    print(dim("  Stack arrêté."))
    print()
    return 0


# ── cmd_init ──────────────────────────────────────────────────────────────────

def cmd_init(args):
    """piqrypt init [--name NAME] [--bridge BRIDGE] [--no-browser]"""
    no_browser = getattr(args, 'no_browser', False)

    print()
    print(bold("  ╔══════════════════════════════════════╗"))
    print(bold("  ║       PiQrypt — Agent Setup          ║"))
    print(bold("  ╚══════════════════════════════════════╝"))
    print()

    # ── Nom de l'agent ────────────────────────────────────────────────────────
    agent_name = getattr(args, 'name', None)
    if not agent_name:
        try:
            raw = input(f"  Nom de l'agent {dim('[my-agent]')} : ").strip()
            agent_name = raw if raw else "my-agent"
        except (KeyboardInterrupt, EOFError):
            print("\n  Annulé.")
            return 0
    agent_name = agent_name.replace(" ", "-")

    # ── Choix du bridge ───────────────────────────────────────────────────────
    bridge_id = getattr(args, 'bridge', None)
    if not bridge_id:
        print()
        print("  Choisissez votre framework :\n")
        for i, (bid, label, icon) in enumerate(BRIDGES, 1):
            print(f"    {bold(str(i))}.  {icon}  {label}")
        print()
        while True:
            try:
                choice = input(f"  Votre choix [1-{len(BRIDGES)}] : ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n  Annulé.")
                return 0
            if choice.isdigit() and 1 <= int(choice) <= len(BRIDGES):
                bridge_id = BRIDGES[int(choice) - 1][0]
                break
            print(red("  Choix invalide."))

    bridge_label = next((label for bid, label, icon in BRIDGES if bid == bridge_id), bridge_id)

    # ── Passphrase ────────────────────────────────────────────────────────────
    passphrase = None
    try:
        print()
        pp = getpass.getpass(f"  Passphrase {dim('(optionnel — Entrée = sans)')} : ")
        if pp:
            pp2 = getpass.getpass("  Confirmer la passphrase : ")
            if pp != pp2:
                print(yellow("  ⚠  Passphrases différentes — clé stockée sans chiffrement."))
            else:
                passphrase = pp
    except (KeyboardInterrupt, EOFError):
        passphrase = None

    # ── Génération des clés ───────────────────────────────────────────────────
    print()
    print(f"  {dim('Génération des clés Ed25519...')}", end="", flush=True)

    try:
        import aiss
        from aiss import generate_keypair, derive_agent_id
        private_key_bytes, public_key_bytes = generate_keypair()
        agent_id = derive_agent_id(public_key_bytes)

        private_b64 = aiss.crypto.ed25519.encode_base64(private_key_bytes)
        public_b64  = aiss.crypto.ed25519.encode_base64(public_key_bytes)
    except Exception as e:
        print(red(f" ✗\n  Erreur : {e}"))
        return 1

    print(green(" ✓"))

    # ── Écriture du fichier identité ──────────────────────────────────────────
    piqrypt_dir = Path.home() / ".piqrypt"
    piqrypt_dir.mkdir(parents=True, exist_ok=True)
    identity_path = piqrypt_dir / f"{agent_name}.json"

    import datetime as _dt
    identity_doc = {
        "agent_name":  agent_name,
        "agent_id":    agent_id,
        "public_key":  public_b64,
        "private_key": private_b64,
        "algorithm":   "Ed25519",
        "created_at":  _dt.datetime.utcnow().isoformat() + "Z",
        "bridge":      bridge_id,
    }

    if passphrase:
        try:
            encrypted = aiss.crypto.ed25519.encrypt_private_key(private_key_bytes, passphrase)
            identity_doc["private_key"] = encrypted
            identity_doc["encrypted"] = True
        except Exception:
            pass

    try:
        with open(identity_path, "w", encoding="utf-8") as f:
            json.dump(identity_doc, f, indent=2)
        print(f"  {green('✓')} Identité    : {dim(str(identity_path))}")
    except Exception as e:
        print(red(f"  ✗ Impossible d'écrire l'identité : {e}"))
        return 1

    print(f"  {green('✓')} Agent ID    : {cyan(agent_id[:24])}...")
    print(f"  {green('✓')} Clé         : {'🔒 chiffrée' if passphrase else dim('non chiffrée')}")
    print(f"  {green('✓')} Bridge      : {bridge_label}")

    # ── Snippet d'intégration ──────────────────────────────────────────────────
    snippet = SNIPPETS.get(bridge_id, SNIPPETS["langchain"]).replace("{name}", agent_name)

    print()
    print(bold(f"  {'━' * 44}"))
    print(f"  Snippet {bridge_label} :")
    print(bold(f"  {'━' * 44}"))
    for line in snippet.splitlines():
        print(f"  {cyan(line)}")
    print(bold(f"  {'━' * 44}"))

    copied = _copy_to_clipboard(snippet)
    if copied:
        print(f"\n  {green('✓')} Snippet copié dans le clipboard.")

    # ── Démarrage Vigil ───────────────────────────────────────────────────────
    print()
    print(f"  {dim('Démarrage Vigil...')}", end="", flush=True)
    vigil_proc = _start_vigil_bg()

    ok = _wait_vigil(timeout=12)
    if not ok:
        print(red(" ✗"))
        print(yellow("  Vigil n'a pas démarré — continuez sans dashboard."))
        vigil_proc.terminate()
        print()
        print(bold(f"  {'━' * 44}"))
        print(f"  Prochaine étape : collez le snippet dans votre code.")
        print(bold(f"  {'━' * 44}"))
        print()
        return 0
    print(green(" ✓"))

    print(f"  {green('✓')} Vigil       : {cyan(f'{VIGIL_URL}/?token={VIGIL_TOKEN}')}")
    print()

    _open_vigil(no_browser)

    print(bold(f"  {'━' * 44}"))
    print(f"  Vigil ouvert — Ctrl+C pour arrêter")
    print(bold(f"  {'━' * 44}"))
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    print()
    print(dim("  Arrêt Vigil..."))
    try:
        vigil_proc.terminate()
        vigil_proc.wait(timeout=5)
    except Exception:
        try:
            vigil_proc.kill()
        except Exception:
            pass

    print(dim("  Vigil arrêté."))
    print()
    return 0


# ── cmd_onboard ───────────────────────────────────────────────────────────────

def cmd_onboard(args):
    """piqrypt onboard — Ouvre la page d'onboarding interactive dans le browser."""
    import webbrowser
    from pathlib import Path
    page = Path(__file__).resolve().parent.parent / "static" / "onboarding" / "index.html"
    if page.exists():
        webbrowser.open(f"file:///{page}")
        print("  ✓ Onboarding page opened in browser")
    else:
        print(f"  ✗ Page not found: {page}")
    return 0
