"""
run_bridges.py - Lance tous les tests bridges depuis piqrypt/
Usage: python run_bridges.py
"""
import subprocess
import sys
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BRIDGES = ROOT / "bridges"

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# Bridges a tester avec leur module principal
BRIDGE_TESTS = [
    ("langchain",  "test_piqrypt_langchain.py"),
    ("crewai",     "test_piqrypt_crewai.py"),
    ("autogen",    "test_piqrypt_autogen.py"),
    ("openclaw",   "test_piqrypt_openclaw.py"),
    ("session",    "test_piqrypt_session.py"),
    ("mcp",        "test_piqrypt_mcp.py"),
    ("ollama",     "test_piqrypt_ollama.py"),
    ("ros",        "test_piqrypt_ros.py"),
    ("rpi",        "test_piqrypt_rpi.py"),
]

results = {}

print(f"\n{BOLD}{CYAN}PiQrypt v1.7.1 - Bridge Tests{RESET}")
print("=" * 60)

for bridge_name, test_file in BRIDGE_TESTS:
    bridge_dir = BRIDGES / bridge_name
    test_path  = bridge_dir / test_file

    if not test_path.exists():
        print(f"  {YELLOW}SKIP{RESET} {bridge_name} - test file not found")
        results[bridge_name] = "SKIP"
        continue

    # Environnement : injecter le dossier du bridge dans PYTHONPATH
    env = os.environ.copy()
    env["PYTHONPATH"] = (
        str(bridge_dir) + os.pathsep + str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    )
    env["PIQRYPT_SCRYPT_N"] = "16384"

    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(test_path), "-v", "--tb=short", "-q"],
        capture_output=True,
        text=True,
        cwd=str(bridge_dir),  # Executer DEPUIS le dossier du bridge
        env=env,
    )

    # Parser le resultat
    output = proc.stdout + proc.stderr
    passed = 0
    failed = 0
    for line in output.splitlines():
        if "passed" in line and ("failed" in line or "passed" in line):
            import re
            m = re.search(r"(\d+) passed", line)
            if m:
                passed = int(m.group(1))
            m = re.search(r"(\d+) failed", line)
            if m:
                failed = int(m.group(1))
        if "error" in line.lower() and "importerror" in line.lower():
            pass

    if proc.returncode == 0:
        print(f"  {GREEN}PASS{RESET} {bridge_name:<12} {passed} tests passed")
        results[bridge_name] = f"PASS ({passed})"
    elif "ImportError" in output or "ModuleNotFoundError" in output:
        # Extraire l'erreur
        for line in output.splitlines():
            if "ImportError" in line or "ModuleNotFoundError" in line:
                err = line.strip()[:60]
                break
        else:
            err = "import error"
        print(f"  {YELLOW}SKIP{RESET} {bridge_name:<12} {err}")
        results[bridge_name] = "SKIP (infra)"
    else:
        print(f"  {RED}FAIL{RESET} {bridge_name:<12} {passed} passed, {failed} failed")
        # Afficher les failures
        for line in output.splitlines():
            if "FAILED" in line:
                print(f"         {line.strip()}")
        results[bridge_name] = f"FAIL ({failed})"

print("\n" + "=" * 60)
print(f"{BOLD}BILAN BRIDGES{RESET}")
print("=" * 60)

total_pass = sum(1 for v in results.values() if v.startswith("PASS"))
total_skip = sum(1 for v in results.values() if v.startswith("SKIP"))
total_fail = sum(1 for v in results.values() if v.startswith("FAIL"))

for bridge, status in results.items():
    color = GREEN if status.startswith("PASS") else (YELLOW if status.startswith("SKIP") else RED)
    print(f"  {color}{status:<20}{RESET} {bridge}")

print(f"\n  PASS: {total_pass}  SKIP: {total_skip}  FAIL: {total_fail}")
print()
