# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#!/usr/bin/env python3
"""
run_all.py — Lance tous les tests PiQrypt v1.8.3
================================================

Usage :
    cd piqrypt/
    python tests/run_all.py

    # Verbose
    python tests/run_all.py -v

    # Un seul module
    python tests/run_all.py --module tsi_engine
"""
import os
import argparse
import sys
import unittest
from pathlib import Path

ROOT       = Path(__file__).resolve().parent.parent
TESTS_DIR  = Path(__file__).resolve().parent

# Ajouter la racine du projet et les sous-modules au path
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "aiss"))
sys.path.insert(0, str(ROOT / "vigil"))
sys.path.insert(0, str(ROOT / "bridges" / "ollama"))
sys.path.insert(0, str(TESTS_DIR))

# Couleurs terminal
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

TEST_MODULES = [
    ("aiss/key_store.py",        "test_aiss_key_store"),
    ("aiss/agent_registry.py",   "test_aiss_agent_registry"),
    ("aiss/identity_session.py", "test_aiss_identity_session"),
    ("aiss/migration.py",        "test_aiss_migration"),
    ("aiss/tsi_engine.py",       "test_aiss_tsi_engine"),
    ("aiss/a2c_detector.py",     "test_aiss_a2c_detector"),
    ("aiss/anomaly_monitor.py",  "test_aiss_anomaly_monitor"),
    ("aiss/trust_score.py",      "test_aiss_trust_score"),
    ("aiss/identity.py",         "test_aiss_identity"),
    ("aiss/memory.py",           "test_aiss_memory"),
    ("vigil/vigil_server.py",    "test_vigil_server"),
    ("tests/security/",          "test_security_keystore"),
    ("tests/security/",          "test_security_registry"),
    ("tests/security/",          "test_security_chain"),
    ("tests/security/",          "test_security_session"),
    ("tests/security/",          "test_security_migration"),
    ("tests/security/",          "test_security_memory"),
    ("bridges/ollama/",          "test_bridges_ollama"),
]


def run_module(module_name: str, verbosity: int = 1) -> unittest.TestResult:
    loader = unittest.TestLoader()
    try:
        suite = loader.loadTestsFromName(module_name)
    except ModuleNotFoundError as e:
        print(f"  {YELLOW}SKIP{RESET} {module_name} — module non trouve : {e}")
        return None
    runner = unittest.TextTestRunner(verbosity=0, stream=open(os.devnull, "w"))
    return runner.run(suite)


def main():
    parser = argparse.ArgumentParser(description="PiQrypt v1.8.3 — Test runner")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--module", help="Lancer un seul module (ex: tsi_engine)")
    args = parser.parse_args()

    _ = 2 if args.verbose else 1

    print(f"\n{BOLD}{CYAN}PiQrypt v1.8.3 — Test Suite{RESET}")
    print(f"Racine projet : {ROOT}")
    print("=" * 60)

    # Filtre si --module
    modules = TEST_MODULES
    if args.module:
        modules = [(f, m) for f, m in TEST_MODULES if args.module in m]
        if not modules:
            print(f"{RED}Module '{args.module}' non trouve.{RESET}")
            print("Modules disponibles :", [m for _, m in TEST_MODULES])
            sys.exit(1)

    total_tests = 0
    total_ok    = 0
    total_fail  = 0
    total_error = 0
    total_skip  = 0
    failed_modules = []

    for file_path, module_name in modules:
        # Verifier si le fichier source existe
        src = ROOT / file_path
        exists = src.exists() or src.is_dir()

        print(f"\n{BOLD}[ {module_name} ]{RESET}", end="")
        if not exists:
            print(f"  {YELLOW}fichier source manquant : {file_path}{RESET}")

        if args.verbose:
            loader = unittest.TestLoader()
            try:
                suite = loader.loadTestsFromName(module_name)
                runner = unittest.TextTestRunner(verbosity=2)
                result = runner.run(suite)
            except ModuleNotFoundError as e:
                print(f"  {YELLOW}SKIP — {e}{RESET}")
                total_skip += 1
                continue
        else:
            result = run_module(module_name)
            if result is None:
                total_skip += 1
                continue

        n  = result.testsRun
        ok = n - len(result.failures) - len(result.errors) - len(result.skipped)
        total_tests += n
        total_ok    += ok
        total_fail  += len(result.failures)
        total_error += len(result.errors)
        total_skip  += len(result.skipped)

        status = GREEN + "OK" + RESET if result.wasSuccessful() else RED + "FAIL" + RESET
        print(f"  {status}  {ok}/{n} tests passes", end="")
        if result.skipped:
            print(f"  ({YELLOW}{len(result.skipped)} skipped{RESET})", end="")
        print()

        if not result.wasSuccessful():
            failed_modules.append(module_name)
            for test, msg in result.failures + result.errors:
                first_line = msg.strip().split("\n")[-1]
                print(f"    {RED}✗{RESET} {test}: {first_line[:80]}")

    # Bilan final
    print("\n" + "=" * 60)
    print(f"{BOLD}BILAN{RESET}")
    print(f"  Tests executes : {total_tests}")
    print(f"  {GREEN}Passes{RESET}        : {total_ok}")
    if total_fail:
        print(f"  {RED}Echecs{RESET}        : {total_fail}")
    if total_error:
        print(f"  {RED}Erreurs{RESET}       : {total_error}")
    if total_skip:
        print(f"  {YELLOW}Ignores{RESET}       : {total_skip}")

    if failed_modules:
        print(f"\n{RED}Modules en echec :{RESET}")
        for m in failed_modules:
            print(f"  - {m}")
        print()
        sys.exit(1)
    else:
        print(f"\n{GREEN}{BOLD}Tous les tests sont passes.{RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
