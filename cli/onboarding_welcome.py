# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
piqrypt-welcome — Message affiché après pip install piqrypt.
Appelé automatiquement via l'entry point piqrypt-welcome.
"""
import sys


def main():
    if not sys.stdout.isatty():
        return

    ESC = "\033["

    def bold(t):   return f"{ESC}1m{t}{ESC}0m"
    def cyan(t):   return f"{ESC}96m{t}{ESC}0m"
    def green(t):  return f"{ESC}92m{t}{ESC}0m"
    def dim(t):    return f"{ESC}2m{t}{ESC}0m"

    try:
        import piqrypt
        version = piqrypt.__version__
    except Exception:
        version = "installed"

    print()
    print(bold(f"  {'━' * 44}"))
    print(bold(f"  PiQrypt {version} ✓"))
    print(bold(f"  {'━' * 44}"))
    print()
    print(f"  {green('→')} {cyan('piqrypt demo')}   {dim('live agents in Vigil  (30s, no setup)')}")
    print(f"  {green('→')} {cyan('piqrypt init')}   {dim('set up your first agent')}")
    print()
    print(f"  {dim('Docs : https://piqrypt.com · https://aiss-standard.org')}")
    print()


if __name__ == "__main__":
    main()
