"""Guard for the aiss-standard sync allowlist (.github/scripts/sync_aiss.py).

The allowlist copies a fixed set of files into aiss-standard (MIT). If a synced file imports
an aiss module that is not synced, "import aiss" fails in the standard. These tests catch that
at the source, before a release is published.
"""
import ast
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "sync_aiss.py"

# Modules that aiss-standard maintains itself and that are not synced.
STANDARD_OWNED = {"aiss.memory", "aiss.telemetry"}
# Modules that must never reach aiss-standard.
ELV2_ONLY = {"aiss.license", "aiss.rfc3161", "aiss.trial"}

_CATCH_ALL = {"ImportError", "ModuleNotFoundError", "Exception"}


def _load_script():
    spec = importlib.util.spec_from_file_location("sync_aiss_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _module_name(rel_path):
    parts = rel_path[: -len(".py")].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _handler_catches(handler):
    if handler.type is None:
        return True
    nodes = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    names = {n.id for n in nodes if isinstance(n, ast.Name)}
    return bool(names & _CATCH_ALL)


def _collect_imports(tree, current_module, is_package):
    """Return a list of (module, lineno, guarded) for every import of an aiss module."""
    found = []
    tested = set()
    package = current_module if is_package else current_module.rpartition(".")[0]

    def add(module, lineno, guarded):
        if module == "aiss" or module.startswith("aiss."):
            found.append((module, lineno, guarded or module in tested))

    def submodule_exists(base, name):
        rel = base.replace(".", "/") + "/" + name
        return (ROOT / (rel + ".py")).is_file() or (ROOT / rel / "__init__.py").is_file()

    def visit(node, guarded):
        if isinstance(node, ast.Import):
            for alias in node.names:
                add(alias.name, node.lineno, guarded)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base_parts = package.split(".")
                base_parts = base_parts[: len(base_parts) - (node.level - 1)]
                base = ".".join(base_parts + ([node.module] if node.module else []))
            else:
                base = node.module or ""
            add(base, node.lineno, guarded)
            for alias in node.names:
                if alias.name != "*" and submodule_exists(base, alias.name):
                    add(base + "." + alias.name, node.lineno, guarded)
        if isinstance(node, ast.Try):
            catches = any(_handler_catches(h) for h in node.handlers)
            before = len(found)
            for child in node.body:
                visit(child, guarded or catches)
            # A handler that re-imports a module already tried (and guarded) in the body
            # only runs when that module exists, so it is guarded too.
            added = {m for m, _, g in found[before:] if g}
            tested.update(added)
            for part in (node.handlers, node.orelse, node.finalbody):
                for child in part:
                    visit(child, guarded)
            tested.difference_update(added)
            return
        for child in ast.iter_child_nodes(node):
            visit(child, guarded)

    visit(tree, False)
    return found


class TestSyncAllowlist(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.script = _load_script()
        cls.entries = list(cls.script.AISS_CORE_FILES)
        managed = set(cls.script.AISS_MANAGED_FILES)
        cls.sources = [s for s, d in cls.entries if d not in managed]
        cls.listed_modules = {
            _module_name(s) for s in cls.sources
            if s.startswith("aiss/") and s.endswith(".py")
        } | {"aiss"}

    def test_import_of_the_script_has_no_side_effect(self):
        self.assertTrue(callable(self.script.main))
        self.assertIn("aiss/identity.py", self.sources)

    def test_every_import_is_available_in_the_standard(self):
        problems = []
        for rel in self.sources:
            if not (rel.startswith("aiss/") and rel.endswith(".py")):
                continue
            path = ROOT / rel
            if not path.is_file():
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            module = _module_name(rel)
            for imported, lineno, guarded in _collect_imports(
                    tree, module, rel.endswith("__init__.py")):
                if imported in self.listed_modules or imported in STANDARD_OWNED:
                    continue
                if imported in ELV2_ONLY:
                    if guarded:
                        continue
                    problems.append(
                        f"{rel}:{lineno} imports {imported} (ELv2 only) "
                        "outside a guarding try block")
                    continue
                problems.append(f"{rel}:{lineno} imports {imported}, which is not synced")
        self.assertEqual(problems, [], "\n" + "\n".join(problems))

    def test_four_modules_required_by_the_standard_are_listed(self):
        for rel in ("aiss/tsa_token.py", "aiss/key_store.py",
                    "aiss/signer.py", "aiss/signer_conformance.py"):
            self.assertIn(rel, [s for s, _ in self.entries], rel)

    def test_elv2_only_files_are_never_synced(self):
        sources = [s for s, _ in self.entries]
        destinations = [d for _, d in self.entries]
        for rel in ("aiss/rfc3161.py", "aiss/signer_file.py", "aiss/license.py"):
            self.assertNotIn(rel, sources, rel)
            self.assertNotIn(rel, destinations, rel)

    def test_no_duplicate_destinations(self):
        destinations = [d for _, d in self.entries]
        duplicates = sorted({d for d in destinations if destinations.count(d) > 1})
        self.assertEqual(duplicates, [])


if __name__ == "__main__":
    unittest.main()
