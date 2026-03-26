import re

with open('cli/piqrypt_start.py', encoding='utf-8-sig') as f:
    content = f.read()

old = '    def _check_auth_middleware(self):\n        auth_path = _PACKAGE_ROOT / "auth_middleware.py"\n        if not auth_path.exists():\n            auth_path = _LAUNCHER_DIR / "auth_middleware.py"\n        if not auth_path.exists():\n            auth_path = _LAUNCHER_DIR / "auth_middleware.py"\n        if not auth_path.exists():\n            self.errors.append(\n                f"auth_middleware.py introuvable dans {_PACKAGE_ROOT} ni dans {_LAUNCHER_DIR}. "\n                "Reinstallez piqrypt : pip install piqrypt --upgrade"\n            )'

new = '    def _check_auth_middleware(self):\n        auth_path = _PACKAGE_ROOT / "auth_middleware.py"\n        if not auth_path.exists():\n            auth_path = _LAUNCHER_DIR / "auth_middleware.py"\n        if not auth_path.exists():\n            self.errors.append(\n                f"auth_middleware.py introuvable dans {_PACKAGE_ROOT} ni dans {_LAUNCHER_DIR}. "\n                "Reinstallez piqrypt : pip install piqrypt --upgrade"\n            )'

content = content.replace(old, new)

with open('cli/piqrypt_start.py', 'w', encoding='utf-8') as f:
    f.write(content)

print('done')
