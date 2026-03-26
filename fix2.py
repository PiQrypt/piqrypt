with open('cli/piqrypt_start.py', encoding='utf-8') as f:
    content = f.read()

method = '''    def _check_auth_middleware(self):
        auth_path = _PACKAGE_ROOT / "auth_middleware.py"
        if not auth_path.exists():
            auth_path = _LAUNCHER_DIR / "auth_middleware.py"
        if not auth_path.exists():
            self.errors.append(
                f"auth_middleware.py introuvable dans {_PACKAGE_ROOT} ni dans {_LAUNCHER_DIR}. "
                "Reinstallez piqrypt : pip install piqrypt --upgrade"
            )

'''

content = content.replace(
    '    def _check_python_version(self):',
    method + '    def _check_python_version(self):'
)

with open('cli/piqrypt_start.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('done')
