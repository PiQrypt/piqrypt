"""Guard: test runs must never send telemetry to the production server."""
import os
import subprocess
import sys
from pathlib import Path

_PROD_HOST = "trust-server-ucjb.onrender.com"
_REPO_ROOT = Path(__file__).resolve().parent.parent


def test_endpoint_is_not_production_in_process():
    import aiss.telemetry as tel

    assert _PROD_HOST not in tel.TELEMETRY_ENDPOINT


def test_endpoint_is_not_production_in_subprocess(tmp_path):
    env = dict(os.environ)
    env["HOME"] = str(tmp_path)
    env["USERPROFILE"] = str(tmp_path)
    env["PYTHONPATH"] = str(_REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import aiss.telemetry as t; print(t.TELEMETRY_ENDPOINT)",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert _PROD_HOST not in result.stdout
