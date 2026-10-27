"""PIQRYPT_TELEMETRY accepts the usual 'off' spellings."""
import importlib
from unittest.mock import patch

import pytest


@pytest.fixture
def tel(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("PIQRYPT_TELEMETRY", raising=False)
    import aiss.telemetry as tel_mod

    importlib.reload(tel_mod)
    yield tel_mod
    importlib.reload(tel_mod)


@pytest.mark.parametrize("value", ["0", "false", "False", "FALSE", "no", "off", " off "])
def test_off_values_disable(tel, monkeypatch, value):
    monkeypatch.setenv("PIQRYPT_TELEMETRY", value)
    importlib.reload(tel)
    assert not tel.is_telemetry_enabled()


@pytest.mark.parametrize("value", ["1", "true", "yes", "", "maybe"])
def test_other_values_keep_the_default(tel, monkeypatch, value):
    monkeypatch.setenv("PIQRYPT_TELEMETRY", value)
    importlib.reload(tel)
    assert tel.is_telemetry_enabled()


def test_send_is_skipped_when_the_environment_says_off(tel, monkeypatch):
    monkeypatch.setenv("PIQRYPT_TELEMETRY", "false")
    with patch("urllib.request.urlopen") as urlopen:
        tel._telemetry._send_to_server("install")
    urlopen.assert_not_called()
