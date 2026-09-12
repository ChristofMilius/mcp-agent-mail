"""tests/test_config.py — fail-fast config, path resolution, masking."""
from __future__ import annotations

import os

import pytest

from mcp_agent_mail.config import Config, ConfigError


class TestConfigFailFast:
    def test_constructed_with_all_secrets(self):
        cfg = Config(require_secrets=True)
        assert cfg.email_address == "agent@example.com"
        assert cfg.gpg_key_id == "AAAA" * 10

    def test_missing_email_password_aborts(self, monkeypatch):
        monkeypatch.delenv("EMAIL_PASSWORD")
        with pytest.raises(ConfigError, match="EMAIL_PASSWORD"):
            Config(require_secrets=True)

    def test_missing_gpg_passphrase_aborts(self, monkeypatch):
        monkeypatch.delenv("GPG_PASSPHRASE")
        with pytest.raises(ConfigError, match="GPG_PASSPHRASE"):
            Config(require_secrets=True)

    def test_missing_gpg_key_id_aborts(self, monkeypatch):
        monkeypatch.delenv("GPG_KEY_ID")
        with pytest.raises(ConfigError, match="GPG_KEY_ID"):
            Config(require_secrets=True)

    def test_missing_email_address_aborts(self, monkeypatch):
        monkeypatch.delenv("EMAIL_ADDRESS")
        with pytest.raises(ConfigError, match="EMAIL_ADDRESS"):
            Config(require_secrets=True)

    def test_tolerant_mode_reports_missing(self, monkeypatch):
        monkeypatch.delenv("EMAIL_PASSWORD")
        cfg = Config(require_secrets=False)
        assert any("EMAIL_PASSWORD" in s and "MISSING" in s for s in cfg.secret_status())


class TestConfigMasking:
    def test_repr_does_not_include_passwords(self):
        cfg = Config(require_secrets=True)
        for secret_value in ("fake-app-password", "fake-passphrase"):
            assert secret_value not in repr(cfg)
            assert secret_value not in str(cfg)

    def test_repr_shows_marker(self):
        cfg = Config(require_secrets=True)
        assert "***" in repr(cfg)


class TestConfigPathResolution:
    def test_relative_contacts_path_resolves_against_project_root(self, monkeypatch):
        monkeypatch.delenv("EMAIL_PASSWORD")  # keep provider gate off via tolerant mode
        monkeypatch.delenv("CONTACTS_PATH", raising=False)
        cfg = Config(require_secrets=False)
        # Would fail if resolved against CWD; must resolve against package root.
        assert os.path.isabs(cfg.contacts_path)
        assert cfg.contacts_path.replace("\\", "/").endswith("data/contacts.json")

    def test_absolute_env_paths_are_kept(self, tmp_project, monkeypatch):
        root, env = tmp_project
        monkeypatch.setenv("CONTACTS_PATH", env["CONTACTS_PATH"])
        cfg = Config(require_secrets=True)
        assert cfg.contacts_path == str(root / "data" / "contacts.json")


class TestConfigToggles:
    def test_smtp_use_ssl_parses(self, monkeypatch):
        assert Config(require_secrets=True).smtp_use_ssl is False
        monkeypatch.setenv("SMTP_USE_SSL", "true")
        assert Config(require_secrets=True).smtp_use_ssl is True

    def test_secret_status_lists_all_required(self):
        cfg = Config(require_secrets=True)
        names = [s.split(":")[0] for s in cfg.secret_status()]
        assert set(names) == {
            "EMAIL_ADDRESS", "EMAIL_PASSWORD", "GPG_KEY_ID", "GPG_PASSPHRASE",
        }
        assert all(s.endswith("set") for s in cfg.secret_status())


class _FakeProvider:
    name = "fake"

    def get(self, name):
        return None


class TestSecretProviderInjection:
    def test_custom_provider_controls_secrets(self, monkeypatch):
        from mcp_agent_mail.secrets import SecretString
        monkeypatch.delenv("EMAIL_PASSWORD")
        cfg = Config(require_secrets=False, secret_provider=_FakeProvider())
        assert cfg.email_password == SecretString("")
        assert any("MISSING" in s for s in cfg.secret_status())

    def test_invalid_backend_promoted_to_config_error(self, monkeypatch):
        monkeypatch.setenv("SECRET_BACKEND", "bogus_backend")
        with pytest.raises(ConfigError, match="unknown secret backend"):
            Config(require_secrets=True)
