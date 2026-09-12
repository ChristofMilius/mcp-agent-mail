"""tests/test_secret_provider.py — secret provider and registry."""
from __future__ import annotations

import pytest

from mcp_agent_mail.secret_provider.env_provider import EnvSecretProvider
from mcp_agent_mail.secret_provider.registry import (
    get_provider,
    known_backends,
)
from mcp_agent_mail.secrets import SecretString


class TestEnvSecretProvider:
    def test_returns_secret_for_existing_env_var(self, monkeypatch):
        monkeypatch.setenv("MY_SECRET", "hello")
        p = EnvSecretProvider()
        val = p.get("MY_SECRET")
        assert isinstance(val, SecretString)
        assert val == SecretString("hello")
        assert val.expose_secret() == "hello"

    def test_returns_none_for_missing_env_var(self):
        p = EnvSecretProvider()
        assert p.get("NONEXISTENT_KEY_12345") is None

    def test_returns_none_for_empty_string(self, monkeypatch):
        monkeypatch.setenv("EMPTY_SECRET", "")
        p = EnvSecretProvider()
        assert p.get("EMPTY_SECRET") is None

    def test_repr_does_not_leak_value(self, monkeypatch):
        monkeypatch.setenv("REPR_SECRET", "s3cret-val")
        p = EnvSecretProvider()
        p.get("REPR_SECRET")
        assert "s3cret-val" not in repr(p)
        assert "s3cret-val" not in str(p)


class TestRegistry:
    def test_known_backends_returns_env(self):
        assert "env" in known_backends()

    def test_get_provider_default_returns_env(self):
        p = get_provider(None)
        assert isinstance(p, EnvSecretProvider)

    def test_get_provider_explicit_env(self):
        p = get_provider("env")
        assert isinstance(p, EnvSecretProvider)

    def test_unknown_backend_raises_value_error(self):
        with pytest.raises(ValueError, match="unknown secret backend"):
            get_provider("nonexistent_backend_xyz")

    def test_roadmap_backend_raises_value_error(self):
        with pytest.raises(ValueError, match="not yet implemented"):
            get_provider("keepassxc")

    def test_empty_string_defaults_to_env(self):
        p = get_provider("")
        assert isinstance(p, EnvSecretProvider)


class TestMissingSecretError:
    def test_is_exception(self):
        from mcp_agent_mail.secret_provider.base import MissingSecretError
        assert issubclass(MissingSecretError, Exception)
        with pytest.raises(MissingSecretError, match="missing"):
            raise MissingSecretError("missing")
