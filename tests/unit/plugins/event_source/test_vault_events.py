# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import asyncio
import importlib.util
import json
import ssl
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

PLUGIN_PATH = (
    Path(__file__).resolve().parents[4] / "extensions" / "eda" / "plugins" / "event_source" / "vault_events.py"
)


def load_vault_events():
    spec = importlib.util.spec_from_file_location("vault_events", PLUGIN_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vault_events = load_vault_events()


VAULT_1X_EVENT = {
    "id": "event-uuid",
    "source": "vault://cluster",
    "specversion": "1.0",
    "type": "*",
    "data": {
        "event_type": "kv-v2/data-write",
        "metadata": {"path": "secret/data/foo", "operation": "write"},
        "plugin_info": {"mount_path": "secret/", "plugin": "kv"},
    },
    "time": "2025-06-12T15:19:49Z",
}

VAULT_2X_EVENT = {
    "id": "event-uuid-2",
    "source": "vault://cluster",
    "data": {
        "event_type": "kv-v2/data-delete",
        "event": {"metadata": {"path": "secret/data/bar", "operation": "delete"}},
        "plugin_info": {"mount_path": "secret/", "plugin": "kv"},
    },
    "time": "2026-01-15T10:00:00Z",
}


class TestProcessVaultEvent:
    def test_vault_1x_metadata_shape(self):
        result = vault_events.process_vault_event(json.dumps(VAULT_1X_EVENT))

        assert result["vault"]["event_type"] == "kv-v2/data-write"
        assert result["vault"]["metadata"]["path"] == "secret/data/foo"
        assert result["vault"]["metadata"]["operation"] == "write"
        assert result["vault"]["plugin_info"]["plugin"] == "kv"
        assert result["cloudevents"]["id"] == "event-uuid"
        assert result["cloudevents"]["source"] == "vault://cluster"
        assert result["cloudevents"]["time"] == "2025-06-12T15:19:49Z"

    def test_vault_2x_nested_metadata_shape(self):
        result = vault_events.process_vault_event(json.dumps(VAULT_2X_EVENT))

        assert result["vault"]["event_type"] == "kv-v2/data-delete"
        assert result["vault"]["metadata"]["path"] == "secret/data/bar"
        assert result["vault"]["metadata"]["operation"] == "delete"
        assert result["cloudevents"]["id"] == "event-uuid-2"

    def test_invalid_json_returns_none(self):
        assert vault_events.process_vault_event("not-json") is None

    def test_missing_data_returns_none(self):
        payload = json.dumps({"id": "event-uuid", "source": "vault://cluster"})
        assert vault_events.process_vault_event(payload) is None


class TestNormalizeArgs:
    def test_canonical_names(self):
        result = vault_events.normalize_args(
            {
                "url": "https://vault.example.com:8200",
                "token": "s.token",
                "role_id": "role",
                "secret_id": "secret",
                "namespace": "admin/dev",
                "ca_cert": "/etc/ssl/certs/ca.pem",
                "tls_skip_verify": False,
            },
            {},
        )

        assert result["url"] == "https://vault.example.com:8200"
        assert result["token"] == "s.token"
        assert result["role_id"] == "role"
        assert result["secret_id"] == "secret"
        assert result["namespace"] == "admin/dev"
        assert result["ca_cert"] == "/etc/ssl/certs/ca.pem"
        assert result["tls_skip_verify"] is False
        assert result["vault_approle_path"] == "approle"
        assert result["event_types"] == ["*"]

    def test_plugin_aliases(self):
        result = vault_events.normalize_args(
            {
                "vault_url": "https://vault.example.com:8200/",
                "vault_token": "s.token",
                "approle_role_id": "role",
                "approle_secret_id": "secret",
                "vault_namespace": "ns1",
                "ca_cert_path": "/tmp/ca.pem",
            },
            {},
        )

        assert result["url"] == "https://vault.example.com:8200"
        assert result["token"] == "s.token"
        assert result["role_id"] == "role"
        assert result["secret_id"] == "secret"
        assert result["namespace"] == "ns1"
        assert result["ca_cert"] == "/tmp/ca.pem"

    def test_env_fallbacks(self):
        result = vault_events.normalize_args(
            {},
            {
                "VAULT_ADDR": "https://from-env.example.com:8200",
                "VAULT_TOKEN": "env-token",
                "VAULT_APPROLE_ROLE_ID": "env-role",
                "VAULT_APPROLE_SECRET_ID": "env-secret",
                "VAULT_APPROLE_PATH": "custom-approle",
                "VAULT_NAMESPACE": "env-ns",
                "VAULT_CACERT": "/env/ca.pem",
                "VAULT_SKIP_VERIFY": "true",
            },
        )

        assert result["url"] == "https://from-env.example.com:8200"
        assert result["token"] == "env-token"
        assert result["role_id"] == "env-role"
        assert result["secret_id"] == "env-secret"
        assert result["vault_approle_path"] == "custom-approle"
        assert result["namespace"] == "env-ns"
        assert result["ca_cert"] == "/env/ca.pem"
        assert result["tls_skip_verify"] is True

    def test_canonical_beats_alias_beats_env(self):
        result = vault_events.normalize_args(
            {
                "url": "https://canonical.example.com:8200",
                "vault_url": "https://alias.example.com:8200",
                "token": "canonical-token",
                "vault_token": "alias-token",
            },
            {
                "VAULT_ADDR": "https://env.example.com:8200",
                "VAULT_TOKEN": "env-token",
            },
        )

        assert result["url"] == "https://canonical.example.com:8200"
        assert result["token"] == "canonical-token"

    def test_verify_ssl_is_inverted_alias(self):
        result = vault_events.normalize_args(
            {
                "url": "https://vault.example.com:8200",
                "verify_ssl": False,
            },
            {},
        )

        assert result["tls_skip_verify"] is True

    def test_tls_skip_verify_wins_over_verify_ssl(self):
        result = vault_events.normalize_args(
            {
                "url": "https://vault.example.com:8200",
                "tls_skip_verify": False,
                "verify_ssl": False,
            },
            {},
        )

        assert result["tls_skip_verify"] is False

    def test_namespace_is_not_defaulted(self):
        result = vault_events.normalize_args({"url": "https://vault.example.com:8200"}, {})

        assert result["namespace"] is None

    def test_missing_url_raises(self):
        with pytest.raises(ValueError, match="url is required"):
            vault_events.normalize_args({}, {})

    def test_event_types_string_is_wrapped(self):
        result = vault_events.normalize_args(
            {
                "url": "https://vault.example.com:8200",
                "event_types": "kv-v2/*",
            },
            {},
        )

        assert result["event_types"] == ["kv-v2/*"]

    def test_url_without_scheme_gets_https(self):
        result = vault_events.normalize_args({"url": "vault.example.com:8200"}, {})

        assert result["url"] == "https://vault.example.com:8200"

    def test_http_scheme_is_preserved(self):
        result = vault_events.normalize_args({"url": "http://vault.example.com:8200/"}, {})

        assert result["url"] == "http://vault.example.com:8200"

    def test_slash_only_url_raises(self):
        with pytest.raises(ValueError, match="Invalid vault URL"):
            vault_events.normalize_args({"url": "/"}, {})

    def test_empty_host_url_raises(self):
        with pytest.raises(ValueError, match="Invalid vault URL"):
            vault_events.normalize_args({"url": "///"}, {})

    def test_ping_interval_must_be_positive(self):
        with pytest.raises(ValueError, match="ping_interval must be greater than 0"):
            vault_events.normalize_args(
                {"url": "https://vault.example.com:8200", "ping_interval": 0},
                {},
            )

    def test_ping_timeout_must_be_positive(self):
        with pytest.raises(ValueError, match="ping_timeout must be greater than 0"):
            vault_events.normalize_args(
                {"url": "https://vault.example.com:8200", "ping_timeout": -1},
                {},
            )

    def test_backoff_multiplier_must_be_positive(self):
        with pytest.raises(ValueError, match="reconnect_backoff_multiplier must be greater than 0"):
            vault_events.normalize_args(
                {"url": "https://vault.example.com:8200", "reconnect_backoff_multiplier": 0},
                {},
            )

    def test_max_delay_must_be_at_least_initial(self):
        with pytest.raises(ValueError, match="reconnect_max_delay must be greater than or equal"):
            vault_events.normalize_args(
                {
                    "url": "https://vault.example.com:8200",
                    "reconnect_initial_delay": 10,
                    "reconnect_max_delay": 5,
                },
                {},
            )


class TestReadTokenFromFile:
    def test_token_file_is_read_as_utf8(self, tmp_path):
        token_file = tmp_path / "token"
        token_file.write_text("s.token\n", encoding="utf-8")
        auth = vault_events.VaultAuthenticator(
            vault_events.normalize_args(
                {
                    "url": "https://vault.example.com:8200",
                    "vault_token_path": str(token_file),
                },
                {},
            )
        )

        token = asyncio.run(auth._read_token_from_file(str(token_file)))

        assert token == "s.token"


class TestApproleLogin:
    def _authenticator(self):
        return vault_events.VaultAuthenticator(
            vault_events.normalize_args(
                {
                    "url": "https://vault.example.com:8200",
                    "role_id": "role",
                    "secret_id": "secret",
                },
                {},
            )
        )

    def _mock_session(self, response):
        session = MagicMock()
        session.post.return_value.__aenter__ = AsyncMock(return_value=response)
        session.post.return_value.__aexit__ = AsyncMock(return_value=False)
        client_session = MagicMock()
        client_session.__aenter__ = AsyncMock(return_value=session)
        client_session.__aexit__ = AsyncMock(return_value=False)
        return client_session

    def test_success_reads_json_not_text(self):
        if vault_events.aiohttp is None:
            pytest.skip("aiohttp is not installed")

        response = MagicMock()
        response.status = 200
        response.json = AsyncMock(return_value={"auth": {"client_token": "s.approle"}})
        response.text = AsyncMock(return_value="should-not-be-read")

        with patch.object(vault_events.aiohttp, "ClientSession", return_value=self._mock_session(response)):
            token = asyncio.run(self._authenticator()._approle_login())

        assert token == "s.approle"
        response.json.assert_awaited_once()
        response.text.assert_not_awaited()

    def test_error_reads_text_not_json(self):
        if vault_events.aiohttp is None:
            pytest.skip("aiohttp is not installed")

        response = MagicMock()
        response.status = 400
        response.json = AsyncMock(return_value={"errors": ["denied"]})
        response.text = AsyncMock(return_value="permission denied")

        with patch.object(vault_events.aiohttp, "ClientSession", return_value=self._mock_session(response)):
            with pytest.raises(RuntimeError, match="AppRole login failed with status 400"):
                asyncio.run(self._authenticator()._approle_login())

        response.text.assert_awaited_once()
        response.json.assert_not_awaited()


class TestWebsocketSslArgument:
    def test_skip_verify_is_rejected(self):
        with pytest.raises(ValueError, match="tls_skip_verify is not supported"):
            vault_events.websocket_ssl_argument(True, True, None)

    def test_aiohttp_skip_verify_is_rejected(self):
        with pytest.raises(ValueError, match="tls_skip_verify is not supported"):
            vault_events.aiohttp_ssl_argument(True, None)

    def test_plain_http_returns_none(self):
        ssl_arg = vault_events.websocket_ssl_argument(False, False, None)

        assert ssl_arg is None

    def test_verified_https_without_ca_returns_true(self):
        ssl_arg = vault_events.websocket_ssl_argument(True, False, None)

        assert ssl_arg is True

    def test_verified_context_requires_tls12(self):
        context = vault_events._verified_ssl_context(None)

        assert context.minimum_version == ssl.TLSVersion.TLSv1_2
        assert context.verify_mode != ssl.CERT_NONE
        assert context.check_hostname is True
