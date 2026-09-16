# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
name: vault_events
short_description: Receive events from HashiCorp Vault via WebSocket
description:
  - Connects to Vault's event notification system via WebSocket.
  - Subscribes to audit events, KV writes, and more.
  - Supports token, token file, and AppRole authentication.
  - Automatically reconnects with exponential backoff.
  - Transforms CloudEvents format to an EDA-friendly structure.
version_added: "2.0.0"
author:
  - Ansible (@ansible)
requirements:
  - websockets
  - aiohttp
options:
  url:
    description:
      - Vault server URL.
      - Must include protocol (C(http://) or C(https://)) and port.
      - If not specified, the value of the E(VAULT_ADDR) environment variable is used.
    required: true
    type: str
    aliases: [vault_url, vault_address]
  token:
    description:
      - Vault authentication token.
      - Takes precedence over O(vault_token_path) and AppRole.
      - If not specified, the value of the E(VAULT_TOKEN) environment variable is used.
    required: false
    type: str
    aliases: [vault_token]
  vault_token_path:
    description:
      - Path to a file containing a Vault token.
      - Used if O(token) is not provided.
    required: false
    type: str
  role_id:
    description:
      - AppRole role ID for authentication.
      - Must be used with O(secret_id).
      - If not specified, the value of the E(VAULT_APPROLE_ROLE_ID) environment variable is used.
    required: false
    type: str
    aliases: [approle_role_id]
  secret_id:
    description:
      - AppRole secret ID for authentication.
      - Must be used with O(role_id).
      - If not specified, the value of the E(VAULT_APPROLE_SECRET_ID) environment variable is used.
    required: false
    type: str
    aliases: [approle_secret_id]
  vault_approle_path:
    description:
      - AppRole auth method mount path.
      - If not specified, the value of the E(VAULT_APPROLE_PATH) environment variable is used.
    required: false
    type: str
    default: approle
  namespace:
    description:
      - Vault Enterprise or HCP namespace.
      - Optional. Do not set this for Community Edition.
      - If not specified, the value of the E(VAULT_NAMESPACE) environment variable is used.
    required: false
    type: str
    aliases: [vault_namespace]
  event_types:
    description:
      - List of event types to subscribe to.
      - Use V(*) for all events, or specific patterns such as V(kv-v2/*) or V(audit/*).
      - Only the first entry is subscribed to in this version.
    required: false
    type: list
    elements: str
    default: ["*"]
  tls_skip_verify:
    description:
      - Accepted for consistency with other collection plugins, but must remain V(false).
      - This event source always verifies TLS certificates and hostnames.
      - For a private CA, set O(ca_cert) instead of disabling verification.
      - If not specified, the value of the E(VAULT_SKIP_VERIFY) environment variable is used.
    required: false
    type: bool
    default: false
  verify_ssl:
    description:
      - Inverse of O(tls_skip_verify). Kept as a compatibility alias from the standalone plugin.
      - Ignored when O(tls_skip_verify) or E(VAULT_SKIP_VERIFY) is set.
      - Must not disable verification. Use O(ca_cert) for a private CA.
    required: false
    type: bool
  ca_cert:
    description:
      - Path to a PEM-encoded CA certificate file to use for TLS verification.
      - If this parameter is not provided, the value of the E(VAULT_CACERT) environment variable is used.
    required: false
    type: str
    aliases: [ca_cert_path, cacert, ssl_ca_cert]
  ping_interval:
    description:
      - WebSocket ping interval in seconds.
    required: false
    type: int
    default: 20
  ping_timeout:
    description:
      - WebSocket ping timeout in seconds.
    required: false
    type: int
    default: 20
  reconnect_enabled:
    description:
      - Enable automatic reconnection on connection loss.
    required: false
    type: bool
    default: true
  reconnect_max_attempts:
    description:
      - Maximum number of reconnection attempts.
      - Use V(-1) for infinite attempts.
    required: false
    type: int
    default: -1
  reconnect_initial_delay:
    description:
      - Initial reconnection delay in seconds.
    required: false
    type: float
    default: 1.0
  reconnect_max_delay:
    description:
      - Maximum reconnection delay in seconds.
    required: false
    type: float
    default: 60.0
  reconnect_backoff_multiplier:
    description:
      - Backoff multiplier for exponential backoff.
    required: false
    type: float
    default: 2.0
notes:
  - Requires HashiCorp Vault 1.16+ Enterprise or HCP Vault Dedicated. The events WebSocket API is not available in Community Edition.
  - Events are delivered in CloudEvents format and transformed for EDA.
  - Supports automatic reconnection with exponential backoff.
  - Authentication method priority is token, then vault_token_path, then AppRole.
  - Only the first entry in O(event_types) is subscribed to.
  - TLS certificate and hostname verification cannot be disabled. Use O(ca_cert) for a private CA.
"""

EXAMPLES = r"""
- name: Subscribe to all Vault events with token authentication
  hashicorp.vault.vault_events:
    url: https://vault.example.com:8200
    token: "{{ VAULT_TOKEN }}"
    event_types:
      - "*"

- name: Subscribe to KV events with AppRole authentication
  hashicorp.vault.vault_events:
    url: https://vault.example.com:8200
    role_id: "{{ VAULT_APPROLE_ROLE_ID }}"
    secret_id: "{{ VAULT_APPROLE_SECRET_ID }}"
    event_types:
      - kv-v2/*

- name: Subscribe to audit events with token from file
  hashicorp.vault.vault_events:
    url: https://vault.example.com:8200
    vault_token_path: /var/run/secrets/vault-token
    event_types:
      - audit/*
    tls_skip_verify: false
    ca_cert: /etc/ssl/certs/ca-bundle.crt

- name: Subscribe with custom reconnection settings
  hashicorp.vault.vault_events:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    reconnect_max_attempts: 10
    reconnect_initial_delay: 2
    reconnect_max_delay: 120
"""

import asyncio
import json
import logging
import os
import secrets
import ssl
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence
from urllib.parse import urlparse

try:
    import aiohttp
    import websockets
except ImportError as imp_exc:
    EDA_IMPORT_ERROR = imp_exc
    aiohttp = None
    websockets = None
else:
    EDA_IMPORT_ERROR = None

logger = logging.getLogger(__name__)

TRUE_STRINGS = ("1", "true", "yes", "on")
FALSE_STRINGS = ("0", "false", "no", "off")


def _is_blank(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str) and value.strip() == "":
        return True
    return False


def _coalesce(values: Sequence[Any]) -> Any:
    for value in values:
        if _is_blank(value):
            continue
        return value
    return None


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in TRUE_STRINGS:
            return True
        if lowered in FALSE_STRINGS:
            return False
        raise ValueError("Invalid boolean value: %s" % value)
    raise ValueError("Invalid boolean value: %s" % value)


def _as_string_list(value: Any) -> List[str]:
    if value is None:
        return ["*"]
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    raise ValueError("event_types must be a string or a list of strings")


def _as_int(value: Any, fallback: int) -> int:
    if _is_blank(value):
        return fallback
    return int(value)


def _as_float(value: Any, fallback: float) -> float:
    if _is_blank(value):
        return fallback
    return float(value)


def normalize_args(args: Mapping[str, Any], environ: Mapping[str, str]) -> Dict[str, Any]:
    """Resolve aliases and VAULT_* environment fallbacks into canonical keys."""
    url = _coalesce(
        [
            args.get("url"),
            args.get("vault_url"),
            args.get("vault_address"),
            environ.get("VAULT_ADDR"),
        ]
    )
    if _is_blank(url):
        raise ValueError("url is required (set url or VAULT_ADDR)")

    tls_skip_raw = _coalesce(
        [
            args.get("tls_skip_verify"),
            environ.get("VAULT_SKIP_VERIFY"),
        ]
    )
    if tls_skip_raw is not None:
        tls_skip_verify = _parse_bool(tls_skip_raw)
    elif not _is_blank(args.get("verify_ssl")):
        tls_skip_verify = not _parse_bool(args.get("verify_ssl"))
    else:
        tls_skip_verify = False

    event_types = _as_string_list(args.get("event_types"))
    if not event_types:
        raise ValueError("event_types must not be empty")

    reconnect_enabled_raw = args.get("reconnect_enabled")
    if _is_blank(reconnect_enabled_raw):
        reconnect_enabled = True
    else:
        reconnect_enabled = _parse_bool(reconnect_enabled_raw)

    return {
        "url": str(url).rstrip("/"),
        "token": _coalesce(
            [
                args.get("token"),
                args.get("vault_token"),
                environ.get("VAULT_TOKEN"),
            ]
        ),
        "vault_token_path": _coalesce([args.get("vault_token_path")]),
        "role_id": _coalesce(
            [
                args.get("role_id"),
                args.get("approle_role_id"),
                environ.get("VAULT_APPROLE_ROLE_ID"),
            ]
        ),
        "secret_id": _coalesce(
            [
                args.get("secret_id"),
                args.get("approle_secret_id"),
                environ.get("VAULT_APPROLE_SECRET_ID"),
            ]
        ),
        "vault_approle_path": _coalesce(
            [
                args.get("vault_approle_path"),
                environ.get("VAULT_APPROLE_PATH"),
                "approle",
            ]
        ),
        "namespace": _coalesce(
            [
                args.get("namespace"),
                args.get("vault_namespace"),
                environ.get("VAULT_NAMESPACE"),
            ]
        ),
        "ca_cert": _coalesce(
            [
                args.get("ca_cert"),
                args.get("ca_cert_path"),
                args.get("cacert"),
                args.get("ssl_ca_cert"),
                environ.get("VAULT_CACERT"),
            ]
        ),
        "tls_skip_verify": tls_skip_verify,
        "event_types": event_types,
        "ping_interval": _as_int(args.get("ping_interval"), 20),
        "ping_timeout": _as_int(args.get("ping_timeout"), 20),
        "reconnect_enabled": reconnect_enabled,
        "reconnect_max_attempts": _as_int(args.get("reconnect_max_attempts"), -1),
        "reconnect_initial_delay": _as_float(args.get("reconnect_initial_delay"), 1.0),
        "reconnect_max_delay": _as_float(args.get("reconnect_max_delay"), 60.0),
        "reconnect_backoff_multiplier": _as_float(args.get("reconnect_backoff_multiplier"), 2.0),
    }


def process_vault_event(raw_event: str) -> Optional[Dict[str, Any]]:
    """Transform a Vault CloudEvent JSON string into an EDA event dict."""
    try:
        cloud_event = json.loads(raw_event)
    except json.JSONDecodeError:
        logger.error("Failed to parse event JSON")
        return None

    data = cloud_event.get("data", {})
    if not data:
        logger.warning("Event missing data section")
        return None

    event_inner = data.get("event", {})
    if not isinstance(event_inner, dict):
        event_inner = {}
    metadata = event_inner.get("metadata", data.get("metadata", {}))
    if not isinstance(metadata, dict):
        metadata = {}

    plugin_info = data.get("plugin_info", {})
    if not isinstance(plugin_info, dict):
        plugin_info = {}

    return {
        "vault": {
            "event_type": data.get("event_type", "unknown"),
            "metadata": metadata,
            "plugin_info": plugin_info,
        },
        "cloudevents": {
            "id": cloud_event.get("id", ""),
            "source": cloud_event.get("source", ""),
            "time": cloud_event.get("time", ""),
        },
    }


def _verified_ssl_context(ca_cert: Optional[str]) -> ssl.SSLContext:
    if ca_cert:
        context = ssl.create_default_context(cafile=ca_cert)
    else:
        context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _require_tls_verification(tls_skip_verify: bool) -> None:
    if tls_skip_verify:
        raise ValueError(
            "tls_skip_verify is not supported for hashicorp.vault.vault_events. "
            "Provide ca_cert with a PEM CA bundle that signs the Vault server certificate."
        )


def aiohttp_ssl_argument(tls_skip_verify: bool, ca_cert: Optional[str]) -> Any:
    """Return the ssl argument accepted by aiohttp."""
    _require_tls_verification(tls_skip_verify)
    if ca_cert:
        return _verified_ssl_context(ca_cert)
    return None


def websocket_ssl_argument(use_tls: bool, tls_skip_verify: bool, ca_cert: Optional[str]) -> Any:
    """Return the ssl argument accepted by websockets on connect."""
    _require_tls_verification(tls_skip_verify)
    if not use_tls:
        return None
    if ca_cert:
        return _verified_ssl_context(ca_cert)
    return True


class VaultAuthenticator:
    """Handles authentication with HashiCorp Vault using multiple methods."""

    def __init__(self, args: Mapping[str, Any]):
        self.args = args
        self.vault_url = args["url"]
        self.namespace = args.get("namespace")
        self.tls_skip_verify = args["tls_skip_verify"]
        self.ca_cert = args.get("ca_cert")

    async def authenticate(self) -> str:
        if not _is_blank(self.args.get("token")):
            logger.info("Using token authentication")
            return self.args["token"]

        token_path = self.args.get("vault_token_path")
        if not _is_blank(token_path):
            logger.info("Reading token from file")
            return await self._read_token_from_file(token_path)

        if not _is_blank(self.args.get("role_id")) and not _is_blank(self.args.get("secret_id")):
            logger.info("Using AppRole authentication")
            return await self._approle_login()

        raise ValueError(
            "No valid authentication method provided. Must provide one of: token, vault_token_path, or AppRole credentials"
        )

    async def _read_token_from_file(self, token_path: str) -> str:
        path = Path(token_path)
        if not path.exists():
            raise FileNotFoundError("Token file not found: %s" % token_path)

        token = path.read_text().strip()
        if not token:
            raise ValueError("Token file is empty: %s" % token_path)
        return token

    async def _approle_login(self) -> str:
        if EDA_IMPORT_ERROR:
            raise ImportError(
                "Missing required dependency: %s. Install with: pip install websockets aiohttp" % EDA_IMPORT_ERROR
            )

        mount = str(self.args["vault_approle_path"]).strip("/")
        login_url = "%s/v1/auth/%s/login" % (self.vault_url, mount)
        payload = {
            "role_id": self.args["role_id"],
            "secret_id": self.args["secret_id"],
        }

        headers = {}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace

        ssl_arg = aiohttp_ssl_argument(self.tls_skip_verify, self.ca_cert)

        async with aiohttp.ClientSession() as session:
            async with session.post(login_url, json=payload, headers=headers, ssl=ssl_arg) as response:
                error_text = await response.text()
                if response.status != 200:
                    raise RuntimeError("AppRole login failed with status %s: %s" % (response.status, error_text))

                data = await response.json()
                token = data.get("auth", {}).get("client_token")
                if not token:
                    raise ValueError("No token returned from AppRole login")

                logger.info("AppRole authentication successful")
                return token


class VaultWebSocketClient:
    """Manages WebSocket connection to Vault events API."""

    def __init__(self, token: str, args: Mapping[str, Any]):
        self.vault_url = args["url"]
        self.token = token
        self.namespace = args.get("namespace")
        self.tls_skip_verify = args["tls_skip_verify"]
        self.ca_cert = args.get("ca_cert")
        self.ping_interval = args["ping_interval"]
        self.ping_timeout = args["ping_timeout"]

    async def connect(self, event_type: str):
        if EDA_IMPORT_ERROR:
            raise ImportError(
                "Missing required dependency: %s. Install with: pip install websockets aiohttp" % EDA_IMPORT_ERROR
            )

        ws_url = self._build_ws_url(event_type)
        headers = self._build_headers()
        parsed = urlparse(self.vault_url)
        ssl_arg = websocket_ssl_argument(parsed.scheme == "https", self.tls_skip_verify, self.ca_cert)

        logger.info("Connecting to Vault WebSocket: %s", ws_url)
        websocket = await websockets.connect(
            ws_url,
            additional_headers=headers,
            ssl=ssl_arg,
            ping_interval=self.ping_interval,
            ping_timeout=self.ping_timeout,
        )
        logger.info("Connected to Vault events for type: %s", event_type)
        return websocket

    def _build_ws_url(self, event_type: str) -> str:
        parsed = urlparse(self.vault_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        return "%s://%s/v1/sys/events/subscribe/%s?json=true" % (ws_scheme, parsed.netloc, event_type)

    def _build_headers(self) -> Dict[str, str]:
        headers = {"X-Vault-Token": self.token}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        return headers


class ReconnectionManager:
    """Manages reconnection logic with exponential backoff."""

    def __init__(self, args: Mapping[str, Any]):
        self.enabled = args["reconnect_enabled"]
        self.max_attempts = args["reconnect_max_attempts"]
        self.initial_delay = args["reconnect_initial_delay"]
        self.max_delay = args["reconnect_max_delay"]
        self.backoff_multiplier = args["reconnect_backoff_multiplier"]
        self.current_attempt = 0

    def should_reconnect(self) -> bool:
        if not self.enabled:
            logger.info("Reconnection disabled")
            return False

        if self.max_attempts == -1:
            return True

        if self.current_attempt >= self.max_attempts:
            logger.error("Max reconnection attempts (%s) reached", self.max_attempts)
            return False

        return True

    async def wait_before_reconnect(self):
        delay = min(
            self.initial_delay * (self.backoff_multiplier**self.current_attempt),
            self.max_delay,
        )
        # Non-crypto jitter for reconnect backoff so retries do not thundering-herd.
        jitter = delay * 0.25 * ((secrets.randbelow(500) / 250.0) - 1.0)
        total_delay = delay + jitter

        logger.info(
            "Waiting %.2fs before reconnection attempt %s",
            total_delay,
            self.current_attempt + 1,
        )
        await asyncio.sleep(total_delay)
        self.current_attempt += 1

    def reset(self):
        if self.current_attempt > 0:
            logger.info("Connection successful, resetting reconnection counter")
        self.current_attempt = 0


async def main(queue: asyncio.Queue, args: Dict[str, Any]):
    """Entry point called by ansible-rulebook."""
    if EDA_IMPORT_ERROR:
        raise ImportError(
            "Missing required dependency: %s. Install with: pip install websockets aiohttp" % EDA_IMPORT_ERROR
        )

    normalized = normalize_args(args, os.environ)
    _require_tls_verification(normalized["tls_skip_verify"])
    event_types = normalized["event_types"]
    event_type = event_types[0]

    logger.info("Starting Vault events plugin for %s", normalized["url"])
    logger.info("Subscribing to event type: %s", event_type)
    if len(event_types) > 1:
        logger.warning("Only the first event_types entry is subscribed to; ignoring %s", event_types[1:])

    authenticator = VaultAuthenticator(normalized)
    reconnection_mgr = ReconnectionManager(normalized)
    websocket = None

    while True:
        try:
            logger.info("Authenticating with Vault")
            token = await authenticator.authenticate()
            ws_client = VaultWebSocketClient(token, normalized)
            websocket = await ws_client.connect(event_type)
            reconnection_mgr.reset()

            logger.info("Listening for Vault events")
            async for message in websocket:
                try:
                    event = process_vault_event(message)
                    if event:
                        await queue.put(event)
                        await asyncio.sleep(0)
                except Exception as exc:
                    logger.error("Error processing event: %s", exc)
                    continue

        except asyncio.CancelledError:
            logger.info("Shutdown requested, closing connection")
            if websocket:
                await websocket.close()
            raise

        except Exception as exc:
            logger.error("Connection error: %s", exc)
            if websocket:
                try:
                    await websocket.close()
                except Exception:
                    pass

            if not reconnection_mgr.should_reconnect():
                logger.error("Reconnection disabled or max attempts reached, exiting")
                raise

            await reconnection_mgr.wait_before_reconnect()
            logger.info("Attempting to reconnect")
