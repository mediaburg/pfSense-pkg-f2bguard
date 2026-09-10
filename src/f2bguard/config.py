"""Configuration parsing and validation for the f2bguard receiver."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_PATH = "/usr/local/etc/f2bguard/config.json"
DEFAULT_DATABASE = "/var/db/f2bguard/state.sqlite"
DEFAULT_WHITELIST = "/usr/local/etc/f2bguard/whitelist.txt"
DEFAULT_SOCKET = "/var/run/f2bguard/pf.sock"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_FINGERPRINT_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class ConfigError(ValueError):
    """Raised when configuration is unsafe or malformed."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json_loads(data: str | bytes) -> Any:
    """Decode JSON while rejecting duplicate object keys and non-finite numbers."""

    def reject_constant(value: str) -> None:
        raise ConfigError(f"invalid JSON number: {value}")

    try:
        return json.loads(
            data,
            object_pairs_hook=_unique_object,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"invalid JSON: {exc}") from exc


def _expect_dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be an object")
    return value


def _reject_unknown(value: dict[str, Any], allowed: set[str], name: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ConfigError(f"unknown {name} field(s): {', '.join(unknown)}")


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _path(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ConfigError(f"{name} must be a non-empty path")
    if not os.path.isabs(value):
        raise ConfigError(f"{name} must be an absolute path")
    return value


@dataclass(frozen=True)
class TLSConfig:
    cert: str = ""
    key: str = ""
    ca: str = ""


@dataclass(frozen=True)
class ClientConfig:
    id: str
    cert_sha256: tuple[str, ...]
    allowed_jails: frozenset[str]


@dataclass(frozen=True)
class Limits:
    body_bytes: int = 1_048_576
    events_per_request: int = 1_000
    claims_per_client: int = 10_000
    requests_per_minute: int = 120


@dataclass(frozen=True)
class Config:
    enabled: bool = False
    listen: str = "127.0.0.1"
    port: int = 9443
    tls: TLSConfig = field(default_factory=TLSConfig)
    clients: tuple[ClientConfig, ...] = ()
    database: str = DEFAULT_DATABASE
    whitelist_file: str = DEFAULT_WHITELIST
    enforcement_socket: str = DEFAULT_SOCKET
    limits: Limits = field(default_factory=Limits)
    history_days: int = 90

    @property
    def clients_by_fingerprint(self) -> dict[str, ClientConfig]:
        return {
            fingerprint: client
            for client in self.clients
            for fingerprint in client.cert_sha256
        }


def parse_config(raw: Any) -> Config:
    obj = _expect_dict(raw, "config")
    _reject_unknown(
        obj,
        {
            "enabled",
            "listen",
            "port",
            "tls",
            "clients",
            "database",
            "whitelist_file",
            "enforcement_socket",
            "limits",
            "history_days",
        },
        "config",
    )

    enabled = obj.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigError("enabled must be a boolean")

    listen = obj.get("listen", "127.0.0.1")
    if not isinstance(listen, str):
        raise ConfigError("listen must be an IP literal")
    try:
        listen_ip = ipaddress.ip_address(listen)
    except ValueError as exc:
        raise ConfigError("listen must be an IP literal") from exc
    if listen_ip.is_unspecified:
        raise ConfigError("listen must not be a wildcard address")
    listen = listen_ip.compressed

    port = _integer(obj.get("port", 9443), "port", 1, 65535)

    tls_raw = _expect_dict(obj.get("tls", {}), "tls")
    _reject_unknown(tls_raw, {"cert", "key", "ca"}, "tls")
    tls = TLSConfig(
        cert=_path(tls_raw["cert"], "tls.cert") if "cert" in tls_raw else "",
        key=_path(tls_raw["key"], "tls.key") if "key" in tls_raw else "",
        ca=_path(tls_raw["ca"], "tls.ca") if "ca" in tls_raw else "",
    )
    if enabled and not all((tls.cert, tls.key, tls.ca)):
        raise ConfigError("enabled service requires tls.cert, tls.key, and tls.ca")

    clients_raw = obj.get("clients", [])
    if not isinstance(clients_raw, list):
        raise ConfigError("clients must be an array")
    clients: list[ClientConfig] = []
    client_ids: set[str] = set()
    fingerprints: set[str] = set()
    for index, item in enumerate(clients_raw):
        client = _expect_dict(item, f"clients[{index}]")
        _reject_unknown(client, {"id", "cert_sha256", "allowed_jails"}, f"clients[{index}]")
        client_id = client.get("id")
        if not isinstance(client_id, str) or not _ID_RE.fullmatch(client_id):
            raise ConfigError(f"clients[{index}].id is invalid")
        if client_id in client_ids:
            raise ConfigError(f"duplicate client id: {client_id}")
        client_ids.add(client_id)

        fp_raw = client.get("cert_sha256")
        if not isinstance(fp_raw, list) or not fp_raw:
            raise ConfigError(f"clients[{index}].cert_sha256 must be a non-empty array")
        client_fps: list[str] = []
        for fingerprint in fp_raw:
            if not isinstance(fingerprint, str) or not _FINGERPRINT_RE.fullmatch(fingerprint):
                raise ConfigError(f"clients[{index}] contains an invalid certificate fingerprint")
            normalized = fingerprint.lower()
            if normalized in fingerprints:
                raise ConfigError(f"certificate fingerprint is assigned more than once: {normalized}")
            fingerprints.add(normalized)
            client_fps.append(normalized)

        jails_raw = client.get("allowed_jails")
        if not isinstance(jails_raw, list) or not jails_raw:
            raise ConfigError(f"clients[{index}].allowed_jails must be a non-empty array")
        jails: set[str] = set()
        for jail in jails_raw:
            if not isinstance(jail, str) or not _ID_RE.fullmatch(jail):
                raise ConfigError(f"clients[{index}] contains an invalid jail")
            if jail in jails:
                raise ConfigError(f"clients[{index}] contains duplicate jail {jail}")
            jails.add(jail)
        clients.append(ClientConfig(client_id, tuple(client_fps), frozenset(jails)))

    limits_raw = _expect_dict(obj.get("limits", {}), "limits")
    _reject_unknown(
        limits_raw,
        {"body_bytes", "events_per_request", "claims_per_client", "requests_per_minute"},
        "limits",
    )
    limits = Limits(
        body_bytes=_integer(limits_raw.get("body_bytes", 1_048_576), "limits.body_bytes", 1_024, 4_194_304),
        events_per_request=_integer(limits_raw.get("events_per_request", 1_000), "limits.events_per_request", 1, 10_000),
        claims_per_client=_integer(limits_raw.get("claims_per_client", 10_000), "limits.claims_per_client", 1, 1_000_000),
        requests_per_minute=_integer(limits_raw.get("requests_per_minute", 120), "limits.requests_per_minute", 1, 100_000),
    )

    return Config(
        enabled=enabled,
        listen=listen,
        port=port,
        tls=tls,
        clients=tuple(clients),
        database=_path(obj.get("database", DEFAULT_DATABASE), "database"),
        whitelist_file=_path(obj.get("whitelist_file", DEFAULT_WHITELIST), "whitelist_file"),
        enforcement_socket=_path(obj.get("enforcement_socket", DEFAULT_SOCKET), "enforcement_socket"),
        limits=limits,
        history_days=_integer(obj.get("history_days", 90), "history_days", 1, 3650),
    )


def load_config(path: str | os.PathLike[str] = DEFAULT_CONFIG_PATH) -> Config:
    """Load a root-owned configuration file with exactly mode 0640."""

    config_path = Path(path)
    if not config_path.is_absolute():
        raise ConfigError("config path must be absolute")
    try:
        for parent in reversed(config_path.parents):
            parent_info = parent.lstat()
            if (
                not stat.S_ISDIR(parent_info.st_mode)
                or stat.S_ISLNK(parent_info.st_mode)
                or parent_info.st_uid != 0
                or parent_info.st_mode & 0o022
            ):
                raise ConfigError(f"unsafe config parent directory: {parent}")
        fd = os.open(config_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise ConfigError(f"cannot securely open config: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError("config must be a regular file")
        if info.st_uid != 0:
            raise ConfigError("config must be owned by root")
        if stat.S_IMODE(info.st_mode) != 0o640:
            raise ConfigError("config mode must be 0640")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(1_048_577)
    finally:
        os.close(fd)
    if len(data) > 1_048_576:
        raise ConfigError("config exceeds 1 MiB")
    return parse_config(strict_json_loads(data))
