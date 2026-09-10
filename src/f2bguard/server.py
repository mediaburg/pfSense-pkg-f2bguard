"""mTLS HTTPS API for the pfSense Fail2Ban Guard receiver.

Run with ``python -m f2bguard.server --config /absolute/path/config.json``.
The shipped/default configuration is disabled and therefore opens no listener.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import ipaddress
import json
import os
import re
import socket
import sqlite3
import ssl
import stat
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .config import ClientConfig, Config, ConfigError, load_config, strict_json_loads
from .networks import NetworkIndex
from .store import (
    ApplyResult,
    ClaimStore,
    StoreConflict,
    StoreLimit,
    ValidationError,
)


MAX_HELPER_MESSAGE = 4 * 1024 * 1024
MAX_WHITELIST_BYTES = 4 * 1024 * 1024
MAX_WHITELIST_ENTRIES = 100_000
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_NO_BODY = object()


class EnforcementError(RuntimeError):
    """The desired claim state could not be safely applied."""


def certificate_fingerprint(connection: ssl.SSLSocket) -> str:
    certificate = connection.getpeercert(binary_form=True)
    if not certificate:
        raise PermissionError("client certificate required")
    return hashlib.sha256(certificate).hexdigest()


def _secure_read_root_file(path: str, maximum: int) -> bytes:
    target = Path(path)
    if not target.is_absolute():
        raise EnforcementError("whitelist path must be absolute")
    try:
        for parent in reversed(target.parents):
            info = parent.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & 0o022
            ):
                raise EnforcementError("unsafe whitelist parent directory")
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise EnforcementError("whitelist is missing or inaccessible") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise EnforcementError("unsafe whitelist file")
        if info.st_size > maximum:
            raise EnforcementError("whitelist exceeds size limit")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
    finally:
        os.close(fd)
    if len(data) > maximum:
        raise EnforcementError("whitelist exceeds size limit")
    return data


def parse_whitelist(data: bytes) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EnforcementError("whitelist must be ASCII") from exc
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if "%" in value:
            raise EnforcementError("whitelist contains a scoped address")
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise EnforcementError("whitelist contains an invalid entry") from exc
        if len(networks) > MAX_WHITELIST_ENTRIES:
            raise EnforcementError("whitelist contains too many entries")
    return tuple(networks)


class Whitelist:
    """Loads the trusted whitelist afresh and remembers only the last valid parse."""

    def __init__(self, path: str):
        self.path = path
        self.last_valid: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] | None = None

    def reload(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        # Failure intentionally raises instead of using stale policy for a replacement.
        parsed = parse_whitelist(_secure_read_root_file(self.path, MAX_WHITELIST_BYTES))
        self.last_valid = parsed
        return parsed


class HelperClient:
    def __init__(self, path: str, *, timeout: float = 5.0, retries: int = 3):
        self.path = path
        self.timeout = timeout
        self.retries = retries

    def replace(self, ipv4: list[str], ipv6: list[str]) -> dict[str, Any]:
        request = json.dumps(
            {"op": "replace", "ipv4": ipv4, "ipv6": ipv6},
            separators=(",", ":"),
            allow_nan=False,
        ).encode() + b"\n"
        if len(request) > MAX_HELPER_MESSAGE:
            raise EnforcementError("helper request exceeds size limit")
        last_error = "helper unavailable"
        for attempt in range(self.retries):
            try:
                response = self._exchange(request)
                return self._validate_response(response)
            except (OSError, TimeoutError, json.JSONDecodeError, ConfigError, EnforcementError) as exc:
                last_error = "PF helper unavailable" if isinstance(exc, OSError) else (str(exc) or exc.__class__.__name__)
                if attempt + 1 < self.retries:
                    time.sleep(0.1 * (2**attempt))
        raise EnforcementError(f"PF helper failed after {self.retries} attempts: {last_error}")

    def _exchange(self, request: bytes) -> Any:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self.timeout)
            connection.connect(self.path)
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            response = bytearray()
            while b"\n" not in response:
                chunk = connection.recv(min(65536, MAX_HELPER_MESSAGE + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > MAX_HELPER_MESSAGE:
                    raise EnforcementError("helper response exceeds size limit")
        if not response.endswith(b"\n") or response.count(b"\n") != 1:
            raise EnforcementError("invalid helper response framing")
        return strict_json_loads(bytes(response[:-1]))

    @staticmethod
    def _validate_response(response: Any) -> dict[str, Any]:
        if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
            raise EnforcementError("invalid helper response")
        if not response["ok"]:
            error = response.get("error")
            raise EnforcementError(error if isinstance(error, str) and error else "helper rejected replacement")
        ipv4 = response.get("applied_ipv4")
        ipv6 = response.get("applied_ipv6")
        digest = response.get("digest")
        if (
            isinstance(ipv4, bool)
            or not isinstance(ipv4, int)
            or ipv4 < 0
            or isinstance(ipv6, bool)
            or not isinstance(ipv6, int)
            or ipv6 < 0
            or (digest is not None and (not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest)))
        ):
            raise EnforcementError("helper returned invalid applied-state metadata")
        return response


class Enforcer:
    def __init__(self, store: ClaimStore, whitelist_path: str, helper: HelperClient):
        self.store = store
        self.whitelist = Whitelist(whitelist_path)
        self.helper = helper
        self._lock = threading.Lock()
        self._last_index: NetworkIndex | None = None

    def enforce(self) -> int:
        with self._lock:
            desired_v4, desired_v6 = self.store.effective_ips()
            desired_digest = hashlib.sha256(
                "\n".join(desired_v4 + desired_v6).encode()
            ).hexdigest()
            self.store.record_enforcement_attempt(desired_digest)
            try:
                networks = self.whitelist.reload()
                index = NetworkIndex(networks)
                v4 = self._exclude(desired_v4, index)
                v6 = self._exclude(desired_v6, index)
                response = self.helper.replace(v4, v6)
            except Exception as exc:
                error = str(exc) if isinstance(exc, EnforcementError) else "enforcement failed"
                self.store.record_enforcement_failure(desired_digest, error)
                if isinstance(exc, EnforcementError):
                    raise
                raise EnforcementError(error) from exc
            self.store.record_enforcement_success(
                desired_digest=desired_digest,
                applied_digest=response.get("digest"),
                ipv4=response["applied_ipv4"],
                ipv6=response["applied_ipv6"],
            )
            self._last_index = index
            return response["applied_ipv4"] + response["applied_ipv6"]

    @staticmethod
    def _exclude(
        values: list[str],
        index: NetworkIndex,
    ) -> list[str]:
        return index.exclude(values)

    def client_effective_count(self, client_id: str) -> int:
        with self._lock:
            v4, v6 = self.store.client_effective_ips(client_id)
            # The empty set is unaffected by whitelist policy.  This also lets
            # a newly started server answer status for a client with no claims
            # before its first periodic enforcement completes.
            if not v4 and not v6:
                return 0
            index = self._last_index
            if index is None:
                raise EnforcementError("no valid whitelist has been loaded")
            return len(self._exclude(v4, index)) + len(self._exclude(v6, index))


class RateLimiter:
    def __init__(self, requests_per_minute: int):
        self.limit = requests_per_minute
        self._requests: dict[str, collections.deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, client_id: str, *, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            history = self._requests.setdefault(client_id, collections.deque())
            while history and history[0] <= current - 60.0:
                history.popleft()
            if len(history) >= self.limit:
                return False
            history.append(current)
            return True


class GuardHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    # A clean restart can otherwise fail while connections accepted by the old
    # listener remain in TIME_WAIT.  This is SO_REUSEADDR; socketserver does not
    # enable SO_REUSEPORT here, so a second live listener still cannot bind.
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], config: Config):
        self.config = config
        self.store = ClaimStore(config.database, history_days=config.history_days)
        self.enforcer = Enforcer(
            self.store, config.whitelist_file, HelperClient(config.enforcement_socket)
        )
        self.rate_limiter = RateLimiter(config.limits.requests_per_minute)
        self.stop_event = threading.Event()
        self.ssl_context: ssl.SSLContext | None = None
        self._worker_slots = threading.BoundedSemaphore(64)
        super().__init__(address, handler)

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._worker_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        secured: ssl.SSLSocket | None = None
        try:
            request.settimeout(10.0)
            if self.ssl_context is None:
                raise RuntimeError("TLS context is not configured")
            secured = self.ssl_context.wrap_socket(request, server_side=True)
            self.finish_request(secured, client_address)
        except (ssl.SSLError, TimeoutError, ConnectionError, OSError):
            pass
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(secured if secured is not None else request)
            self._worker_slots.release()


class GuardHandler(BaseHTTPRequestHandler):
    server: GuardHTTPServer
    protocol_version = "HTTP/1.1"
    server_version = "f2bguard"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10.0)

    def log_message(self, format: str, *args: Any) -> None:
        message = format % args
        sys.stderr.write("f2bguard: " + json.dumps(message, ensure_ascii=True) + "\n")

    def _client(self) -> ClientConfig | None:
        try:
            fingerprint = certificate_fingerprint(self.connection)  # type: ignore[arg-type]
        except (PermissionError, ssl.SSLError, AttributeError):
            return None
        return self.server.config.clients_by_fingerprint.get(fingerprint)

    def _authorize(self) -> ClientConfig | None:
        client = self._client()
        if client is None:
            self._json(HTTPStatus.FORBIDDEN, {"error": "unknown client certificate"})
            return None
        if not self.server.rate_limiter.allow(client.id):
            self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "rate limit exceeded"})
            return None
        return client

    def _json(self, status: HTTPStatus | int, value: dict[str, Any]) -> None:
        encoded = json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        if self.command != "HEAD":
            self.wfile.write(encoded)

    def _body(self) -> Any:
        if self.headers.get("Transfer-Encoding") is not None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "transfer encoding is unsupported"})
            return _NO_BODY
        lengths = self.headers.get_all("Content-Length", failobj=[])
        if len(lengths) != 1 or "," in lengths[0]:
            if not lengths:
                self._json(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length required"})
            else:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "exactly one Content-Length required"})
            return _NO_BODY
        raw_length = lengths[0]
        if raw_length is None:
            self._json(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length required"})
            return _NO_BODY
        try:
            length = int(raw_length, 10)
        except ValueError:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid Content-Length"})
            return _NO_BODY
        if length < 0:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid Content-Length"})
            return _NO_BODY
        if length > self.server.config.limits.body_bytes:
            self.close_connection = True
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "request body too large"})
            return _NO_BODY
        content_type = self.headers.get_content_type()
        if content_type != "application/json":
            self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "application/json required"})
            return _NO_BODY
        data = self.rfile.read(length)
        if len(data) != length:
            self.close_connection = True
            self._json(HTTPStatus.BAD_REQUEST, {"error": "incomplete request body"})
            return _NO_BODY
        try:
            return strict_json_loads(data)
        except ConfigError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return _NO_BODY

    @staticmethod
    def _outer(raw: Any, fields: set[str]) -> dict[str, Any]:
        if not isinstance(raw, dict) or set(raw) != fields:
            raise ValidationError(f"request must contain exactly: {', '.join(sorted(fields))}")
        return raw

    @staticmethod
    def _allowed(client: ClientConfig, jails: list[str]) -> None:
        if any(jail not in client.allowed_jails for jail in jails):
            raise PermissionError("jail is not allowed for this client")

    def _finish_write(self, client: ClientConfig, result: ApplyResult) -> None:
        try:
            self.server.enforcer.enforce()
            count = self.server.enforcer.client_effective_count(client.id)
        except (EnforcementError, sqlite3.Error) as exc:
            error = str(exc) if isinstance(exc, EnforcementError) else "enforcement state unavailable"
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "accepted": result.accepted,
                    "durable": result.duplicate or not result.stale,
                    "enforced": False,
                    "stale": result.stale,
                    "error": error,
                },
            )
            return
        self._json(
            HTTPStatus.OK,
            {
                "accepted": result.accepted,
                "duplicate": result.duplicate,
                "stale": result.stale,
                "last_seq": result.last_seq,
                "effective_ip_count": count,
            },
        )

    def do_POST(self) -> None:
        client = self._authorize()
        if client is None:
            return
        raw = self._body()
        if raw is _NO_BODY:
            return
        try:
            if self.path == "/v1/events":
                body = self._outer(raw, {"events"})
                events = self.server.store.validate_events(
                    body["events"], self.server.config.limits.events_per_request
                )
                self._allowed(client, [event.jail for event in events])
                result = self.server.store.apply_events(
                    client.id,
                    events,
                    claims_limit=self.server.config.limits.claims_per_client,
                )
            elif self.path == "/v1/snapshot":
                body = self._outer(raw, {"snapshot_id", "seq", "claims"})
                snapshot_id, seq, claims = self.server.store.validate_snapshot(
                    body["snapshot_id"],
                    body["seq"],
                    body["claims"],
                    self.server.config.limits.claims_per_client,
                )
                self._allowed(client, [claim.jail for claim in claims])
                result = self.server.store.apply_snapshot(
                    client.id,
                    snapshot_id,
                    seq,
                    claims,
                    claims_limit=self.server.config.limits.claims_per_client,
                )
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
        except PermissionError as exc:
            self._json(HTTPStatus.FORBIDDEN, {"error": str(exc)})
            return
        except (ValidationError, StoreLimit) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        except StoreConflict as exc:
            self._json(HTTPStatus.CONFLICT, {"error": str(exc)})
            return
        except sqlite3.Error:
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"accepted": False, "error": "durable store unavailable"})
            return
        self._finish_write(client, result)

    def do_GET(self) -> None:
        client = self._authorize()
        if client is None:
            return
        if self.path != "/v1/status":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        try:
            status = self.server.store.client_status(client.id)
            count = self.server.enforcer.client_effective_count(client.id)
        except (EnforcementError, sqlite3.Error) as exc:
            error = str(exc) if isinstance(exc, EnforcementError) else "enforcement state unavailable"
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": error})
            return
        # The store-level count precedes whitelist filtering and may count
        # multiple claims for one address.  Report the same client-owned,
        # whitelist-filtered unique-IP metric used by successful writes.
        status.pop("effective_claim_count", None)
        status["effective_ip_count"] = count
        self._json(HTTPStatus.OK, status)


def _periodic(server: GuardHTTPServer, interval: float = 30.0) -> None:
    while not server.stop_event.is_set():
        try:
            server.enforcer.enforce()
            server.store.prune_history()
        except (EnforcementError, OSError, sqlite3.Error):
            # The durable error is visible through status; retry on the next interval.
            pass
        if server.stop_event.wait(interval):
            break


def build_server(config: Config) -> GuardHTTPServer:
    if not config.enabled:
        raise ConfigError("service is disabled")
    server_class: type[GuardHTTPServer] = GuardHTTPServer
    if ipaddress.ip_address(config.listen).version == 6:
        server_class = type("IPv6GuardHTTPServer", (GuardHTTPServer,), {"address_family": socket.AF_INET6})
    server = server_class((config.listen, config.port), GuardHandler, config)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(config.tls.cert, config.tls.key)
    context.load_verify_locations(cafile=config.tls.ca)
    server.ssl_context = context
    return server


def serve(config: Config) -> None:
    server = build_server(config)
    worker = threading.Thread(target=_periodic, args=(server,), daemon=True)
    worker.start()
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.stop_event.set()
        server.server_close()
        worker.join(timeout=2.0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/usr/local/etc/f2bguard/config.json")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if not config.enabled:
            print("f2bguard is disabled; no listener opened", file=sys.stderr)
            return 0
        serve(config)
    except (ConfigError, OSError, ssl.SSLError) as exc:
        print(f"f2bguard: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
