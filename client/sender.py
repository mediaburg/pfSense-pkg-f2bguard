#!/usr/bin/env python3
"""Durable Fail2Ban event sender.

The action hooks only write to a local SQLite outbox.  A separate worker owns
network delivery, which keeps Fail2Ban's ban path independent of the network.
"""

from __future__ import annotations

import argparse
import dataclasses
import ipaddress
import json
import math
import os
import re
import signal
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable, Iterable, Mapping


MAX_JAIL = 128
MAX_IP = 64
MAX_EVENT_BYTES = 1_000_000
MAX_RESPONSE_BYTES = 64 * 1024
MAX_PENDING = 10_000
UUID_RE = __import__("re").compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


class ConfigError(ValueError):
    """Invalid sender configuration."""


class EnumerationError(RuntimeError):
    """Fail2Ban state could not be enumerated completely."""


class SnapshotRace(RuntimeError):
    """A hook changed local state while a snapshot was being enumerated."""


class StoreFullError(RuntimeError):
    """The durable outbox reached its configured safety bound."""


def _uuid(value: str, field: str) -> str:
    if not isinstance(value, str) or not UUID_RE.fullmatch(value):
        raise ValueError(f"{field} must be a UUID")
    return value.lower()


def canonical_ip(value: str) -> str:
    try:
        text = value.strip()
        if "%" in text:
            raise ValueError("scoped IP is not allowed")
        parsed = ipaddress.ip_address(text)
    except (ValueError, AttributeError) as exc:
        raise ValueError("IP must be a literal") from exc
    if (
        parsed.is_unspecified
        or parsed.is_multicast
        or parsed.is_loopback
        or parsed.is_link_local
        or getattr(parsed, "ipv4_mapped", None) is not None
    ):
        raise ValueError("special-purpose IP is not allowed")
    return str(parsed)


def _jail(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_JAIL:
        raise ValueError("jail must be a non-empty short string")
    # Fail2Ban jail names are identifiers.  Keeping this narrow also makes
    # command argument construction unambiguous.
    if any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for ch in value):
        raise ValueError("jail contains unsupported characters")
    return value


def _absolute_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or not os.path.isabs(value):
        raise ConfigError(f"{field} must be an absolute path")
    return value


@dataclasses.dataclass(frozen=True)
class PermanentJail:
    name: str
    bantime: int = -1

    def __post_init__(self) -> None:
        _jail(self.name)
        if isinstance(self.bantime, bool) or not isinstance(self.bantime, int) or self.bantime != -1:
            raise ConfigError(f"permanent jail {self.name!r} must have bantime -1")


@dataclasses.dataclass(frozen=True)
class SenderConfig:
    database: str
    endpoint: str
    ca: str
    cert: str
    key: str
    permanent_jails: tuple[PermanentJail, ...]
    fail2ban_client: str = "/usr/bin/fail2ban-client"
    poll_seconds: float = 5.0
    request_timeout: float = 10.0
    initial_backoff: float = 1.0
    max_backoff: float = 300.0

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "SenderConfig":
        if not isinstance(raw, Mapping):
            raise ConfigError("configuration must be an object")
        unknown = set(raw) - {
            "database", "endpoint", "tls", "permanent_jails", "fail2ban_client",
            "poll_seconds", "request_timeout", "initial_backoff", "max_backoff",
        }
        if unknown:
            raise ConfigError("unknown configuration field")
        try:
            endpoint = raw["endpoint"]
            if not isinstance(endpoint, str):
                raise TypeError("endpoint must be a string")
            parsed = urllib.parse.urlsplit(endpoint)
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigError("endpoint is required") from exc
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ConfigError("endpoint must be an https URL with a hostname")
        if parsed.fragment or parsed.query:
            raise ConfigError("endpoint must not contain a query or fragment")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ConfigError("endpoint port is invalid")

        tls = raw.get("tls")
        if not isinstance(tls, Mapping):
            raise ConfigError("tls.ca, tls.cert and tls.key are required")
        ca = _absolute_path(tls.get("ca"), "tls.ca")
        cert = _absolute_path(tls.get("cert"), "tls.cert")
        key = _absolute_path(tls.get("key"), "tls.key")
        # There is deliberately no disable-TLS/verify option.  Reject common
        # spellings so a typo cannot silently turn into insecure behaviour.
        for name in ("verify", "verify_tls", "insecure", "disable_tls", "check_hostname"):
            if name in tls:
                raise ConfigError(f"tls.{name} is not supported")
        for name in ("verify", "verify_tls", "insecure", "insecure_tls", "disable_tls", "tls_verify"):
            if name in raw:
                raise ConfigError(f"{name} is not supported")

        raw_jails = raw.get("permanent_jails", [])
        if not isinstance(raw_jails, list) or not raw_jails:
            raise ConfigError("permanent_jails must contain configured bantime=-1 jails")
        jails: list[PermanentJail] = []
        seen: set[str] = set()
        for item in raw_jails:
            if not isinstance(item, Mapping) or set(item) - {"name", "bantime"}:
                raise ConfigError("permanent_jails entries must be {name, bantime}")
            entry = PermanentJail(str(item.get("name", "")), item.get("bantime", None))
            if entry.name in seen:
                raise ConfigError("permanent_jails contains a duplicate")
            seen.add(entry.name)
            jails.append(entry)

        command = _absolute_path(raw.get("fail2ban_client", "/usr/bin/fail2ban-client"), "fail2ban_client")
        def positive(name: str, default: float) -> float:
            value = raw.get(name, default)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
                raise ConfigError(f"{name} must be positive")
            return float(value)

        initial = positive("initial_backoff", 1.0)
        maximum = positive("max_backoff", 300.0)
        if maximum < initial:
            raise ConfigError("max_backoff must be at least initial_backoff")
        api_base = endpoint.rstrip("/")
        if parsed.path in ("", "/"):
            api_base += "/v1"
        elif parsed.path.rstrip("/") != "/v1":
            raise ConfigError("endpoint path must be /v1 (or omitted)")
        return cls(
            database=_absolute_path(raw.get("database"), "database"),
            endpoint=api_base,
            ca=ca,
            cert=cert,
            key=key,
            permanent_jails=tuple(jails),
            fail2ban_client=command,
            poll_seconds=positive("poll_seconds", 5.0),
            request_timeout=positive("request_timeout", 10.0),
            initial_backoff=initial,
            max_backoff=maximum,
        )

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "SenderConfig":
        config_path = _absolute_path(os.fspath(path), "config")
        def reject_constant(_value: str) -> None:
            raise ConfigError("non-finite JSON number")
        def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ConfigError("duplicate configuration field")
                result[key] = value
            return result
        try:
            with open(config_path, "rb") as handle:
                raw = json.load(handle, object_pairs_hook=reject_duplicate, parse_constant=reject_constant)
        except (OSError, ValueError) as exc:
            raise ConfigError("could not read sender configuration") from exc
        return cls.from_dict(raw)


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


class SenderStore:
    """SQLite-backed sequence allocator, claim lifecycle and outbox."""

    def __init__(self, path: str | os.PathLike[str], max_pending: int = MAX_PENDING):
        self.path = os.fspath(path)
        parent = os.path.dirname(self.path)
        if not os.path.isabs(self.path):
            raise ValueError("database path must be absolute")
        if parent and not os.path.isdir(parent):
            raise OSError("database parent directory does not exist")
        if isinstance(max_pending, bool) or not isinstance(max_pending, int) or max_pending < 1:
            raise ValueError("max_pending must be a positive integer")
        self.max_pending = max_pending
        self.db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT OR IGNORE INTO metadata(key, value) VALUES ('seq', '0');
            CREATE TABLE IF NOT EXISTS claims (
                jail TEXT NOT NULL,
                ip TEXT NOT NULL,
                ban_id TEXT NOT NULL,
                active INTEGER NOT NULL CHECK(active IN (0,1)),
                PRIMARY KEY(jail, ip),
                UNIQUE(jail, ban_id)
            );
            CREATE TABLE IF NOT EXISTS outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                seq INTEGER NOT NULL UNIQUE,
                kind TEXT NOT NULL CHECK(kind IN ('event','snapshot')),
                event_id TEXT NOT NULL UNIQUE,
                payload BLOB NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                available_at REAL NOT NULL DEFAULT 0,
                delivered_at REAL
            );
            CREATE INDEX IF NOT EXISTS outbox_due ON outbox(delivered_at, seq, available_at);
            """
        )
        self.prune_delivered()

    def close(self) -> None:
        self.db.close()

    def _next_seq(self) -> int:
        row = self.db.execute("SELECT value FROM metadata WHERE key='seq'").fetchone()
        current = int(row[0])
        seq = current + 1
        self.db.execute("UPDATE metadata SET value=? WHERE key='seq'", (str(seq),))
        return seq

    def current_seq(self) -> int:
        row = self.db.execute("SELECT value FROM metadata WHERE key='seq'").fetchone()
        return int(row[0])

    def _check_capacity(self) -> None:
        row = self.db.execute("SELECT COUNT(*) FROM outbox WHERE delivered_at IS NULL").fetchone()
        if int(row[0]) >= self.max_pending:
            raise StoreFullError("sender outbox is full; delivery must catch up")

    def prune_delivered(self) -> None:
        self.db.execute("DELETE FROM outbox WHERE delivered_at IS NOT NULL")

    def set_last_error(self, error_type: str) -> None:
        # Store only a class name, never endpoint text, response bodies, or
        # certificate/key paths.
        self.db.execute(
            "INSERT INTO metadata(key,value) VALUES('last_error',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (error_type[:128],),
        )

    def clear_last_error(self) -> None:
        self.db.execute("DELETE FROM metadata WHERE key='last_error'")

    def last_error(self) -> str | None:
        row = self.db.execute("SELECT value FROM metadata WHERE key='last_error'").fetchone()
        return None if row is None else str(row[0])

    @staticmethod
    def _event_payload(seq: int, op: str, jail: str, ban_id: str, ip: str) -> dict[str, Any]:
        if op not in ("ban", "unban"):
            raise ValueError("operation must be ban or unban")
        return {
            "event_id": str(uuid.uuid4()),
            "seq": seq,
            "op": op,
            "jail": _jail(jail),
            "ban_id": _uuid(ban_id, "ban_id"),
            "ip": canonical_ip(ip),
            "permanent": True,
            "expires_at": None,
        }

    def enqueue(self, op: str, jail: str, ip: str, now: float | None = None) -> dict[str, Any] | None:
        """Enqueue one lifecycle event and return its exact payload.

        A duplicate ban for an active claim is idempotent.  A duplicate unban
        after the claim is inactive is also idempotent.  A re-ban after an
        unban gets a fresh ban_id, while the sequence keeps event order.
        """
        jail = _jail(jail)
        ip = canonical_ip(ip)
        if op not in ("ban", "unban"):
            raise ValueError("operation must be ban or unban")
        when = time.time() if now is None else float(now)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT ban_id, active FROM claims WHERE jail=? AND ip=?", (jail, ip)).fetchone()
            if op == "ban":
                if row is not None and row["active"]:
                    self.db.execute("COMMIT")
                    return None
                ban_id = str(uuid.uuid4())
                self.db.execute(
                    "INSERT INTO claims(jail,ip,ban_id,active) VALUES(?,?,?,1) "
                    "ON CONFLICT(jail,ip) DO UPDATE SET ban_id=excluded.ban_id, active=1",
                    (jail, ip, ban_id),
                )
            else:
                if row is None or not row["active"]:
                    self.db.execute("COMMIT")
                    return None
                ban_id = row["ban_id"]
                self.db.execute("UPDATE claims SET active=0 WHERE jail=? AND ip=?", (jail, ip))
            self._check_capacity()
            seq = self._next_seq()
            payload = self._event_payload(seq, op, jail, ban_id, ip)
            self.db.execute(
                "INSERT INTO outbox(seq,kind,event_id,payload,available_at) VALUES(?,?,?,?,?)",
                (seq, "event", payload["event_id"], _json_bytes(payload), when),
            )
            self.db.execute("COMMIT")
            return payload
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def _current_claim(self, jail: str, ip: str) -> str | None:
        row = self.db.execute(
            "SELECT ban_id FROM claims WHERE jail=? AND ip=? AND active=1", (jail, ip)
        ).fetchone()
        return None if row is None else str(row[0])

    def enqueue_snapshot(
        self,
        claims: Iterable[Mapping[str, Any]],
        now: float | None = None,
        expected_seq: int | None = None,
    ) -> dict[str, Any]:
        """Atomically reconcile claims and enqueue an authoritative snapshot."""
        when = time.time() if now is None else float(now)
        normalized: dict[tuple[str, str], dict[str, Any]] = {}
        for claim in claims:
            jail = _jail(claim.get("jail"))
            ip = canonical_ip(claim.get("ip"))
            key = (jail, ip)
            if key in normalized:
                raise ValueError("snapshot contains duplicate claim")
            existing = self._current_claim(jail, ip)
            ban_id = existing or _uuid(str(claim.get("ban_id")), "ban_id") if claim.get("ban_id") else existing
            if not ban_id:
                ban_id = str(uuid.uuid4())
            normalized[key] = {
                "jail": jail,
                "ban_id": ban_id,
                "ip": ip,
                "permanent": True,
                "expires_at": None,
            }

        self.db.execute("BEGIN IMMEDIATE")
        try:
            if expected_seq is not None and self.current_seq() != expected_seq:
                raise SnapshotRace("Fail2Ban changed while snapshot was enumerated")
            self._check_capacity()
            # Reuse existing lifecycle IDs, then make the snapshot's set
            # authoritative locally.  A later action event receives a higher
            # sequence while this transaction holds the allocator lock.
            existing_rows = self.db.execute("SELECT jail,ip,ban_id FROM claims WHERE active=1").fetchall()
            existing_map = {(r["jail"], r["ip"]): r["ban_id"] for r in existing_rows}
            for key, claim in normalized.items():
                claim["ban_id"] = existing_map.get(key, claim["ban_id"])
                self.db.execute(
                    "INSERT INTO claims(jail,ip,ban_id,active) VALUES(?,?,?,1) "
                    "ON CONFLICT(jail,ip) DO UPDATE SET ban_id=excluded.ban_id, active=1",
                    (claim["jail"], claim["ip"], claim["ban_id"]),
                )
            for key in set(existing_map) - set(normalized):
                self.db.execute("UPDATE claims SET active=0 WHERE jail=? AND ip=?", key)
            seq = self._next_seq()
            snapshot = {
                "snapshot_id": str(uuid.uuid4()),
                "seq": seq,
                "claims": sorted(normalized.values(), key=lambda item: (item["jail"], item["ip"])),
            }
            self.db.execute(
                "INSERT INTO outbox(seq,kind,event_id,payload,available_at) VALUES(?,?,?,?,?)",
                (seq, "snapshot", snapshot["snapshot_id"], _json_bytes(snapshot), when),
            )
            self.db.execute("COMMIT")
            return snapshot
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def next_due(self, now: float | None = None) -> sqlite3.Row | None:
        when = time.time() if now is None else float(now)
        # Preserve global sequence order, including an earlier row waiting for
        # retry.  Sending a later sequence could make an earlier retry stale.
        return self.db.execute(
            "SELECT * FROM outbox WHERE delivered_at IS NULL AND available_at<=? "
            "AND seq=(SELECT MIN(seq) FROM outbox WHERE delivered_at IS NULL)",
            (when,),
        ).fetchone()

    def mark_delivered(self, row_id: int, when: float | None = None) -> None:
        self.db.execute("UPDATE outbox SET delivered_at=? WHERE id=? AND delivered_at IS NULL", (time.time() if when is None else when, row_id))

    def mark_retry(self, row_id: int, attempts: int, when: float, delay: float) -> None:
        self.db.execute(
            "UPDATE outbox SET attempts=?, available_at=? WHERE id=? AND delivered_at IS NULL",
            (attempts, when + delay, row_id),
        )

    def pending(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.db.execute("SELECT * FROM outbox WHERE delivered_at IS NULL ORDER BY seq")]


def _extract_ips(output: str) -> list[str]:
    """Parse fail2ban-client get JAIL banip output without accepting partial data."""
    if not output.strip():
        return []
    result: list[str] = []
    for line in output.splitlines():
        for token in line.split():
            token = token.strip().rstrip(",")
            try:
                result.append(canonical_ip(token))
            except ValueError as exc:
                raise EnumerationError("fail2ban returned an unparseable ban list") from exc
    if len(set(result)) != len(result):
        raise EnumerationError("fail2ban returned duplicate IPs")
    return result


_BAN_WITH_TIME = re.compile(
    r"^(?P<ip>\S+)\s+\t"
    r"(?P<start>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"\s+\+\s+(?P<duration>-?\d+)\s+=\s+"
    r"(?P<end>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$"
)


def _extract_permanent_ips(output: str) -> list[str]:
    """Parse every line of ``banip --with-time`` without partial recovery."""
    if not output.strip():
        return []
    result: list[str] = []
    for line in output.splitlines():
        match = _BAN_WITH_TIME.fullmatch(line)
        if match is None:
            raise EnumerationError("fail2ban returned an unparseable timed ban list")
        try:
            ip = canonical_ip(match.group("ip"))
        except ValueError as exc:
            raise EnumerationError("fail2ban returned an invalid ban IP") from exc
        if int(match.group("duration")) == -1:
            result.append(ip)
    if len(set(result)) != len(result):
        raise EnumerationError("fail2ban returned duplicate IPs")
    return result


def enumerate_permanent_jails(
    config: SenderConfig,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[dict[str, Any]]:
    """Return complete claims, raising before a snapshot on any command error."""
    claims: list[dict[str, Any]] = []
    for jail in config.permanent_jails:
        try:
            completed = runner(
                [config.fail2ban_client, "get", jail.name, "banip", "--with-time"],
                check=False,
                capture_output=True,
                text=True,
                timeout=config.request_timeout,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise EnumerationError("could not enumerate fail2ban bans") from exc
        if completed.returncode != 0:
            raise EnumerationError("fail2ban returned an enumeration error")
        for ip in _extract_permanent_ips(completed.stdout):
            claims.append({"jail": jail.name, "ip": ip, "permanent": True, "expires_at": None})
    return claims


class HTTPSClient:
    def __init__(self, config: SenderConfig, opener: urllib.request.OpenerDirector | None = None):
        self.config = config
        context = ssl.create_default_context(cafile=config.ca)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(certfile=config.cert, keyfile=config.key)
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                raise urllib.error.HTTPError(req.full_url, code, "redirects are not accepted", headers, fp)

        self.opener = opener or urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), NoRedirect()
        )

    def send(self, payload: Mapping[str, Any]) -> None:
        is_snapshot = "snapshot_id" in payload
        body = _json_bytes(payload if is_snapshot or "events" in payload else {"events": [payload]})
        if len(body) > MAX_EVENT_BYTES:
            raise ValueError("request is too large")
        request = urllib.request.Request(
            self.config.endpoint + ("/snapshot" if is_snapshot else "/events"),
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with self.opener.open(request, timeout=self.config.request_timeout) as response:
                status = response.status
                raw_response = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            if 400 <= exc.code < 500 and exc.code != 429:
                raise RuntimeError(f"sender endpoint rejected request with HTTP {exc.code}") from exc
            raise RuntimeError("sender endpoint temporarily unavailable") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError("sender endpoint unavailable") from exc
        if status < 200 or status >= 300:
            raise RuntimeError("sender endpoint returned an unsuccessful response")
        if len(raw_response) > MAX_RESPONSE_BYTES:
            raise RuntimeError("sender endpoint response is too large")
        try:
            response_json = json.loads(raw_response.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise RuntimeError("sender endpoint returned invalid JSON") from exc
        if not isinstance(response_json, dict) or response_json.get("accepted") is not True:
            raise RuntimeError("sender endpoint did not acknowledge the write")


class Worker:
    def __init__(self, config: SenderConfig, store: SenderStore, transport: HTTPSClient, error_stream: Any = sys.stderr):
        self.config = config
        self.store = store
        self.transport = transport
        self.error_stream = error_stream

    def process_once(self, now: float | None = None) -> bool:
        when = time.time() if now is None else float(now)
        row = self.store.next_due(when)
        if row is None:
            return False
        payload = json.loads(row["payload"])
        request = {"events": [payload]} if row["kind"] == "event" else payload
        try:
            self.transport.send(request)
        except Exception:
            attempts = int(row["attempts"]) + 1
            delay = min(self.config.max_backoff, self.config.initial_backoff * (2 ** min(attempts - 1, 20)))
            self.store.mark_retry(row["id"], attempts, when, delay)
            self.store.set_last_error("delivery failure")
            print("f2bguard sender delivery retry", file=self.error_stream)
            return False
        self.store.mark_delivered(row["id"], when)
        self.store.clear_last_error()
        return True

    def run(self, stop: Callable[[], bool] | None = None, sleep: Callable[[float], None] = time.sleep) -> None:
        while stop is None or not stop():
            if not self.process_once():
                sleep(self.config.poll_seconds)


def _read_json_config(path: str) -> SenderConfig:
    return SenderConfig.load(path)


def _cli() -> int:
    parser = argparse.ArgumentParser(description="Durable pfSense Fail2Ban Guard sender")
    parser.add_argument("--config", required=True, help="sender config path")
    sub = parser.add_subparsers(dest="command", required=True)
    enqueue = sub.add_parser("enqueue")
    enqueue.add_argument("op", choices=("ban", "unban"))
    enqueue.add_argument("--jail", required=True)
    enqueue.add_argument("--ip", required=True)
    enqueue.add_argument("--bantime", help="live Fail2Ban bantime; bans require -1")
    sub.add_parser("snapshot")
    sub.add_parser("worker")
    args = parser.parse_args()
    config = _read_json_config(args.config)
    store = SenderStore(config.database)
    try:
        if args.command == "enqueue":
            configured = {entry.name for entry in config.permanent_jails}
            if args.jail not in configured:
                raise ConfigError("jail is not configured as permanent")
            if args.op == "ban":
                if args.bantime is None:
                    raise ConfigError("ban enqueue requires --bantime")
                try:
                    bantime = int(args.bantime)
                except ValueError as exc:
                    raise ConfigError("bantime must be an integer") from exc
                if bantime != -1:
                    # Temporary Fail2Ban bans are intentionally not claimed.
                    return 0
            store.enqueue(args.op, args.jail, args.ip)
            return 0
        if args.command == "snapshot":
            # Enumeration is intentionally outside SQLite's write lock.  The
            # sequence fence then detects hooks that changed state meanwhile;
            # retrying re-enumerates instead of releasing a newly banned IP.
            for _attempt in range(5):
                observed_seq = store.current_seq()
                claims = enumerate_permanent_jails(config)
                try:
                    store.enqueue_snapshot(claims, expected_seq=observed_seq)
                except SnapshotRace:
                    continue
                return 0
            raise RuntimeError("Fail2Ban changed continuously; snapshot not created")
        transport = HTTPSClient(config)
        stopping = False
        def handle_signal(_signum: int, _frame: Any) -> None:
            nonlocal stopping
            stopping = True
        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)
        Worker(config, store, transport).run(lambda: stopping)
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(_cli())
