"""Transactional durable state for f2bguard."""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
MAX_HISTORY_EVENTS_PER_CLIENT = 100_000
MAX_HISTORY_SNAPSHOTS_PER_CLIENT = 1_000
MAX_TOTAL_CLAIMS = 100_000


class StoreError(RuntimeError):
    """Base class for durable state errors."""


class StoreConflict(StoreError):
    """An idempotency key was reused with different content."""


class StoreLimit(StoreError):
    """A durable per-client limit would be exceeded."""


class ValidationError(ValueError):
    """An event or snapshot is malformed."""


@dataclass(frozen=True)
class Event:
    event_id: str
    seq: int
    op: str
    jail: str
    ban_id: str
    ip: str
    permanent: bool | None
    expires_at: float | None

    def wire(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "seq": self.seq,
            "op": self.op,
            "jail": self.jail,
            "ban_id": self.ban_id,
            "ip": self.ip,
            "permanent": self.permanent,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class Claim:
    jail: str
    ban_id: str
    ip: str
    permanent: bool
    expires_at: float | None

    def wire(self) -> dict[str, Any]:
        return {
            "jail": self.jail,
            "ban_id": self.ban_id,
            "ip": self.ip,
            "permanent": self.permanent,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class ApplyResult:
    accepted: bool
    duplicate: bool = False
    stale: bool = False
    last_seq: int = 0


def _uuid(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be a UUID string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValidationError(f"{name} must be a UUID string") from exc
    canonical = str(parsed)
    if value.lower() != canonical:
        raise ValidationError(f"{name} must be a canonical UUID")
    return canonical


def _seq(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= 2**63 - 1:
        raise ValidationError("seq must be an integer between 1 and 2^63-1")
    return value


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValidationError(f"{name} is invalid")
    return value


def _ip(value: Any) -> str:
    if not isinstance(value, str) or "%" in value:
        raise ValidationError("ip must be an IP literal")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationError("ip must be an IP literal") from exc
    if (
        parsed.is_unspecified
        or parsed.is_multicast
        or parsed.is_loopback
        or parsed.is_link_local
        or getattr(parsed, "ipv4_mapped", None) is not None
    ):
        raise ValidationError("ip is a protected special-purpose address")
    return parsed.compressed


def _expires_at(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValidationError("expires_at must be null, a Unix timestamp, or RFC3339")
    if isinstance(value, (int, float)):
        result = float(value)
        if not 0 <= result <= 253402300799:
            raise ValidationError("expires_at is outside the supported range")
        return result
    if isinstance(value, str):
        text = value
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = dt.datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValidationError("expires_at must be RFC3339") from exc
        if parsed.tzinfo is None:
            raise ValidationError("expires_at must include a timezone")
        return parsed.timestamp()
    raise ValidationError("expires_at must be null, a Unix timestamp, or RFC3339")


def parse_event(raw: Any) -> Event:
    if not isinstance(raw, dict):
        raise ValidationError("event must be an object")
    required = {"event_id", "seq", "op", "jail", "ban_id", "ip"}
    allowed = required | {"permanent", "expires_at"}
    missing = sorted(required - set(raw))
    unknown = sorted(set(raw) - allowed)
    if missing:
        raise ValidationError(f"event missing field(s): {', '.join(missing)}")
    if unknown:
        raise ValidationError(f"event has unknown field(s): {', '.join(unknown)}")
    op = raw["op"]
    if op not in ("ban", "unban"):
        raise ValidationError("op must be ban or unban")
    permanent_raw = raw.get("permanent")
    if op == "ban" and not isinstance(permanent_raw, bool):
        raise ValidationError("ban permanent must be a boolean")
    if op == "unban" and permanent_raw is not None and not isinstance(permanent_raw, bool):
        raise ValidationError("unban permanent must be a boolean when present")
    expires = _expires_at(raw.get("expires_at"))
    return Event(
        event_id=_uuid(raw["event_id"], "event_id"),
        seq=_seq(raw["seq"]),
        op=op,
        jail=_identifier(raw["jail"], "jail"),
        ban_id=_uuid(raw["ban_id"], "ban_id"),
        ip=_ip(raw["ip"]),
        permanent=permanent_raw,
        expires_at=expires,
    )


def parse_claim(raw: Any) -> Claim:
    if not isinstance(raw, dict):
        raise ValidationError("claim must be an object")
    required = {"jail", "ban_id", "ip", "permanent", "expires_at"}
    missing = sorted(required - set(raw))
    unknown = sorted(set(raw) - required)
    if missing:
        raise ValidationError(f"claim missing field(s): {', '.join(missing)}")
    if unknown:
        raise ValidationError(f"claim has unknown field(s): {', '.join(unknown)}")
    if not isinstance(raw["permanent"], bool):
        raise ValidationError("claim permanent must be a boolean")
    expires = _expires_at(raw["expires_at"])
    return Claim(
        jail=_identifier(raw["jail"], "jail"),
        ban_id=_uuid(raw["ban_id"], "ban_id"),
        ip=_ip(raw["ip"]),
        permanent=raw["permanent"],
        expires_at=expires,
    )


def _payload_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


class ClaimStore:
    """SQLite-backed claim set with atomic, per-client sequence handling."""

    def __init__(self, path: str | os.PathLike[str], *, history_days: int = 90):
        self.path = str(path)
        self.history_days = history_days
        parent = Path(self.path).parent
        parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    @contextmanager
    def _connection(self):
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self._connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS client_state (
                    client_id TEXT PRIMARY KEY,
                    last_seq INTEGER NOT NULL DEFAULT 0,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS claims (
                    client_id TEXT NOT NULL,
                    jail TEXT NOT NULL,
                    ban_id TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    permanent INTEGER NOT NULL CHECK (permanent IN (0,1)),
                    expires_at REAL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (client_id, jail, ban_id),
                    FOREIGN KEY (client_id) REFERENCES client_state(client_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS events (
                    client_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    payload_hash TEXT NOT NULL,
                    op TEXT NOT NULL,
                    jail TEXT NOT NULL,
                    ban_id TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    received_at REAL NOT NULL,
                    PRIMARY KEY (client_id, event_id),
                    UNIQUE (client_id, seq)
                );
                CREATE TABLE IF NOT EXISTS snapshots (
                    client_id TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    payload_hash TEXT NOT NULL,
                    received_at REAL NOT NULL,
                    PRIMARY KEY (client_id, snapshot_id),
                    UNIQUE (client_id, seq)
                );
                CREATE TABLE IF NOT EXISTS enforcement_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton=1),
                    desired_digest TEXT,
                    applied_digest TEXT,
                    applied_ipv4 INTEGER NOT NULL DEFAULT 0,
                    applied_ipv6 INTEGER NOT NULL DEFAULT 0,
                    last_attempt REAL,
                    last_success REAL,
                    last_error TEXT
                );
                INSERT OR IGNORE INTO enforcement_state(singleton) VALUES (1);
                """
            )

    @staticmethod
    def validate_events(raw_events: Any, maximum: int) -> list[Event]:
        if not isinstance(raw_events, list) or not raw_events:
            raise ValidationError("events must be a non-empty array")
        if len(raw_events) > maximum:
            raise ValidationError("too many events")
        events = [parse_event(raw) for raw in raw_events]
        if any(left.seq >= right.seq for left, right in zip(events, events[1:])):
            raise ValidationError("event seq values must strictly increase")
        event_ids = [event.event_id for event in events]
        if len(event_ids) != len(set(event_ids)):
            raise ValidationError("event_id values must be unique within a batch")
        return events

    @staticmethod
    def validate_snapshot(
        snapshot_id: Any, seq: Any, raw_claims: Any, maximum: int
    ) -> tuple[str, int, list[Claim]]:
        parsed_id = _uuid(snapshot_id, "snapshot_id")
        parsed_seq = _seq(seq)
        if not isinstance(raw_claims, list):
            raise ValidationError("claims must be an array")
        if len(raw_claims) > maximum:
            raise ValidationError("too many claims")
        claims = [parse_claim(raw) for raw in raw_claims]
        keys = [(claim.jail, claim.ban_id) for claim in claims]
        if len(keys) != len(set(keys)):
            raise ValidationError("snapshot contains duplicate claim identities")
        return parsed_id, parsed_seq, claims

    def apply_events(
        self, client_id: str, events: Sequence[Event], *, claims_limit: int
    ) -> ApplyResult:
        if not events:
            raise ValidationError("events must not be empty")
        if any(left.seq >= right.seq for left, right in zip(events, events[1:])):
            raise ValidationError("event seq values must strictly increase")
        now = time.time()
        hashes = [_payload_hash(event.wire()) for event in events]
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO client_state(client_id,last_seq,updated_at) VALUES (?,0,?)",
                    (client_id, now),
                )
                row = conn.execute(
                    "SELECT last_seq FROM client_state WHERE client_id=?", (client_id,)
                ).fetchone()
                last_seq = int(row["last_seq"])

                existing: list[sqlite3.Row | None] = [
                    conn.execute(
                        "SELECT seq,payload_hash FROM events WHERE client_id=? AND event_id=?",
                        (client_id, event.event_id),
                    ).fetchone()
                    for event in events
                ]
                for event, digest, prior in zip(events, hashes, existing):
                    if prior is not None and (
                        int(prior["seq"]) != event.seq or prior["payload_hash"] != digest
                    ):
                        raise StoreConflict("event_id was reused with different content")

                if events[0].seq <= last_seq:
                    if events[-1].seq > last_seq:
                        raise StoreConflict("event batch crosses the stored sequence boundary")
                    if all(prior is not None for prior in existing):
                        conn.commit()
                        return ApplyResult(True, duplicate=True, last_seq=last_seq)
                    conn.commit()
                    return ApplyResult(True, stale=True, last_seq=last_seq)
                if any(prior is not None for prior in existing):
                    raise StoreConflict("new event batch contains a previously used event_id")

                for event, digest in zip(events, hashes):
                    if event.op == "ban":
                        current = conn.execute(
                            "SELECT ip FROM claims WHERE client_id=? AND jail=? AND ban_id=?",
                            (client_id, event.jail, event.ban_id),
                        ).fetchone()
                        if current is not None and current["ip"] != event.ip:
                            raise StoreConflict("ban identity cannot change IP")
                        conn.execute(
                            """INSERT INTO claims
                               (client_id,jail,ban_id,ip,permanent,expires_at,updated_at)
                               VALUES (?,?,?,?,?,?,?)
                               ON CONFLICT(client_id,jail,ban_id) DO UPDATE SET
                                 ip=excluded.ip, permanent=excluded.permanent,
                                 expires_at=excluded.expires_at, updated_at=excluded.updated_at""",
                            (
                                client_id,
                                event.jail,
                                event.ban_id,
                                event.ip,
                                int(bool(event.permanent)),
                                event.expires_at,
                                now,
                            ),
                        )
                    else:
                        current = conn.execute(
                            "SELECT ip FROM claims WHERE client_id=? AND jail=? AND ban_id=?",
                            (client_id, event.jail, event.ban_id),
                        ).fetchone()
                        if current is not None and current["ip"] != event.ip:
                            raise StoreConflict("unban IP does not match the existing claim")
                        conn.execute(
                            "DELETE FROM claims WHERE client_id=? AND jail=? AND ban_id=? AND ip=?",
                            (client_id, event.jail, event.ban_id, event.ip),
                        )
                    conn.execute(
                        """INSERT INTO events
                           (client_id,event_id,seq,payload_hash,op,jail,ban_id,ip,received_at)
                           VALUES (?,?,?,?,?,?,?,?,?)""",
                        (
                            client_id,
                            event.event_id,
                            event.seq,
                            digest,
                            event.op,
                            event.jail,
                            event.ban_id,
                            event.ip,
                            now,
                        ),
                    )

                count = conn.execute(
                    "SELECT COUNT(*) FROM claims WHERE client_id=?", (client_id,)
                ).fetchone()[0]
                if count > claims_limit:
                    raise StoreLimit("claims_per_client limit exceeded")
                total = conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
                if total > MAX_TOTAL_CLAIMS:
                    raise StoreLimit("global claim limit exceeded")
                new_seq = events[-1].seq
                conn.execute(
                    "UPDATE client_state SET last_seq=?,updated_at=? WHERE client_id=?",
                    (new_seq, now, client_id),
                )
                conn.execute(
                    """DELETE FROM events WHERE rowid IN (
                         SELECT rowid FROM events WHERE client_id=?
                         ORDER BY received_at DESC,seq DESC LIMIT -1 OFFSET ?
                       )""",
                    (client_id, MAX_HISTORY_EVENTS_PER_CLIENT),
                )
                conn.commit()
                return ApplyResult(True, last_seq=new_seq)
            except Exception:
                conn.rollback()
                raise

    def apply_snapshot(
        self,
        client_id: str,
        snapshot_id: str,
        seq: int,
        claims: Sequence[Claim],
        *,
        claims_limit: int,
    ) -> ApplyResult:
        if len(claims) > claims_limit:
            raise StoreLimit("claims_per_client limit exceeded")
        payload = {
            "snapshot_id": snapshot_id,
            "seq": seq,
            "claims": [claim.wire() for claim in claims],
        }
        digest = _payload_hash(payload)
        now = time.time()
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO client_state(client_id,last_seq,updated_at) VALUES (?,0,?)",
                    (client_id, now),
                )
                last_seq = int(
                    conn.execute(
                        "SELECT last_seq FROM client_state WHERE client_id=?", (client_id,)
                    ).fetchone()["last_seq"]
                )
                prior = conn.execute(
                    "SELECT seq,payload_hash FROM snapshots WHERE client_id=? AND snapshot_id=?",
                    (client_id, snapshot_id),
                ).fetchone()
                if prior is not None and (
                    int(prior["seq"]) != seq or prior["payload_hash"] != digest
                ):
                    raise StoreConflict("snapshot_id was reused with different content")
                if seq <= last_seq:
                    conn.commit()
                    if prior is not None:
                        return ApplyResult(True, duplicate=True, last_seq=last_seq)
                    return ApplyResult(True, stale=True, last_seq=last_seq)

                existing_claims = {
                    (row["jail"], row["ban_id"]): row["ip"]
                    for row in conn.execute(
                        "SELECT jail,ban_id,ip FROM claims WHERE client_id=?", (client_id,)
                    ).fetchall()
                }
                for claim in claims:
                    previous_ip = existing_claims.get((claim.jail, claim.ban_id))
                    if previous_ip is not None and previous_ip != claim.ip:
                        raise StoreConflict("snapshot cannot rebind a claim identity to a new IP")

                conn.execute("DELETE FROM claims WHERE client_id=?", (client_id,))
                conn.executemany(
                    """INSERT INTO claims
                       (client_id,jail,ban_id,ip,permanent,expires_at,updated_at)
                       VALUES (?,?,?,?,?,?,?)""",
                    [
                        (
                            client_id,
                            claim.jail,
                            claim.ban_id,
                            claim.ip,
                            int(claim.permanent),
                            claim.expires_at,
                            now,
                        )
                        for claim in claims
                    ],
                )
                total = conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
                if total > MAX_TOTAL_CLAIMS:
                    raise StoreLimit("global claim limit exceeded")
                conn.execute(
                    "INSERT INTO snapshots(client_id,snapshot_id,seq,payload_hash,received_at) VALUES (?,?,?,?,?)",
                    (client_id, snapshot_id, seq, digest, now),
                )
                conn.execute(
                    "UPDATE client_state SET last_seq=?,updated_at=? WHERE client_id=?",
                    (seq, now, client_id),
                )
                conn.execute(
                    """DELETE FROM snapshots WHERE rowid IN (
                         SELECT rowid FROM snapshots WHERE client_id=?
                         ORDER BY received_at DESC,seq DESC LIMIT -1 OFFSET ?
                       )""",
                    (client_id, MAX_HISTORY_SNAPSHOTS_PER_CLIENT),
                )
                conn.commit()
                return ApplyResult(True, last_seq=seq)
            except Exception:
                conn.rollback()
                raise

    def effective_ips(self, *, now: float | None = None) -> tuple[list[str], list[str]]:
        boundary = time.time() if now is None else now
        with self._connection() as conn:
            rows = conn.execute(
                """SELECT DISTINCT ip FROM claims
                   WHERE permanent=1 AND (expires_at IS NULL OR expires_at>?)""",
                (boundary,),
            ).fetchall()
        v4: set[str] = set()
        v6: set[str] = set()
        for row in rows:
            parsed = ipaddress.ip_address(row["ip"])
            (v4 if parsed.version == 4 else v6).add(parsed.compressed)
        return sorted(v4, key=ipaddress.ip_address), sorted(v6, key=ipaddress.ip_address)

    def client_effective_ips(
        self, client_id: str, *, now: float | None = None
    ) -> tuple[list[str], list[str]]:
        boundary = time.time() if now is None else now
        with self._connection() as conn:
            rows = conn.execute(
                """SELECT DISTINCT ip FROM claims WHERE client_id=? AND permanent=1
                   AND (expires_at IS NULL OR expires_at>?)""",
                (client_id, boundary),
            ).fetchall()
        v4: set[str] = set()
        v6: set[str] = set()
        for row in rows:
            parsed = ipaddress.ip_address(row["ip"])
            (v4 if parsed.version == 4 else v6).add(parsed.compressed)
        return sorted(v4, key=ipaddress.ip_address), sorted(v6, key=ipaddress.ip_address)

    def client_status(self, client_id: str, *, now: float | None = None) -> dict[str, Any]:
        boundary = time.time() if now is None else now
        with self._connection() as conn:
            state = conn.execute(
                "SELECT last_seq,updated_at FROM client_state WHERE client_id=?", (client_id,)
            ).fetchone()
            totals = conn.execute(
                """SELECT COUNT(*) AS total,
                          COALESCE(SUM(CASE WHEN permanent=1 AND
                            (expires_at IS NULL OR expires_at>?) THEN 1 ELSE 0 END),0) AS effective
                   FROM claims WHERE client_id=?""",
                (boundary, client_id),
            ).fetchone()
            enforcement = conn.execute(
                "SELECT last_attempt,last_success,last_error FROM enforcement_state WHERE singleton=1"
            ).fetchone()
        return {
            "client_id": client_id,
            "last_seq": int(state["last_seq"]) if state else 0,
            "claim_count": int(totals["total"]),
            "effective_claim_count": int(totals["effective"]),
            "updated_at": state["updated_at"] if state else None,
            "enforcement": {
                "last_attempt": enforcement["last_attempt"],
                "last_success": enforcement["last_success"],
                "last_error": enforcement["last_error"],
            },
        }

    def record_enforcement_attempt(self, desired_digest: str) -> None:
        with self._connection() as conn:
            conn.execute(
                """UPDATE enforcement_state SET desired_digest=?,last_attempt=?
                   WHERE singleton=1""",
                (desired_digest, time.time()),
            )

    def record_enforcement_success(
        self, *, desired_digest: str, applied_digest: str | None, ipv4: int, ipv6: int
    ) -> None:
        now = time.time()
        with self._connection() as conn:
            conn.execute(
                """UPDATE enforcement_state SET desired_digest=?,applied_digest=?,
                   applied_ipv4=?,applied_ipv6=?,last_attempt=?,last_success=?,last_error=NULL
                   WHERE singleton=1""",
                (desired_digest, applied_digest, ipv4, ipv6, now, now),
            )

    def record_enforcement_failure(self, desired_digest: str, error: str) -> None:
        with self._connection() as conn:
            conn.execute(
                """UPDATE enforcement_state SET desired_digest=?,last_attempt=?,last_error=?
                   WHERE singleton=1""",
                (desired_digest, time.time(), error[:1024]),
            )

    def prune_history(self, *, now: float | None = None) -> int:
        boundary = (time.time() if now is None else now) - self.history_days * 86400
        with self._connection() as conn:
            first = conn.execute("DELETE FROM events WHERE received_at<?", (boundary,)).rowcount
            second = conn.execute("DELETE FROM snapshots WHERE received_at<?", (boundary,)).rowcount
        return first + second
