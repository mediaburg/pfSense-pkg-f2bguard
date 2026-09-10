from __future__ import annotations

import ipaddress
import socket
import tempfile
import threading
import unittest
import uuid
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace

from f2bguard.config import Config, ConfigError, load_config, parse_config, strict_json_loads
from f2bguard.networks import NetworkIndex
from f2bguard.server import (
    Enforcer,
    EnforcementError,
    GuardHTTPServer,
    GuardHandler,
    HelperClient,
    RateLimiter,
    parse_whitelist,
)
from f2bguard.store import ClaimStore


class FakeHelper:
    def __init__(self):
        self.calls = []

    def replace(self, ipv4, ipv6):
        self.calls.append((ipv4, ipv6))
        return {
            "ok": True,
            "applied_ipv4": len(ipv4),
            "applied_ipv6": len(ipv6),
            "digest": "0" * 64,
        }


class SecurityTest(unittest.TestCase):
    def test_server_rebinds_after_accepted_connection_but_not_while_live(self):
        accepted = threading.Event()

        class ClosingGuardHTTPServer(GuardHTTPServer):
            def process_request_thread(self, request, client_address):
                try:
                    accepted.set()
                finally:
                    self.shutdown_request(request)
                    self._worker_slots.release()

        with tempfile.TemporaryDirectory() as directory:
            config = Config(database=str(Path(directory) / "state.sqlite"))
            first = ClosingGuardHTTPServer(("127.0.0.1", 0), GuardHandler, config)
            address = first.server_address
            thread = threading.Thread(target=first.serve_forever, daemon=True)
            thread.start()
            try:
                with self.assertRaises(OSError):
                    ClosingGuardHTTPServer(address, GuardHandler, config)
                with socket.create_connection(address, timeout=2) as connection:
                    self.assertTrue(accepted.wait(2))
                    while connection.recv(1024):
                        pass
            finally:
                first.shutdown()
                first.server_close()
                thread.join(timeout=2)

            rebound = ClosingGuardHTTPServer(address, GuardHandler, config)
            rebound.server_close()

    def test_status_uses_whitelist_filtered_effective_ip_count(self):
        response = []
        client = SimpleNamespace(id="server-a")
        handler = object.__new__(GuardHandler)
        handler.path = "/v1/status"
        handler.server = SimpleNamespace(
            store=SimpleNamespace(
                client_status=lambda client_id: {
                    "client_id": client_id,
                    "claim_count": 1,
                    "effective_claim_count": 1,
                }
            ),
            enforcer=SimpleNamespace(client_effective_count=lambda client_id: 0),
        )
        handler._authorize = lambda: client
        handler._json = lambda status, body: response.append((status, body))

        handler.do_GET()

        self.assertEqual(
            response,
            [
                (
                    HTTPStatus.OK,
                    {"client_id": "server-a", "claim_count": 1, "effective_ip_count": 0},
                )
            ],
        )

    def test_empty_client_effective_count_does_not_require_loaded_whitelist(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ClaimStore(Path(directory) / "state.sqlite")
            enforcer = Enforcer(store, "/unused", FakeHelper())  # type: ignore[arg-type]

            self.assertEqual(enforcer.client_effective_count("new-client"), 0)

    def test_network_index_merges_overlaps_and_handles_family_boundaries(self):
        index = NetworkIndex(
            [
                ipaddress.ip_network("192.0.2.0/25"),
                ipaddress.ip_network("192.0.2.64/26"),
                ipaddress.ip_network("192.0.2.128/25"),
                ipaddress.ip_network("2001:db8::/127"),
                ipaddress.ip_network("2001:db8::2/127"),
            ]
        )

        self.assertEqual(len(index), 2)
        for address in ("192.0.2.0", "192.0.2.255", "2001:db8::", "2001:db8::3"):
            self.assertTrue(index.contains(address))
        for address in ("192.0.1.255", "192.0.3.0", "2001:db7::ffff", "2001:db8::4"):
            self.assertFalse(index.contains(address))
        self.assertEqual(index.exclude(["192.0.2.1", "198.51.100.1"]), ["198.51.100.1"])

    def test_network_index_handles_many_disjoint_intervals(self):
        networks = [
            ipaddress.ip_network(f"10.{second}.{third}.0/24")
            for second in range(40)
            for third in range(0, 256, 2)
        ]
        index = NetworkIndex(networks)

        self.assertEqual(len(index), len(networks))
        self.assertTrue(index.contains("10.39.254.255"))
        self.assertFalse(index.contains("10.39.255.0"))
        self.assertFalse(index.contains("2001:db8::1"))

    def test_config_defaults_disabled_and_rejects_wildcard(self):
        self.assertFalse(parse_config({}) .enabled)
        with self.assertRaises(ConfigError):
            parse_config({"listen": "0.0.0.0"})

    def test_config_rejects_fingerprint_shared_by_clients(self):
        fingerprint = "a" * 64
        raw = {
            "clients": [
                {"id": "a", "cert_sha256": [fingerprint], "allowed_jails": ["recidive"]},
                {"id": "b", "cert_sha256": [fingerprint], "allowed_jails": ["recidive"]},
            ]
        }
        with self.assertRaises(ConfigError):
            parse_config(raw)

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(ConfigError):
            strict_json_loads('{"events":[],"events":[]}')

    def test_config_loader_rejects_service_writable_trust_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text("{}", encoding="ascii")
            path.chmod(0o640)
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_whitelist_excludes_claim_without_creating_pass_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ClaimStore(Path(directory) / "state.sqlite")
            raw = {
                "event_id": str(uuid.uuid4()),
                "seq": 1,
                "op": "ban",
                "jail": "recidive",
                "ban_id": str(uuid.uuid4()),
                "ip": "203.0.113.25",
                "permanent": True,
                "expires_at": None,
            }
            events = store.validate_events([raw], 10)
            store.apply_events("server-a", events, claims_limit=10)
            helper = FakeHelper()
            enforcer = Enforcer(store, "/unused", helper)  # type: ignore[arg-type]
            networks = (ipaddress.ip_network("203.0.113.0/24"),)

            def reload_valid():
                enforcer.whitelist.last_valid = networks
                return networks

            enforcer.whitelist.reload = reload_valid

            self.assertEqual(enforcer.enforce(), 0)
            self.assertEqual(helper.calls, [([], [])])
            self.assertEqual(enforcer.client_effective_count("server-a"), 0)

    def test_invalid_whitelist_preserves_last_applied_state_and_skips_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ClaimStore(Path(directory) / "state.sqlite")
            helper = FakeHelper()
            enforcer = Enforcer(store, "/unused", helper)  # type: ignore[arg-type]
            enforcer.whitelist.reload = lambda: ()
            enforcer.enforce()
            before = store.client_status("server-a")["enforcement"]["last_success"]

            def invalid():
                raise EnforcementError("invalid whitelist")

            enforcer.whitelist.reload = invalid
            with self.assertRaises(EnforcementError):
                enforcer.enforce()

            status = store.client_status("server-a")["enforcement"]
            self.assertEqual(len(helper.calls), 1)
            self.assertEqual(status["last_success"], before)
            self.assertEqual(status["last_error"], "invalid whitelist")

    def test_whitelist_parser_is_all_or_nothing(self):
        with self.assertRaises(EnforcementError):
            parse_whitelist(b"203.0.113.0/24\nnot-a-network\n")

    def test_helper_retries_and_requires_applied_counts(self):
        class Stub(HelperClient):
            def __init__(self):
                super().__init__("/unused", retries=3)
                self.attempts = 0

            def _exchange(self, request):
                self.attempts += 1
                if self.attempts < 3:
                    raise OSError("offline")
                return {"ok": True, "applied_ipv4": 1, "applied_ipv6": 0}

        helper = Stub()
        self.assertEqual(helper.replace(["203.0.113.1"], [])["applied_ipv4"], 1)
        self.assertEqual(helper.attempts, 3)
        with self.assertRaises(EnforcementError):
            HelperClient._validate_response({"ok": True})

    def test_rate_limit_uses_strict_rolling_boundary(self):
        limiter = RateLimiter(2)
        self.assertTrue(limiter.allow("a", now=0))
        self.assertTrue(limiter.allow("a", now=1))
        self.assertFalse(limiter.allow("a", now=59.999))
        self.assertTrue(limiter.allow("a", now=60))
        self.assertTrue(limiter.allow("b", now=60))


if __name__ == "__main__":
    unittest.main()
