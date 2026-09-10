from __future__ import annotations

import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from f2bguard.store import ClaimStore, StoreConflict, StoreLimit, ValidationError


def uid(number: int) -> str:
    return str(uuid.UUID(int=number))


def event(
    number: int,
    seq: int,
    op: str,
    ban_number: int,
    ip: str,
    *,
    permanent: bool | None = True,
    expires_at=None,
):
    value = {
        "event_id": uid(number),
        "seq": seq,
        "op": op,
        "jail": "recidive",
        "ban_id": uid(ban_number),
        "ip": ip,
        "expires_at": expires_at,
    }
    if permanent is not None:
        value["permanent"] = permanent
    return value


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = ClaimStore(Path(self.temp.name) / "state.sqlite")

    def parsed(self, *values):
        return self.store.validate_events(list(values), 100)

    def apply(self, client, *values):
        return self.store.apply_events(client, self.parsed(*values), claims_limit=100)

    def test_unban_is_scoped_to_authenticated_client(self):
        self.apply("server-a", event(1, 1, "ban", 10, "203.0.113.8"))
        self.apply(
            "server-b",
            event(2, 1, "unban", 10, "203.0.113.8", permanent=None),
        )

        self.assertEqual(self.store.effective_ips()[0], ["203.0.113.8"])
        self.assertEqual(self.store.client_status("server-a")["claim_count"], 1)
        self.assertEqual(self.store.client_status("server-b")["claim_count"], 0)

    def test_stale_snapshot_is_acknowledged_without_resurrecting_or_deleting(self):
        self.apply("server-a", event(3, 5, "ban", 11, "203.0.113.9"))
        snapshot_id, seq, claims = self.store.validate_snapshot(uid(20), 4, [], 100)

        result = self.store.apply_snapshot(
            "server-a", snapshot_id, seq, claims, claims_limit=100
        )

        self.assertTrue(result.accepted)
        self.assertTrue(result.stale)
        self.assertEqual(result.last_seq, 5)
        self.assertEqual(self.store.effective_ips()[0], ["203.0.113.9"])

    def test_batch_crossing_stored_sequence_boundary_is_rejected_atomically(self):
        self.apply("server-a", event(50, 2, "ban", 50, "203.0.113.50"))
        crossing = self.parsed(
            event(51, 1, "unban", 50, "203.0.113.50", permanent=None),
            event(52, 3, "ban", 52, "203.0.113.52"),
        )

        with self.assertRaises(StoreConflict):
            self.store.apply_events("server-a", crossing, claims_limit=100)

        self.assertEqual(self.store.client_status("server-a")["last_seq"], 2)
        self.assertEqual(self.store.effective_ips()[0], ["203.0.113.50"])

    def test_duplicate_retry_has_no_effect_and_reuse_with_new_content_conflicts(self):
        original = event(4, 1, "ban", 12, "203.0.113.10")
        first = self.apply("server-a", original)
        second = self.apply("server-a", original)

        self.assertTrue(first.accepted)
        self.assertTrue(second.duplicate)
        self.assertEqual(self.store.client_status("server-a")["claim_count"], 1)

        changed = event(4, 1, "ban", 12, "203.0.113.11")
        with self.assertRaises(StoreConflict):
            self.apply("server-a", changed)
        self.assertEqual(self.store.effective_ips()[0], ["203.0.113.10"])

    def test_malformed_semantic_batch_rolls_back_atomically(self):
        values = self.parsed(
            event(5, 1, "ban", 13, "203.0.113.12"),
            event(6, 2, "unban", 13, "203.0.113.13", permanent=None),
        )

        with self.assertRaises(StoreConflict):
            self.store.apply_events("server-a", values, claims_limit=100)

        self.assertEqual(self.store.client_status("server-a")["last_seq"], 0)
        self.assertEqual(self.store.client_status("server-a")["claim_count"], 0)

    def test_ban_identity_cannot_be_rebound_to_a_different_ip(self):
        self.apply("server-a", event(7, 1, "ban", 14, "203.0.113.14"))
        with self.assertRaises(StoreConflict):
            self.apply("server-a", event(8, 2, "ban", 14, "203.0.113.15"))
        self.assertEqual(self.store.effective_ips()[0], ["203.0.113.14"])
        self.assertEqual(self.store.client_status("server-a")["last_seq"], 1)

    def test_non_permanent_claim_never_escalates(self):
        self.apply(
            "server-a",
            event(9, 1, "ban", 15, "203.0.113.16", permanent=False),
        )

        self.assertEqual(self.store.client_status("server-a")["claim_count"], 1)
        self.assertEqual(self.store.effective_ips(), ([], []))

    def test_expiry_boundary_is_strict(self):
        self.apply(
            "server-a",
            event(10, 1, "ban", 16, "203.0.113.17", expires_at=1000),
        )

        self.assertEqual(self.store.effective_ips(now=999)[0], ["203.0.113.17"])
        self.assertEqual(self.store.effective_ips(now=1000), ([], []))
        self.assertEqual(self.store.effective_ips(now=1001), ([], []))

    def test_full_snapshot_atomically_replaces_only_its_client(self):
        self.apply("server-a", event(11, 1, "ban", 17, "203.0.113.18"))
        self.apply("server-b", event(12, 1, "ban", 18, "203.0.113.19"))
        snapshot_id, seq, claims = self.store.validate_snapshot(
            uid(21),
            2,
            [
                {
                    "jail": "recidive",
                    "ban_id": uid(19),
                    "ip": "2001:db8::20",
                    "permanent": True,
                    "expires_at": None,
                }
            ],
            100,
        )
        self.store.apply_snapshot("server-a", snapshot_id, seq, claims, claims_limit=100)

        self.assertEqual(self.store.effective_ips(), (["203.0.113.19"], ["2001:db8::20"]))

    def test_snapshot_cannot_rebind_existing_identity(self):
        self.apply("server-a", event(60, 1, "ban", 60, "203.0.113.60"))
        snapshot_id, seq, claims = self.store.validate_snapshot(
            uid(61),
            2,
            [{
                "jail": "recidive",
                "ban_id": uid(60),
                "ip": "203.0.113.61",
                "permanent": True,
                "expires_at": None,
            }],
            100,
        )

        with self.assertRaises(StoreConflict):
            self.store.apply_snapshot("server-a", snapshot_id, seq, claims, claims_limit=100)
        self.assertEqual(self.store.client_status("server-a")["last_seq"], 1)
        self.assertEqual(self.store.effective_ips()[0], ["203.0.113.60"])

    def test_global_claim_limit_rolls_back_events_and_snapshots(self):
        with mock.patch("f2bguard.store.MAX_TOTAL_CLAIMS", 1):
            self.apply("server-a", event(70, 1, "ban", 70, "203.0.113.70"))
            with self.assertRaises(StoreLimit):
                self.apply("server-b", event(71, 1, "ban", 71, "203.0.113.71"))
            snapshot_id, seq, claims = self.store.validate_snapshot(
                uid(72),
                1,
                [{
                    "jail": "recidive",
                    "ban_id": uid(72),
                    "ip": "203.0.113.72",
                    "permanent": True,
                    "expires_at": None,
                }],
                100,
            )
            with self.assertRaises(StoreLimit):
                self.store.apply_snapshot("server-c", snapshot_id, seq, claims, claims_limit=100)

        self.assertEqual(self.store.client_status("server-b")["last_seq"], 0)
        self.assertEqual(self.store.client_status("server-c")["last_seq"], 0)
        self.assertEqual(self.store.effective_ips()[0], ["203.0.113.70"])

    def test_invalid_address_classes_are_rejected_before_persistence(self):
        for address in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "fe80::1", "::ffff:192.0.2.1"):
            with self.subTest(address=address), self.assertRaises(ValidationError):
                self.parsed(event(30, 1, "ban", 30, address))

    def test_syntactically_malformed_batch_is_validated_before_any_write(self):
        good = event(40, 1, "ban", 40, "203.0.113.40")
        bad = event(41, 2, "ban", 41, "not-an-ip")
        with self.assertRaises(ValidationError):
            self.store.validate_events([good, bad], 100)
        self.assertEqual(self.store.client_status("server-a")["last_seq"], 0)


if __name__ == "__main__":
    unittest.main()
