import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from client.sender import (
    EnumerationError,
    PermanentJail,
    SenderConfig,
    SenderStore,
    SnapshotRace,
    Worker,
    enumerate_permanent_jails,
)


class _Transport:
    def __init__(self, failures=0):
        self.failures = failures
        self.payloads = []

    def send(self, payload):
        if self.failures:
            self.failures -= 1
            raise OSError("network interrupted")
        self.payloads.append(payload)


def _config(tmp: Path) -> SenderConfig:
    return SenderConfig(
        database=str(tmp / "sender.sqlite"),
        endpoint="https://guard.example/v1",
        ca="/tmp/ca.pem",
        cert="/tmp/client.pem",
        key="/tmp/client.key",
        permanent_jails=(PermanentJail("recidive"),),
        initial_backoff=1,
        max_backoff=10,
    )


class SenderStoreTests(unittest.TestCase):
    def test_sequence_survives_restart_and_ban_unban_order(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sender.sqlite"
            store = SenderStore(path)
            ban = store.enqueue("ban", "recidive", "203.0.113.1", now=0)
            unban = store.enqueue("unban", "recidive", "203.0.113.1", now=0)
            store.close()
            restarted = SenderStore(path)
            reban = restarted.enqueue("ban", "recidive", "203.0.113.1", now=0)
            pending = restarted.pending()
            restarted.close()
        self.assertEqual([ban["seq"], unban["seq"], reban["seq"]], [1, 2, 3])
        self.assertEqual(unban["ban_id"], ban["ban_id"])
        self.assertNotEqual(reban["ban_id"], ban["ban_id"])
        self.assertEqual([json.loads(row["payload"])["op"] for row in pending], ["ban", "unban", "ban"])

    def test_interrupted_delivery_keeps_event_for_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            config = _config(Path(directory))
            store = SenderStore(config.database)
            store.enqueue("ban", "recidive", "2001:db8::1", now=0)
            transport = _Transport(failures=1)
            worker = Worker(config, store, transport)
            self.assertFalse(worker.process_once(now=0))
            self.assertEqual(len(store.pending()), 1)
            self.assertTrue(worker.process_once(now=1))
            self.assertEqual(len(store.pending()), 0)
            store.close()

    def test_snapshot_sequence_fence_rejects_hook_race(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SenderStore(Path(directory) / "sender.sqlite")
            observed = store.current_seq()
            store.enqueue("ban", "recidive", "203.0.113.2", now=0)
            with self.assertRaises(SnapshotRace):
                store.enqueue_snapshot([], now=0, expected_seq=observed)
            self.assertEqual([json.loads(row["payload"])["op"] for row in store.pending()], ["ban"])
            store.close()


class EnumerationTests(unittest.TestCase):
    def test_command_failure_does_not_produce_empty_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            config = _config(Path(directory))

            def runner(*args, **kwargs):
                return subprocess.CompletedProcess(args[0], 1, "", "failure")

            with self.assertRaises(EnumerationError):
                enumerate_permanent_jails(config, runner)

    def test_only_literal_ips_from_configured_permanent_jails(self):
        with tempfile.TemporaryDirectory() as directory:
            config = _config(Path(directory))

            def runner(*args, **kwargs):
                self.assertEqual(args[0][1:], ["get", "recidive", "banip", "--with-time"])
                return subprocess.CompletedProcess(
                    args[0], 0,
                    "203.0.113.1 \t2025-01-01 00:00:00 + -1 = 9999-12-31 23:59:59\n"
                    "2001:db8::1 \t2025-01-01 00:00:00 + -1 = 9999-12-31 23:59:59\n",
                    "",
                )

            claims = enumerate_permanent_jails(config, runner)
            self.assertEqual([claim["ip"] for claim in claims], ["203.0.113.1", "2001:db8::1"])

    def test_temporary_ticket_in_permanent_jail_is_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            config = _config(Path(directory))

            def runner(*args, **kwargs):
                return subprocess.CompletedProcess(
                    args[0], 0,
                    "203.0.113.1 \t2025-01-01 00:00:00 + 600 = 2025-01-01 00:10:00\n",
                    "",
                )

            self.assertEqual(enumerate_permanent_jails(config, runner), [])


class ActionConfigTests(unittest.TestCase):
    def test_bulk_flush_is_acknowledged_without_per_ip_unbans(self):
        action = Path(__file__).parents[1] / "client" / "f2bguard-action.conf"
        text = action.read_text(encoding="utf-8")
        self.assertIn("actionflush = /usr/bin/true", text)
        self.assertIn("actionunban =", text)


if __name__ == "__main__":
    unittest.main()
