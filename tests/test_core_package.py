from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.build_lab_package import BuildError, Target, build_bundle
from tools.prepare_port import PortError, prepare_port
from f2bguard import __version__


ROOT = Path(__file__).resolve().parents[1]
TARGET = Target("FreeBSD:16:amd64", "3.11", "3.11.15_3", "3.11.15_10")


class PackageStagingTest(unittest.TestCase):
    def test_versions_and_ci_security_contract_match(self):
        makefile = (ROOT / "pfsense/Makefile").read_text()
        workflow = (ROOT / ".github/workflows/build-package.yml").read_text()
        builder = (ROOT / "tools/ci_freebsd16_package.sh").read_text()

        self.assertIn(f"PORTVERSION=    {__version__}", makefile)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertEqual(workflow.count("persist-credentials: false"), 2)
        self.assertNotIn("self-hosted", workflow)
        self.assertNotIn("artifacts/*\n", workflow)
        self.assertIn("127.0.0.1:2222", builder)
        self.assertIn("make PORTSDIR=/tmp/ports package", builder)
        self.assertIn("'FreeBSD:16:*'", builder)
        self.assertNotIn("/Latest/", builder)

    def test_generated_port_is_self_contained(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "pfSense-pkg-f2bguard"
            port = prepare_port(ROOT, output)
            makefile = (port / "Makefile").read_text()

            self.assertIn("PORTVERSION=    0.1.7", makefile)
            self.assertIn("mediaburg@users.noreply.github.com", makefile)
            self.assertIn("${FILESDIR}${DATADIR}/f2bguard/*.py", makefile)
            self.assertNotIn("../src", makefile)
            self.assertEqual(
                sorted(path.name for path in (port / "files/usr/local/share/f2bguard/f2bguard").glob("*.py")),
                sorted(path.name for path in (ROOT / "src/f2bguard").glob("*.py")),
            )
            with self.assertRaises(PortError):
                prepare_port(ROOT, output)

    def test_stages_exact_payload_disabled_defaults_and_native_hooks(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, archive = build_bundle(ROOT, Path(directory) / "bundle", TARGET)
            manifest = json.loads((bundle / "metadata/+MANIFEST").read_text())

            self.assertTrue(archive.is_file())
            self.assertEqual(manifest["name"], "pfSense-pkg-f2bguard")
            self.assertEqual(manifest["maintainer"], "mediaburg@users.noreply.github.com")
            self.assertEqual(manifest["abi"], "FreeBSD:16:*")
            self.assertEqual(manifest["deps"]["python311"]["version"], "3.11.15_3")
            self.assertEqual(manifest["deps"]["py311-sqlite3"]["version"], "3.11.15_10")
            self.assertEqual(
                set(manifest["scripts"]),
                {"post-install", "pre-deinstall", "post-deinstall"},
            )
            self.assertIn("pfSense-pkg-f2bguard POST-INSTALL", manifest["scripts"]["post-install"])
            self.assertIn("pfSense-pkg-f2bguard DEINSTALL", manifest["scripts"]["pre-deinstall"])
            self.assertIn("pfSense-pkg-f2bguard POST-DEINSTALL", manifest["scripts"]["post-deinstall"])

            rc = (bundle / "stage/usr/local/etc/rc.d/f2bguard").read_text()
            integration = (bundle / "stage/usr/local/pkg/f2bguard.inc").read_text()
            self.assertIn('python="/usr/local/bin/python3.11"', rc)
            self.assertIn('f2bguard_enable:="NO"', rc)
            self.assertNotIn("/usr/bin/ps", rc)
            self.assertIn('/bin/ps -p "${_pid}"', rc)
            self.assertIn("f2bguard_wait_running", rc)
            self.assertIn('f2bguard_wait_running()\n{\n\t_pidfile="$1"\n\t# Let daemon finish exec', rc)
            self.assertIn("\t/bin/sleep 1\n\t_i=0", rc)
            self.assertIn("PF helper failed its startup check.", rc)
            self.assertIn("API server failed its startup check", rc)
            self.assertIn("'enabled' => false", integration)
            self.assertFalse(any(bundle.joinpath("stage").rglob("*.pyc")))

            remote = (bundle / "build-on-pfsense.sh").read_text()
            self.assertIn('pkg create -f txz', remote)
            self.assertNotIn("pkg install", remote)
            self.assertNotIn("pkg add", remote)
            for tool in (
                "/bin/sh", "/bin/cat", "/bin/ps", "/usr/bin/grep", "/usr/bin/logger",
                "/bin/kill", "/bin/mkdir", "/usr/sbin/chown", "/bin/chmod", "/bin/sleep",
                "/bin/rm", "/usr/sbin/daemon", "/usr/bin/env", "/sbin/pfctl", "/usr/sbin/service",
            ):
                self.assertIn(tool, remote)

    def test_archive_is_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            _, first = build_bundle(ROOT, Path(directory) / "one", TARGET)
            _, second = build_bundle(ROOT, Path(directory) / "two", TARGET)
            self.assertEqual(
                hashlib.sha256(first.read_bytes()).digest(),
                hashlib.sha256(second.read_bytes()).digest(),
            )

    def test_refuses_wildcard_target_or_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            with self.assertRaises(BuildError):
                build_bundle(
                    ROOT,
                    output,
                    Target("FreeBSD:16:*", "3.11", "3.11.15_3", "3.11.15_10"),
                )
            build_bundle(ROOT, output, TARGET)
            with self.assertRaises(BuildError):
                build_bundle(ROOT, output, TARGET)


if __name__ == "__main__":
    unittest.main()
