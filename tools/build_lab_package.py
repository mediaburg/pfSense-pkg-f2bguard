#!/usr/bin/env python3
"""Stage a pfSense lab package bundle for a matching FreeBSD target.

This tool never contacts a firewall, installs a package, or runs lifecycle
hooks. It creates a transferable source/stage archive containing an explicit
manifest and a guarded FreeBSD script which runs only ``pkg create``.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path


PACKAGE_NAME = "pfSense-pkg-f2bguard"
PACKAGE_ORIGIN = "security/pfSense-pkg-f2bguard"
PACKAGE_PREFIX = "/usr/local"
SAFE_VERSION = re.compile(r"^[0-9][A-Za-z0-9._,+-]*$")
SAFE_ABI = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*:[0-9]+:[A-Za-z0-9_.*-]+$")
SAFE_PYTHON = re.compile(r"^3\.[0-9]{1,2}$")
PLACEHOLDERS = (b"%%PKGVERSION%%", b"%%PYTHON_CMD%%", b"%%PORTNAME%%")


class BuildError(RuntimeError):
    pass


@dataclass(frozen=True)
class Target:
    abi: str
    python_version: str
    python_package_version: str
    sqlite_package_version: str

    @property
    def python_flavor(self) -> str:
        return self.python_version.replace(".", "")

    @property
    def python_command(self) -> str:
        return f"/usr/local/bin/python{self.python_version}"

    @property
    def package_abi(self) -> str:
        os_name, major, _architecture = self.abi.split(":", 2)
        return f"{os_name}:{major}:*"


def _validate_target(target: Target) -> None:
    if not SAFE_ABI.fullmatch(target.abi) or "*" in target.abi:
        raise BuildError("--abi must be an exact target ABI such as FreeBSD:16:amd64")
    if not SAFE_PYTHON.fullmatch(target.python_version):
        raise BuildError("--python-version must be a major.minor value such as 3.11")
    for label, value in (
        ("--python-package-version", target.python_package_version),
        ("--sqlite-package-version", target.sqlite_package_version),
    ):
        if not SAFE_VERSION.fullmatch(value):
            raise BuildError(f"{label} is not a safe package version")


def _port_version(repo: Path) -> str:
    matches = re.findall(
        r"^PORTVERSION\s*=\s*([^\s#]+)",
        (repo / "pfsense" / "Makefile").read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if len(matches) != 1 or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", matches[0]):
        raise BuildError("pfsense/Makefile must define one numeric PORTVERSION")
    return matches[0]


def _write(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def _substitute(data: bytes, *, version: str, target: Target) -> bytes:
    return (
        data.replace(b"%%PKGVERSION%%", version.encode("ascii"))
        .replace(b"%%PYTHON_CMD%%", target.python_command.encode("ascii"))
        .replace(b"%%PORTNAME%%", PACKAGE_NAME.encode("ascii"))
    )


def _payload(repo: Path, stage: Path, version: str, target: Target) -> list[str]:
    source_root = repo / "pfsense" / "files"
    paths: list[str] = []
    for source in sorted(source_root.rglob("*")):
        if not source.is_file() or source.name in {"pkg-install.in", "pkg-deinstall.in"}:
            continue
        relative = source.relative_to(source_root)
        destination = stage / relative
        mode = 0o555 if relative == Path("usr/local/etc/rc.d/f2bguard") else 0o644
        _write(destination, _substitute(source.read_bytes(), version=version, target=target), mode)
        paths.append("/" + relative.as_posix())

    for source in sorted((repo / "src" / "f2bguard").glob("*.py")):
        relative = Path("usr/local/share/f2bguard/f2bguard") / source.name
        _write(stage / relative, source.read_bytes(), 0o644)
        paths.append("/" + relative.as_posix())
    return sorted(paths)


def _expected_plist(repo: Path) -> list[str]:
    prefix = "/usr/local"
    result: list[str] = []
    for raw in (repo / "pfsense" / "pkg-plist").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("@cwd "):
            prefix = line[5:].replace("%%PREFIX%%", PACKAGE_PREFIX)
            continue
        if line.startswith("@"):
            continue
        result.append((prefix.rstrip("/") + "/" + line.lstrip("/")).replace("//", "/"))
    return sorted(result)


def _lifecycle_scripts() -> dict[str, str]:
    command = '"${PKG_ROOTDIR}/usr/local/bin/php" -f "${PKG_ROOTDIR}/etc/rc.packages"'
    return {
        "post-install": f"#!/bin/sh\n{command} {PACKAGE_NAME} POST-INSTALL\n",
        "pre-deinstall": f"#!/bin/sh\n{command} {PACKAGE_NAME} DEINSTALL\n",
        "post-deinstall": f"#!/bin/sh\n{command} {PACKAGE_NAME} POST-DEINSTALL\n",
    }


def _manifest(repo: Path, stage: Path, paths: list[str], version: str, target: Target) -> dict:
    flat_size = sum((stage / path.lstrip("/")).stat().st_size for path in paths)
    flavor = target.python_flavor
    return {
        "name": PACKAGE_NAME,
        "version": version,
        "origin": PACKAGE_ORIGIN,
        "comment": "pfSense integration for Fail2Ban Guard",
        "desc": (repo / "pfsense" / "pkg-descr").read_text(encoding="utf-8").strip(),
        "maintainer": "mediaburg@users.noreply.github.com",
        "prefix": PACKAGE_PREFIX,
        "abi": target.package_abi,
        "arch": target.package_abi.lower(),
        "licenselogic": "single",
        "licenses": ["BSD2CLAUSE"],
        "categories": ["security"],
        "flatsize": flat_size,
        "deps": {
            f"python{flavor}": {
                "origin": f"lang/python{flavor}",
                "version": target.python_package_version,
            },
            f"py{flavor}-sqlite3": {
                "origin": "databases/py-sqlite3",
                "version": target.sqlite_package_version,
            },
        },
        "scripts": _lifecycle_scripts(),
    }


def _remote_builder(target: Target, version: str) -> str:
    flavor = target.python_flavor
    expected_package = f"{PACKAGE_NAME}-{version}.pkg"
    return f'''#!/bin/sh
# Run as root on the intended pfSense target. Creates an archive only; never installs it.
set -eu
bundle=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ "$(uname -s)" = FreeBSD ] || {{ echo "FreeBSD target required" >&2; exit 1; }}
[ "$(pkg config ABI)" = {target.abi!r} ] || {{ echo "Target ABI mismatch" >&2; exit 1; }}
for tool in /bin/sh /bin/cat /bin/ps /usr/bin/grep /usr/bin/logger /bin/kill /bin/mkdir /usr/sbin/chown /bin/chmod /bin/sleep /bin/rm /usr/sbin/daemon /usr/bin/env /sbin/pfctl /usr/sbin/service; do
    [ -x "$tool" ] || {{ echo "Required runtime command is missing or not executable: $tool" >&2; exit 1; }}
done
[ -r /etc/rc.subr ] || {{ echo "Required rc framework is missing: /etc/rc.subr" >&2; exit 1; }}
[ -x /etc/rc.filter_configure_sync ] || {{ echo "Required pfSense filter entry point is missing" >&2; exit 1; }}
[ "$("{target.python_command}" -c 'import sys; print(f"{{sys.version_info.major}}.{{sys.version_info.minor}}")')" = {target.python_version!r} ] || {{ echo "Python version mismatch" >&2; exit 1; }}
"{target.python_command}" -c 'import hashlib, http.server, ipaddress, json, socket, sqlite3, ssl'
[ "$(pkg query '%v' python{flavor})" = {target.python_package_version!r} ] || {{ echo "python{flavor} package version mismatch" >&2; exit 1; }}
[ "$(pkg query '%v' py{flavor}-sqlite3)" = {target.sqlite_package_version!r} ] || {{ echo "py{flavor}-sqlite3 package version mismatch" >&2; exit 1; }}
mkdir -p "$bundle/output"
[ ! -e "$bundle/output/{expected_package}" ] || {{ echo "Refusing to overwrite existing package" >&2; exit 1; }}
pkg create -f txz -m "$bundle/metadata" -r "$bundle/stage" -p "$bundle/plist" -o "$bundle/output"
package="$bundle/output/{expected_package}"
[ -f "$package" ] || {{ echo "pkg create did not produce expected artifact" >&2; exit 1; }}
pkg query -F "$package" '%n-%v %q'
sha256 -q "$package"
printf 'Created only; package was not installed: %s\n' "$package"
'''


def _validate_stage(repo: Path, bundle: Path, paths: list[str]) -> None:
    expected = _expected_plist(repo)
    if paths != expected:
        missing = sorted(set(expected) - set(paths))
        extra = sorted(set(paths) - set(expected))
        raise BuildError(f"pkg-plist mismatch; missing={missing}, extra={extra}")
    for path in paths:
        data = (bundle / "stage" / path.lstrip("/")).read_bytes()
        if any(marker in data for marker in PLACEHOLDERS):
            raise BuildError(f"unexpanded placeholder in {path}")
    integration = (bundle / "stage/usr/local/pkg/f2bguard.inc").read_text(encoding="utf-8")
    rc_script = (bundle / "stage/usr/local/etc/rc.d/f2bguard").read_text(encoding="utf-8")
    if "'enabled' => false" not in integration or 'f2bguard_enable:="NO"' not in rc_script:
        raise BuildError("package no longer has a verifiable disabled default")


def _deterministic_archive(bundle: Path, archive: Path) -> None:
    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for path in sorted(bundle.rglob("*"), key=lambda item: item.relative_to(bundle).as_posix()):
                    relative = Path("f2bguard-lab-package") / path.relative_to(bundle)
                    info = tar.gettarinfo(str(path), arcname=relative.as_posix())
                    info.uid = 0
                    info.gid = 0
                    info.uname = "root"
                    info.gname = "wheel"
                    info.mtime = 0
                    with path.open("rb") if path.is_file() else _null_context() as source:
                        tar.addfile(info, source if path.is_file() else None)


class _null_context:
    def __enter__(self):
        return None

    def __exit__(self, *_args):
        return False


def build_bundle(repo: Path, output: Path, target: Target) -> tuple[Path, Path]:
    repo = repo.resolve()
    output = output.resolve()
    _validate_target(target)
    if output.exists() or output.with_suffix(output.suffix + ".tar.gz").exists():
        raise BuildError(f"refusing to overwrite output: {output}")
    version = _port_version(repo)
    try:
        stage = output / "stage"
        paths = _payload(repo, stage, version, target)
        _validate_stage(repo, output, paths)
        manifest = _manifest(repo, stage, paths, version, target)
        _write(
            output / "metadata/+MANIFEST",
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        plist = "@owner root\n@group wheel\n" + "\n".join(paths) + "\n"
        _write(output / "plist", plist.encode("utf-8"))
        _write(output / "build-on-pfsense.sh", _remote_builder(target, version).encode("utf-8"), 0o555)
        details = {
            "package": PACKAGE_NAME,
            "version": version,
            "target_abi": target.abi,
            "package_abi": target.package_abi,
            "python_command": target.python_command,
            "python_package_version": target.python_package_version,
            "sqlite_package_version": target.sqlite_package_version,
            "install_performed": False,
        }
        _write(output / "BUILD-INFO.json", (json.dumps(details, indent=2, sort_keys=True) + "\n").encode())
        archive = output.with_suffix(output.suffix + ".tar.gz")
        _deterministic_archive(output, archive)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        _write(output / "STAGING-SHA256", f"{digest}  {archive.name}\n".encode("ascii"))
        return output, archive
    except Exception:
        if output.exists():
            shutil.rmtree(output)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--abi", required=True, help="Exact target pkg ABI, e.g. FreeBSD:16:amd64")
    parser.add_argument("--python-version", required=True, help="Target Python major.minor, e.g. 3.11")
    parser.add_argument("--python-package-version", required=True, help="Exact installed python package version")
    parser.add_argument("--sqlite-package-version", required=True, help="Exact available py*-sqlite3 package version")
    parser.add_argument("--output", type=Path, required=True, help="New staging directory to create")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    try:
        bundle, archive = build_bundle(
            repo,
            args.output,
            Target(args.abi, args.python_version, args.python_package_version, args.sqlite_package_version),
        )
    except (BuildError, OSError) as exc:
        parser.error(str(exc))
    print(f"Staged bundle: {bundle}")
    print(f"Transfer archive: {archive}")
    print("No remote connection, pkg creation, or installation was performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
