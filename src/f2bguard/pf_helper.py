"""Minimal privileged PF table updater. No TCP listener or arbitrary commands."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import ipaddress
import json
import os
import pwd
import socket
import stat
import struct
import subprocess
import sys
from pathlib import Path
from .networks import NetworkIndex

MAX_MESSAGE = 4 * 1024 * 1024
MAX_ADDRESSES = 100_000
TABLES = {4: 'f2bguard_v4', 6: 'f2bguard_v6'}


class HelperError(Exception):
    pass


def secure_read(path: str, owner: int = 0) -> str:
    """Reject writable/symlink trust paths, not just unsafe leaf files."""
    p = Path(path)
    if not p.is_absolute():
        raise HelperError('whitelist path must be absolute')
    for parent in reversed(p.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise HelperError('unsafe whitelist parent directory')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise HelperError('unsafe whitelist file')
        if info.st_size > MAX_MESSAGE:
            raise HelperError('whitelist exceeds size limit')
        with os.fdopen(fd, 'r', encoding='ascii', closefd=False) as stream:
            return stream.read(MAX_MESSAGE + 1)
    finally:
        os.close(fd)


def parse_whitelist(text: str):
    networks = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '%' in line:
            raise HelperError('scoped addresses not allowed')
        try:
            networks.append(ipaddress.ip_network(line, strict=False))
        except ValueError as exc:
            raise HelperError('invalid whitelist entry') from exc
        if len(networks) > MAX_ADDRESSES:
            raise HelperError('too many whitelist entries')
    return networks


def parse_request(request):
    if not isinstance(request, dict) or set(request) != {'op', 'ipv4', 'ipv6'} or request['op'] != 'replace':
        raise HelperError('only fixed-table replacement is supported')
    result = {}
    count = 0
    for version, field in ((4, 'ipv4'), (6, 'ipv6')):
        values = request[field]
        if not isinstance(values, list):
            raise HelperError('addresses must be arrays')
        count += len(values)
        if count > MAX_ADDRESSES:
            raise HelperError('too many addresses')
        addresses = set()
        for value in values:
            if not isinstance(value, str) or '%' in value:
                raise HelperError('invalid IP literal')
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise HelperError('invalid IP literal') from exc
            if address.version != version or str(address) != value:
                raise HelperError('noncanonical or wrong-family IP')
            if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local or getattr(address, 'ipv4_mapped', None) is not None:
                raise HelperError('protected special-purpose IP')
            addresses.add(address)
        result[version] = sorted(addresses)
    return result


class PFUpdater:
    def __init__(self, whitelist_path: str, runner=subprocess.run, whitelist_reader=secure_read):
        self.whitelist_path = whitelist_path
        self.runner = runner
        self.whitelist_reader = whitelist_reader

    def command(self, version: int, action: str, values=None):
        argv = ['/sbin/pfctl', '-t', TABLES[version], '-T', action]
        stdin = None
        if values is not None:
            argv += ['-f', '-']
            stdin = ''.join(str(value) + '\n' for value in values)
        completed = self.runner(argv, input=stdin, text=True, capture_output=True, timeout=15, check=False)
        if completed.returncode:
            raise HelperError('PF table operation failed')
        return completed.stdout

    def replace(self, request):
        requested = parse_request(request)
        whitelist = NetworkIndex(parse_whitelist(self.whitelist_reader(self.whitelist_path)))
        effective = {
            version: [a for a in addresses if a not in whitelist]
            for version, addresses in requested.items()
        }
        # Validate both families and read current tables before any mutation.
        previous = {}
        for version in TABLES:
            previous[version] = []
            for line in self.command(version, 'show').splitlines():
                line = line.strip()
                if line:
                    network = ipaddress.ip_network(line, strict=True)
                    if network.version != version or network.prefixlen != network.max_prefixlen:
                        raise HelperError('existing table contains a non-host entry')
                    previous[version].append(network)
        try:
            for version in TABLES:
                self.command(version, 'replace', effective[version])
        except Exception as exc:
            rollback_failed = False
            for version in TABLES:
                try:
                    # Never restore a now-whitelisted old entry. Normal tables contain hosts.
                    safe = [n for n in previous[version]
                            if n.network_address not in whitelist]
                    self.command(version, 'replace', safe)
                except Exception:
                    rollback_failed = True
            raise HelperError('PF replacement failed; rollback ' + ('failed' if rollback_failed else 'completed')) from exc
        rendered = '\n'.join(str(a) for version in TABLES for a in effective[version])
        return {'ok': True, 'applied_ipv4': len(effective[4]), 'applied_ipv6': len(effective[6]),
                'digest': hashlib.sha256(rendered.encode()).hexdigest()}


def peer_uid(connection: socket.socket) -> int:
    if sys.platform.startswith('linux'):
        return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
    if sys.platform.startswith(('freebsd', 'darwin', 'openbsd')):
        libc = ctypes.CDLL(None, use_errno=True)
        fn = libc.getpeereid
        fn.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
        fn.restype = ctypes.c_int
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        if fn(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            raise HelperError('cannot verify socket peer')
        return uid.value
    raise HelperError('unsupported peer credential platform')


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise HelperError('duplicate JSON key')
        result[key] = value
    return result


def handle(connection, allowed_uid, updater):
    connection.settimeout(5)
    try:
        if peer_uid(connection) != allowed_uid:
            raise HelperError('unauthorized peer')
        stream = connection.makefile('rb')
        try:
            data = stream.readline(MAX_MESSAGE + 1)
        finally:
            stream.close()
        if len(data) > MAX_MESSAGE or not data.endswith(b'\n'):
            raise HelperError('invalid message length')
        request = json.loads(data, object_pairs_hook=no_duplicate_keys)
        response = updater.replace(request)
    except Exception as exc:
        # No filesystem paths, subprocess stderr, or secrets on the socket.
        response = {'ok': False, 'error': str(exc) if isinstance(exc, HelperError) else 'invalid request or enforcement failure'}
    try:
        connection.sendall(json.dumps(response, separators=(',', ':')).encode() + b'\n')
    except OSError:
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', default='/var/run/f2bguard/pf.sock')
    parser.add_argument('--whitelist', default='/usr/local/etc/f2bguard/whitelist.txt')
    parser.add_argument('--user', default='f2bguard')
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error('helper must run as root')
    account = pwd.getpwnam(args.user)
    if account.pw_uid == 0:
        parser.error('service user must not be root')
    path = Path(args.socket)
    parent = path.parent.lstat()
    if not path.is_absolute() or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        parser.error('socket directory must be root-owned and not group/world writable')
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
            parser.error('refusing to replace non-root socket path')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            try:
                probe.connect(str(path))
            except ConnectionRefusedError:
                path.unlink()
            else:
                parser.error('helper already running')
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    os.umask(0o077)
    server.bind(str(path))
    os.chown(path, 0, account.pw_gid)
    os.chmod(path, 0o660)
    server.listen(16)
    updater = PFUpdater(args.whitelist)
    try:
        while True:
            connection, _ = server.accept()
            with connection:
                handle(connection, account.pw_uid, updater)
    finally:
        server.close()
        path.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
