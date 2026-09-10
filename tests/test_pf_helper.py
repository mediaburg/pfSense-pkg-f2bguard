import ipaddress
import json
import os
import socket
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from f2bguard.pf_helper import HelperError, PFUpdater, handle, parse_request, parse_whitelist, peer_uid, secure_read


class FakePF:
    def __init__(self):
        self.tables = {'f2bguard_v4': ['198.51.100.8'], 'f2bguard_v6': ['2001:db8::8']}
        self.calls = []
        self.fail_v6_once = False

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        table, action = argv[2], argv[4]
        if action == 'show':
            return subprocess.CompletedProcess(argv, 0, '\n'.join(self.tables[table]), '')
        if table == 'f2bguard_v6' and self.fail_v6_once:
            self.fail_v6_once = False
            return subprocess.CompletedProcess(argv, 1, '', 'failed')
        self.tables[table] = kwargs['input'].splitlines()
        return subprocess.CompletedProcess(argv, 0, '', '')


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.pf = FakePF()
        self.helper = PFUpdater('/trusted/whitelist', self.pf, lambda _: '203.0.113.0/24\n2001:db8:1::/48\n')

    def test_whitelist_filtered_at_privilege_boundary(self):
        result = self.helper.replace({'op':'replace','ipv4':['203.0.113.5','198.51.100.3'],
                                      'ipv6':['2001:db8:1::4','2001:db8:2::4']})
        self.assertTrue(result['ok'])
        self.assertEqual(self.pf.tables['f2bguard_v4'], ['198.51.100.3'])
        self.assertEqual(self.pf.tables['f2bguard_v6'], ['2001:db8:2::4'])
        self.assertEqual(result['applied_ipv4'], 1)
        for args, kw in self.pf.calls:
            self.assertNotIn('shell', kw)
            self.assertEqual(args[0], '/sbin/pfctl')
            self.assertIn(args[2], ('f2bguard_v4','f2bguard_v6'))

    def test_invalid_second_family_does_not_mutate_first(self):
        with self.assertRaises(HelperError):
            self.helper.replace({'op':'replace','ipv4':['198.51.100.3'],'ipv6':['2001:db8::1; reboot']})
        self.assertEqual(self.pf.calls, [])

    def test_failed_ipv6_replace_rolls_back_ipv4(self):
        self.pf.fail_v6_once = True
        with self.assertRaisesRegex(HelperError, 'rollback completed'):
            self.helper.replace({'op':'replace','ipv4':['198.51.100.3'],'ipv6':['2001:db8::3']})
        self.assertEqual(self.pf.tables['f2bguard_v4'], ['198.51.100.8/32'])
        self.assertEqual(self.pf.tables['f2bguard_v6'], ['2001:db8::8/128'])

    def test_existing_broad_network_is_not_reapplied(self):
        self.pf.tables['f2bguard_v4'] = ['0.0.0.0/0']
        with self.assertRaisesRegex(HelperError, 'non-host'):
            self.helper.replace({'op':'replace','ipv4':[],'ipv6':[]})
        self.assertTrue(all(call[0][4] == 'show' for call in self.pf.calls))

    def test_invalid_whitelist_preserves_tables(self):
        self.helper.whitelist_reader = lambda _: 'not-an-ip'
        with self.assertRaises(HelperError):
            self.helper.replace({'op':'replace','ipv4':[],'ipv6':[]})
        self.assertEqual(self.pf.calls, [])

    def test_disallowed_protocol_and_targets(self):
        bad = [
            {'op':'flush','ipv4':[],'ipv6':[]},
            {'op':'replace','ipv4':[],'ipv6':[],'table':'other'},
            {'op':'replace','ipv4':['0.0.0.0/0'],'ipv6':[]},
            {'op':'replace','ipv4':['127.0.0.1'],'ipv6':[]},
            {'op':'replace','ipv4':[],'ipv6':['fe80::1%vtnet0']},
            {'op':'replace','ipv4':[],'ipv6':['2001:DB8::1']},
        ]
        for request in bad:
            with self.subTest(request=request), self.assertRaises(HelperError):
                parse_request(request)

    def test_root_trust_file_cannot_live_in_tmp(self):
        with self.assertRaises(HelperError):
            secure_read('/tmp/nonexistent-whitelist')

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux peer credentials')
    def test_real_peer_credentials(self):
        a,b=socket.socketpair()
        try:
            self.assertEqual(peer_uid(a), os.getuid())
        finally:
            a.close();b.close()

    def test_untrusted_socket_uid_cannot_apply(self):
        a,b=socket.socketpair()
        try:
            with patch('f2bguard.pf_helper.peer_uid', return_value=999):
                t=threading.Thread(target=handle,args=(a,123,self.helper));t.start()
                b.sendall(b'{"op":"replace","ipv4":[],"ipv6":[]}\n')
                response=json.loads(b.recv(4096));t.join()
            self.assertFalse(response['ok'])
            self.assertEqual(self.pf.calls,[])
        finally:
            a.close();b.close()


if __name__=='__main__':
    unittest.main()
