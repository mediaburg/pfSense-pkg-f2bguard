"""Actual mTLS sender -> receiver -> authenticated Unix helper integration.

PF subprocesses are simulated; this suite never changes the host firewall.
"""
import dataclasses
import hashlib
import http.client
import ipaddress
import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
import uuid
from unittest.mock import patch

from client.sender import HTTPSClient, PermanentJail, SenderConfig, SenderStore, Worker
from f2bguard.config import ClientConfig, Config, TLSConfig
from f2bguard.pf_helper import PFUpdater, handle
from f2bguard.server import build_server
import os


@unittest.skipUnless(shutil.which('openssl'), 'openssl required for real TLS tests')
class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.root=Path(cls.tmp.name)
        def openssl(*args):
            subprocess.run(['openssl',*args],cwd=cls.root,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','1',
                '-keyout','ca.key','-out','ca.pem','-subj','/CN=Test CA',
                '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
        for name in ['server','a','b','unknown']:
            openssl('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes',
                    '-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+name)
            extra='basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
            extra+='extendedKeyUsage='+('serverAuth' if name=='server' else 'clientAuth')+'\n'
            if name=='server': extra+='subjectAltName=IP:127.0.0.1,DNS:localhost\n'
            (cls.root/(name+'.ext')).write_text(extra)
            openssl('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial',
                    '-days','1','-out',name+'.pem','-extfile',name+'.ext')

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.case=tempfile.TemporaryDirectory(dir=self.root)
        self.path=Path(self.case.name)
        self.whitelist=b'203.0.113.0/24\n'
        self.tables={'f2bguard_v4':[],'f2bguard_v6':[]}
        def runner(argv,**kwargs):
            table,op=argv[2],argv[4]
            if op=='show': return subprocess.CompletedProcess(argv,0,'\n'.join(self.tables[table]),'')
            self.tables[table]=kwargs['input'].splitlines()
            return subprocess.CompletedProcess(argv,0,'','')
        self.updater=PFUpdater('/unit-test-whitelist',runner,lambda _: self.whitelist.decode())
        self.unix=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.unix.bind(str(self.path/'helper.sock'));self.unix.listen(8);self.unix.settimeout(.1)
        self.stop=threading.Event()
        def helper_loop():
            while not self.stop.is_set():
                try: conn,_=self.unix.accept()
                except socket.timeout: continue
                except OSError: return
                with conn: handle(conn,os.getuid(),self.updater)
        self.helper_thread=threading.Thread(target=helper_loop,daemon=True);self.helper_thread.start()
        def fingerprint(name):
            der=ssl.PEM_cert_to_DER_cert((self.root/(name+'.pem')).read_text())
            return hashlib.sha256(der).hexdigest()
        self.config=Config(enabled=True,listen='127.0.0.1',port=0,
            tls=TLSConfig(str(self.root/'server.pem'),str(self.root/'server.key'),str(self.root/'ca.pem')),
            clients=tuple(ClientConfig(name,(fingerprint(name),),frozenset({'recidive'})) for name in ('a','b')),
            database=str(self.path/'receiver.sqlite'),whitelist_file='/unit-test-whitelist',enforcement_socket=str(self.path/'helper.sock'))
        self.read_patch=patch('f2bguard.server._secure_read_root_file',side_effect=lambda *_: self.whitelist)
        self.read_patch.start()
        self.server=build_server(self.config)
        self.port=self.server.server_address[1]
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.05},daemon=True);self.thread.start()
        self.stores=[]

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=3)
        self.stop.set();self.unix.close();self.helper_thread.join(timeout=3)
        self.read_patch.stop()
        for store in self.stores: store.close()
        self.case.cleanup()

    def sender(self,name):
        cfg=SenderConfig(database=str(self.path/(name+'.sqlite')),endpoint=f'https://127.0.0.1:{self.port}/v1',
            ca=str(self.root/'ca.pem'),cert=str(self.root/(name+'.pem')),key=str(self.root/(name+'.key')),
            permanent_jails=(PermanentJail('recidive'),),request_timeout=3)
        store=SenderStore(cfg.database);self.stores.append(store)
        return store,Worker(cfg,store,HTTPSClient(cfg))

    def request(self,name,method,path,payload=None):
        context=ssl.create_default_context(cafile=str(self.root/'ca.pem'))
        if name: context.load_cert_chain(str(self.root/(name+'.pem')),str(self.root/(name+'.key')))
        conn=http.client.HTTPSConnection('127.0.0.1',self.port,context=context,timeout=3)
        try:
            conn.request(method,path,None if payload is None else json.dumps(payload),{'Content-Type':'application/json'})
            response=conn.getresponse();return response.status,json.loads(response.read())
        finally: conn.close()

    def test_two_endpoints_unban_and_whitelist(self):
        a,wa=self.sender('a');b,wb=self.sender('b')
        for store,worker in ((a,wa),(b,wb)):
            store.enqueue('ban','recidive','198.51.100.7',now=0)
            self.assertTrue(worker.process_once(now=1))
        a.enqueue('ban','recidive','203.0.113.7',now=0);self.assertTrue(wa.process_once(now=1))
        self.assertEqual(self.tables['f2bguard_v4'],['198.51.100.7'])
        a.enqueue('unban','recidive','198.51.100.7',now=0);self.assertTrue(wa.process_once(now=1))
        self.assertEqual(self.tables['f2bguard_v4'],['198.51.100.7'])
        b.enqueue('unban','recidive','198.51.100.7',now=0);self.assertTrue(wb.process_once(now=1))
        self.assertEqual(self.tables['f2bguard_v4'],[])
        status,body=self.request('b','GET','/v1/status')
        self.assertEqual(status,200);self.assertEqual(body['client_id'],'b');self.assertEqual(body['claim_count'],0)
        self.assertNotIn('203.0.113.7',json.dumps(body))

    def test_missing_and_unregistered_certificates_rejected(self):
        with self.assertRaises((ssl.SSLError,OSError,http.client.HTTPException)):
            self.request(None,'GET','/v1/status')
        status,_=self.request('unknown','GET','/v1/status')
        self.assertEqual(status,403)
        self.assertEqual(self.tables['f2bguard_v4'],[])

    def test_idle_tcp_does_not_block_tls_clients(self):
        with socket.create_connection(('127.0.0.1',self.port),timeout=2):
            status,_=self.request('a','GET','/v1/status')
            self.assertEqual(status,200)

    def test_null_body_is_rejected_not_hung(self):
        context=ssl.create_default_context(cafile=str(self.root/'ca.pem'))
        context.load_cert_chain(str(self.root/'a.pem'),str(self.root/'a.key'))
        conn=http.client.HTTPSConnection('127.0.0.1',self.port,context=context,timeout=3)
        try:
            conn.request('POST','/v1/events',b'null',{'Content-Type':'application/json'})
            self.assertEqual(conn.getresponse().status,400)
        finally: conn.close()

    def test_whitelist_change_removes_existing_applied_ip(self):
        store,worker=self.sender('a')
        store.enqueue('ban','recidive','198.51.100.9',now=0)
        self.assertTrue(worker.process_once(now=1))
        self.whitelist=b'198.51.100.9/32\n'
        self.server.enforcer.enforce()
        self.assertEqual(self.tables['f2bguard_v4'],[])


if __name__=='__main__': unittest.main()
