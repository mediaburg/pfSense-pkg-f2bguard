#!/usr/bin/env python3
"""Run deterministic local checks without installing or deploying anything."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('--require-php', action='store_true')
args=parser.parse_args()
env=os.environ.copy()
env['PYTHONPATH']=os.pathsep.join((str(root/'src'),str(root)))
subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-v'],cwd=root,env=env,check=True)
for path in (root/'pfsense').rglob('*.xml'):
    ET.parse(path)
php=os.environ.get('PHP_BIN') or shutil.which('php')
if php:
    files=sorted(p for p in (root/'pfsense').rglob('*') if p.suffix in ('.php','.inc'))
    for path in files:
        subprocess.run([php,'-n','-l',str(path)],check=True)
    subprocess.run([php,'-n',str(root/'tests/test_pfsense.php')],check=True)
elif args.require_php:
    raise SystemExit('PHP interpreter required; set PHP_BIN')
else:
    print('PHP lint NOT RUN: set PHP_BIN or install a PHP CLI',file=sys.stderr)
for path in (root/'pfsense/files/usr/local/etc/rc.d').glob('*'):
    if path.is_file():
        subprocess.run(['sh','-n',str(path)],check=True)
print('Available local checks passed; this does not validate pfSense runtime or HA.')
