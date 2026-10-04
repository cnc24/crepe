#!/usr/bin/env python3
"""Check the production crate dependency boundaries declared in docs/ARCHITECTURE.md."""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--no-deps', '--format-version', '1', '--locked'], cwd=root))
allowed = {
    'crepe-plugin': {'crepe-core'},
    'crepe-files': {'crepe-core'},
    'crepe-security': {'crepe-core'},
    'crepe-core': set(),
    'crepe-packet': {'crepe-core'},
    'crepe-capture': {'crepe-core', 'crepe-packet'},
    'crepe-query': {'crepe-core'},
    'crepe-flow': {'crepe-core'},
    'crepe-stream': {'crepe-core'},
    'crepe-dns': {'crepe-core'},
    'crepe-fragment': {'crepe-core'},
    'crepe-protocol': {'crepe-core'},
    'crepe-collector': {'crepe-core'},
    'crepe-storage': {'crepe-core'},
    'crepe-engine': {'crepe-plugin', 'crepe-security', 'crepe-core', 'crepe-capture', 'crepe-packet', 'crepe-flow', 'crepe-analysis', 'crepe-storage', 'crepe-collector'},
    'crepe-analysis': {'crepe-files', 'crepe-core', 'crepe-packet', 'crepe-stream', 'crepe-dns', 'crepe-flow', 'crepe-protocol', 'crepe-fragment'},
    'crepe-cli': {'crepe-core', 'crepe-packet', 'crepe-capture', 'crepe-query', 'crepe-flow', 'crepe-analysis', 'crepe-engine', 'crepe-storage', 'crepe-collector'},
}
packages = {p['name']: p for p in metadata['packages'] if p['id'] in metadata['workspace_members']}
assert packages.keys() == allowed.keys(), 'Update the architecture contract deliberately when adding/removing a crate'
for name, package in packages.items():
    internal = {d['name'] for d in package['dependencies'] if d['kind'] != 'dev' and d['name'].startswith('crepe-')}
    assert internal <= allowed[name], f'{name} has forbidden production dependencies: {internal - allowed[name]}'
    if name == 'crepe-core':
        assert {d['name'] for d in package['dependencies'] if d['kind'] != 'dev'} == {'serde'}, 'Core must stay dependency-light'
print(f'PASS: {len(packages)} crates obey production dependency boundaries; test-only dependencies excluded.')
