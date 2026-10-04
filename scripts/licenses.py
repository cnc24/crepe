#!/usr/bin/env python3
"""Generate auditable, offline-capable third-party notices from locked Cargo inputs."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KNOWN = {'MIT', 'Apache-2.0', 'Unicode-3.0', 'BSD-2-Clause', 'BSD-3-Clause',
         'ISC', 'Zlib', 'Unlicense', 'CC0-1.0', 'MIT-0', 'BSL-1.0', 'LGPL-2.1-or-later'}

def license_file(path):
    return path.name.lower().startswith(('license', 'licence', 'copying', 'notice', 'copyright'))

def generate():
    metadata = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--locked', '--all-features', '--format-version', '1'], cwd=ROOT))
    sections = ['# Third-party licenses and notices\n',
        'Generated from Cargo.lock, including optional, build and cross-platform dependencies.\n'
        'This is an inclusive inventory, not a claim that every package is in every binary.\n'
        'Crepe uses permissive alternatives where an OR expression allows that choice;\n'
        'AND requirements remain cumulative. Upstream texts below are preserved verbatim.\n'
        'System libraries (including libpcap) are dynamically linked, not bundled.\n'
        'No third-party code is relicensed under Crepe\'s project license.\n']
    inventory = []
    standards = ROOT / 'legal/standard'
    for path in sorted(standards.glob('*')):
        if path.suffix == '.txt':
            sections += [f'\n## Standard license text: {path.name}\n', path.read_text()]
    for p in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
        if p['source'] is None:
            continue
        license = p.get('license')
        if not license:
            raise RuntimeError(f'Missing SPDX expression: {p["name"]}')
        tokens = set(license.replace('(', '').replace(')', '').replace('/', ' OR ').split())
        if tokens - KNOWN - {'AND', 'OR', 'WITH', 'LLVM-exception'}:
            raise RuntimeError(f'Unreviewed SPDX expression: {p["name"]}: {license}')
        root = Path(p['manifest_path']).parent
        files = sorted(f for f in root.rglob('*') if f.is_file() and license_file(f))
        supplement = ROOT / 'legal/upstream' / f'{p["name"]}-{p["version"]}'
        extra = sorted(f for f in supplement.glob('*') if f.is_file())
        # Missing upstream files must have a reviewed, version-specific supplement.
        if not files and not extra:
            raise RuntimeError(f'Missing license evidence: {p["name"]} {p["version"]}')
        sections.append(f'\n## {p["name"]} {p["version"]}\n\nDeclared license: {license}\n'
                        f'Repository: {p.get("repository") or "not declared"}\n'
                        f'Authors declared by upstream: {", ".join(a for a in p["authors"] if a) or "not declared"}\n')
        item = {'name': p['name'], 'version': p['version'], 'license': license,
                'repository': p.get('repository'), 'evidence': []}
        for f in files + extra:
            relative = str(f.relative_to(root)) if f in files else 'supplement/' + f.name
            text = f.read_text()
            sections.extend([f'\n### {relative}\n\n', text, '\n'])
            item['evidence'].append({'path': relative, 'sha256': hashlib.sha256(f.read_bytes()).hexdigest()})
        inventory.append(item)
    return '\n'.join(sections), json.dumps(inventory, indent=2, ensure_ascii=False) + '\n'

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    notice, inventory = generate()
    for name, content in [('THIRD-PARTY-NOTICES.txt', notice), ('legal/inventory.json', inventory)]:
        path = ROOT / name
        if args.check:
            if not path.exists() or path.read_text() != content:
                raise SystemExit(f'{name} is stale; run python3 scripts/licenses.py and review changes')
        else:
            path.write_text(content)
    print('PASS: locked dependency licenses and notices are complete and current.')

if __name__ == '__main__':
    main()
