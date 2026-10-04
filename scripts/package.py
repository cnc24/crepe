#!/usr/bin/env python3
"""Deterministic archives with checked dependency and Rust runtime notices."""
import argparse
import gzip
import hashlib
import io
import json
import platform
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def write_archive(output, files):
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w') as tar:
            for name, (data, mode) in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size = len(data); info.mode = mode; info.mtime = 0
                tar.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + '.sha256').write_text(f'{digest}  {output.name}\n')
    with tarfile.open(output) as archive:
        names = archive.getnames()
        assert 'THIRD-PARTY-NOTICES.txt' in names and 'legal/inventory.json' in names
        assert 'legal/rust/COPYRIGHT-library.html' in names
        notice = archive.extractfile('THIRD-PARTY-NOTICES.txt').read()
        assert b'Apache DataFusion' in notice and b'Apache Arrow' in notice
    print(output)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repair-archive', type=Path, help='Preserve every existing file; add license materials only')
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    subprocess.run(['python3', str(ROOT / 'scripts/licenses.py'), '--check'], check=True)
    if args.repair_archive:
        with tarfile.open(args.repair_archive) as old:
            files = {}
            for member in old.getmembers():
                if not member.isfile() or member.name.startswith('/') or '..' in Path(member.name).parts:
                    raise SystemExit(f'Unexpected archive member: {member.name}')
                files[member.name] = (old.extractfile(member).read(), member.mode)
        output = args.output_dir / args.repair_archive.name
        before = hashlib.sha256(files['crepe'][0]).hexdigest()
    else:
        binary = ROOT / 'target/release/crepe'
        version = subprocess.check_output([binary, '--version'], text=True).strip().split()[-1]
        target = f'{platform.system().lower()}-{platform.machine()}'
        output = args.output_dir / f'crepe-{version}-{target}.tar.gz'
        files = {'crepe': (binary.read_bytes(), 0o755)}
        for path in [ROOT / 'README.md', ROOT / 'LICENSE', ROOT / 'CHANGELOG.md', ROOT / 'config/example.toml', *sorted((ROOT / 'docs').glob('*.md')), *sorted((ROOT / 'plugins').rglob('*')), *sorted((ROOT / 'packaging').rglob('*')), *sorted((ROOT / 'config').glob('*.jsonl'))]:
            if path.is_file():
                files[str(path.relative_to(ROOT))] = (path.read_bytes(), 0o644)
    for path in [ROOT / 'THIRD-PARTY-NOTICES.txt', ROOT / 'legal/inventory.json', ROOT / 'legal/README.md']:
        files[str(path.relative_to(ROOT))] = (path.read_bytes(), 0o644)
    sysroot = Path(subprocess.check_output(['rustc', '--print', 'sysroot'], text=True).strip())
    docs = sysroot / 'share/doc/rust'
    runtime = docs / 'COPYRIGHT-library.html'
    if not runtime.exists():
        raise SystemExit('Rust standard-library copyright evidence missing from toolchain')
    files['legal/rust/COPYRIGHT-library.html'] = (runtime.read_bytes(), 0o644)
    for path in sorted((docs / 'licenses').rglob('*')):
        if path.is_file():
            files['legal/rust/licenses/' + str(path.relative_to(docs / 'licenses'))] = (path.read_bytes(), 0o644)
    files['legal/rust/toolchain.txt'] = (subprocess.check_output(['rustc', '-Vv']), 0o644)
    write_archive(output, files)
    if args.repair_archive:
        with tarfile.open(output) as archive:
            assert hashlib.sha256(archive.extractfile('crepe').read()).hexdigest() == before
        print('Unchanged executable SHA-256:', before)

if __name__ == '__main__':
    main()
