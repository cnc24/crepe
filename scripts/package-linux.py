#!/usr/bin/env python3
"""Build native Linux DEB/RPM packages from a validated local release archive."""
import argparse, gzip, hashlib, io, os, platform, re, shutil, subprocess, tarfile, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def tar_bytes(root):
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode='wb', filename='', mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w') as tar:
            for path in sorted(root.rglob('*')):
                info = tarfile.TarInfo('./' + str(path.relative_to(root)))
                if path.is_dir():
                    info.type = tarfile.DIRTYPE; info.mode = 0o755; info.mtime = 0
                    tar.addfile(info); continue
                if not path.is_file(): continue
                data = path.read_bytes()
                info.size = len(data); info.mode = 0o755 if path.name == 'crepe' else 0o644
                info.mtime = 0; tar.addfile(info, io.BytesIO(data))
    return out.getvalue()

def ar(path, members):
    with path.open('wb') as out:
        out.write(b'!<arch>\n')
        for name, data in members:
            header = f'{name + "/":<16}{0:<12}{0:<6}{0:<6}{"100644":<8}{len(data):<10}`\n'.encode()
            assert len(header) == 60
            out.write(header); out.write(data)
            if len(data) % 2: out.write(b'\n')

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--format', choices=['deb', 'rpm'], required=True)
    parser.add_argument('--output-dir', type=Path, default=ROOT/'dist'); args = parser.parse_args()
    if platform.system() != 'Linux': raise SystemExit('Native Linux package builds must run on Linux')
    binary = ROOT/'target/release/crepe'
    version = subprocess.check_output([binary, '--version'], text=True).split()[-1]
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version): raise SystemExit('Use a numeric release version for distro packages')
    subprocess.run(['python3', str(ROOT/'scripts/package.py')], check=True)
    archive = ROOT/'dist'/f'crepe-{version}-linux-{platform.machine()}.tar.gz'
    with tempfile.TemporaryDirectory(prefix='crepe-package-') as temporary:
        temp=Path(temporary); stage=temp/'root'; doc=stage/'usr/share/doc/crepe'; doc.mkdir(parents=True)
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                if not member.isfile() or member.name.startswith('/') or '..' in Path(member.name).parts: raise SystemExit('Unexpected archive member')
                destination = stage/'usr/bin/crepe' if member.name == 'crepe' else doc/member.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(tar.extractfile(member).read()); destination.chmod(member.mode)
        for source, destination in [('packaging/systemd/crepe.service', 'usr/lib/systemd/system/crepe.service'), ('packaging/systemd/crepe.toml', 'etc/crepe/crepe.toml')]:
            target=stage/destination; target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(ROOT/source,target)
        args.output_dir.mkdir(parents=True,exist_ok=True)
        if args.format == 'deb':
            architecture={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
            versions=subprocess.check_output(['readelf','--version-info',binary],text=True)
            glibc=max(set(re.findall(r'GLIBC_([0-9]+\.[0-9]+)',versions)),key=lambda v:tuple(map(int,v.split('.'))))
            control=temp/'control';control.mkdir()
            (control/'control').write_text(f'Package: crepe\nVersion: {version}\nSection: net\nPriority: optional\nArchitecture: {architecture}\nMaintainer: Crepe contributors\nDepends: libc6 (>= {glibc}), libgcc-s1, libpcap0.8t64 | libpcap0.8\nDescription: Passive network analysis, flow collection and historical queries\n')
            (control/'conffiles').write_text('/etc/crepe/crepe.toml\n')
            output=args.output_dir/f'crepe_{version}_{architecture}.deb'
            ar(output,[('debian-binary',b'2.0\n'),('control.tar.gz',tar_bytes(control)),('data.tar.gz',tar_bytes(stage))])
            subprocess.run(['dpkg-deb','--info',output],check=True)
            subprocess.run(['dpkg-deb','--contents',output],check=True,stdout=subprocess.DEVNULL)
        else:
            # Build on the target RPM distribution so ELF requirements match its libpcap/glibc.
            for name in ['BUILD','BUILDROOT','RPMS','SOURCES','SPECS','SRPMS']:(temp/name).mkdir()
            shutil.copytree(stage,temp/'SOURCES/root')
            spec=temp/'SPECS/crepe.spec'
            spec.write_text(f'''Name: crepe
Version: {version}
Release: 1
Summary: Passive network analysis and historical queries
License: LicenseRef-Crepe-Source-Available-1.0 AND MIT AND Apache-2.0 AND (Apache-2.0 WITH LLVM-exception) AND BSD-3-Clause AND ISC AND Unicode-3.0 AND Zlib AND CC0-1.0
URL: https://github.com/cnc24/crepe
%description
Crepe packet, flow, application metadata and historical query tools.
Third-party license expressions and notices are in the packaged inventory.
%prep
%build
%install
mkdir -p %{{buildroot}}
cp -a %{{_sourcedir}}/root/. %{{buildroot}}/
%files
/usr/bin/crepe
/usr/lib/systemd/system/crepe.service
%config(noreplace) /etc/crepe/crepe.toml
/usr/share/doc/crepe
''')
            subprocess.run(['rpmbuild','--define',f'_topdir {temp}','--define','_build_id_links none','--define','debug_package %{nil}','-bb',spec],check=True)
            packages=list((temp/'RPMS').rglob('*.rpm'));assert len(packages)==1
            output=args.output_dir/packages[0].name;shutil.copyfile(packages[0],output)
            subprocess.run(['rpm','-qp','--info',output],check=True)
        digest=hashlib.sha256(output.read_bytes()).hexdigest()
        output.with_suffix(output.suffix+'.sha256').write_text(f'{digest}  {output.name}\n')
        print(output)

if __name__ == '__main__': main()
