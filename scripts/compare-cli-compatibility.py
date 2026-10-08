#!/usr/bin/env python3
"""Compare the documented packet-filter subset with TShark and tcpdump.

Uses repository fixtures, plus an optional externally supplied HTTP capture.
No downloads, root permissions or live capture. Raw evidence goes to a NEW directory.
This verifies selected semantics, not complete Wireshark/tcpdump compatibility.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--crepe', default=str(ROOT / 'target/release/crepe'))
    parser.add_argument('--tshark', default='tshark')
    parser.add_argument('--tcpdump', default='tcpdump')
    parser.add_argument('--http-capture', type=Path)
    args = parser.parse_args()
    tools = {name: shutil.which(getattr(args, name)) for name in ('crepe', 'tshark', 'tcpdump')}
    if not all(tools.values()):
        parser.error(f'Install the comparison tools first: {tools}')
    args.output.mkdir(parents=True, exist_ok=False)
    commands, checks = [], {}

    def run(label, tool, *arguments):
        command = [tools[tool], *map(str, arguments)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        for stream in ('stdout', 'stderr'):
            (args.output / f'{label}.{stream}').write_text(getattr(result, stream))
        commands.append({'command': command, 'exit_code': result.returncode})
        (args.output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if result.returncode:
            raise RuntimeError(f'{label}: {result.stderr}')
        return result.stdout

    files = [ROOT / 'example.pcap', ROOT / 'fixtures/flows.pcap', ROOT / 'fixtures/packet-display.pcap']
    expressions = ['ip', 'ipv6', 'tcp', 'udp', 'ip.src == 192.0.2.10',
                   'ip.dst != 192.0.2.10', 'ip.addr == 192.0.2.10',
                   'tcp.port == 443', 'tcp.srcport != 443', 'udp.dstport == 53',
                   'tcp and (ip.src == 192.0.2.10 or tcp.port == 80)', 'http']
    if args.http_capture:
        files.append(args.http_capture.resolve())
    provenance = []
    for i, capture in enumerate(files):
        provenance.append({'path': str(capture), 'sha256': hashlib.sha256(capture.read_bytes()).hexdigest()})
        for j, expression in enumerate(expressions):
            label = f'filter-{i}-{j}'
            c = run(label + '-crepe', 'crepe', 'read', capture, expression, '--format', 'json')
            t = run(label + '-tshark', 'tshark', '-n', '-r', capture, '-Y', expression,
                    '-T', 'fields', '-e', 'frame.number')
            actual = [json.loads(line)['header']['sequence'] for line in c.splitlines()]
            expected = [int(line) for line in t.splitlines() if line]
            checks[label] = actual == expected
    if args.http_capture:
        capture = args.http_capture
        c = run('http-summary', 'crepe', 'read', capture, 'http')
        verbose = run('http-verbose', 'crepe', 'read', capture, 'http', '-vvX')
        t = run('http-tcpdump', 'tcpdump', '-nn', '-A', '-r', capture)
        fields = run('http-fields', 'tshark', '-n', '-r', capture, '-Y', 'http.request',
                     '-T', 'fields', '-e', 'http.request.method', '-e', 'http.request.uri',
                     '-e', 'http.request.version')
        requests = [' '.join(line.split('\t')) for line in fields.splitlines() if line]
        checks['http-request-details'] = bool(requests) and all(line in c and line in t for line in requests)
        checks['verbose-ip-details'] = 'ttl' in verbose.lower() and '4500' in verbose.replace(' ', '')
    report = {'captures': provenance, 'checks': checks,
              'passed': sum(checks.values()), 'total': len(checks)}
    (args.output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"{report['passed']}/{report['total']} checks passed")
    if not all(checks.values()):
        raise SystemExit('Failed: ' + ', '.join(key for key, value in checks.items() if not value))


if __name__ == '__main__':
    main()
