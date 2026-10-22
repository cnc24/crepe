#!/usr/bin/env python3
"""Compare the documented packet-statistics subset with actual TShark/tcpdump."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--crepe', default='target/release/crepe')
p.add_argument('--tshark', default='tshark')
p.add_argument('--tcpdump', default='tcpdump')
a = p.parse_args()
checks = 0

def run(*cmd):
    return subprocess.check_output(list(map(str, cmd)), text=True, stderr=subprocess.PIPE, timeout=30)

def stats(file, *args):
    return json.loads(run(a.crepe, 'stats', file, *args, '--format', 'json'))

def same(actual, expected):
    global checks
    assert actual == expected, (actual, expected)
    checks += 1

for capture in ['example.pcap', 'fixtures/example.pcapng', 'fixtures/flows.pcap', 'fixtures/packet-display.pcap']:
    for name, expression in [('tcp', 'tcp'), ('udp', 'udp'), ('arp', 'arp'), ('http', 'http'),
                             ('syn', 'tcp.flags.syn == 1'), ('syn-only', 'tcp.flags.syn == 1 && tcp.flags.ack == 0'),
                             ('syn-ack', 'tcp.flags.syn == 1 && tcp.flags.ack == 1'), ('fin', 'tcp.flags.fin == 1'),
                             ('rst', 'tcp.flags.reset == 1')]:
        sizes = [int(x) for x in run(a.tshark, '-n', '-r', capture, '-Y', expression,
                                    '-T', 'fields', '-e', 'frame.len').splitlines()]
        report = stats(capture, name)
        same((report['matched_packets'], report['matched_bytes']), (len(sizes), sum(sizes)))
    source_totals = {}
    endpoint_totals = {}
    fields = run(a.tshark, '-n', '-r', capture, '-T', 'fields',
                 '-e', 'ip.src', '-e', 'ipv6.src', '-e', 'ip.dst', '-e', 'ipv6.dst', '-e', 'frame.len')
    wildcard = stats(capture, 'count *')
    same((wildcard['matched_packets'], wildcard['matched_bytes']),
         (len(fields.splitlines()), sum(int(line.split('\t')[-1]) for line in fields.splitlines())))
    for line in fields.splitlines():
        src4, src6, dst4, dst6, size = line.split('\t')
        src, dst = src4 or src6, dst4 or dst6
        if not src:
            continue
        for totals, names in [(source_totals, [src]), (endpoint_totals, set([src, dst]))]:
            for name in names:
                packets, count_bytes = totals.get(name, (0, 0))
                totals[name] = (packets + 1, count_bytes + int(size))
    for report_name, expected in [('top-talkers', source_totals), ('endpoints', endpoint_totals)]:
        report = stats(capture, report_name, '--top', '3')
        ranked = sorted(expected, key=lambda n: (-expected[n][1], n))[:3]
        same([(r['name'], r['packets'], r['bytes']) for r in report['rows']],
             [(n, *expected[n]) for n in ranked])
        same(report['rows_omitted'], max(len(expected) - 3, 0))
    # Compare actual -z hierarchy output; retain layer nesting, not only totals.
    text = run(a.tshark, '-n', '-r', capture, '-q', '-z', 'io,phs')
    hierarchy = {r['name']: (r['packets'], r['bytes']) for r in stats(capture, 'hierarchy')['rows']}
    stack = []
    for line in text.splitlines():
        match = re.match(r'^( *)(\S+)\s+frames:(\d+) bytes:(\d+)', line)
        if not match:
            continue
        spaces, name, packets, size = match.groups()
        depth = len(spaces) // 2
        stack = stack[:depth]
        stack.append({'eth': 'ethernet', 'ip': 'ipv4'}.get(name, name))
        key = ' > '.join(stack[1:])  # TShark's frame root is implicit in Crepe totals.
        if key in hierarchy:
            same(hierarchy[key], (int(packets), int(size)))
with tempfile.TemporaryDirectory(prefix='crepe-stats-compare-') as d:
    exported = Path(d) / 'tcpdump.pcap'
    run(a.tcpdump, '-n', '-r', 'fixtures/flows.pcap', '-c', '5', '-w', exported, 'tcp')
    expected = [json.loads(x) for x in run(a.crepe, 'read', exported, '--format', 'json').splitlines()]
    actual = [json.loads(x) for x in run(a.crepe, 'read', 'fixtures/flows.pcap', 'tcp', '-c', '5', '--format', 'json').splitlines()]
    for row in expected + actual:
        row['header'].pop('sequence')
    same(actual, expected)
# Shared CQL and BPF produce the same stats selection.
same(stats('fixtures/flows.pcap', 'dst.port == 443')['matched_packets'],
     stats('fixtures/flows.pcap', 'dst port 443')['matched_packets'])
print(f'PASS: {checks} TShark/tcpdump count, byte, hierarchy and -c checks (documented subset).')
