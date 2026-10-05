#!/usr/bin/env python3
"""Verify direct recipes, terminal source selection and real loopback traffic."""
import json
import os
import pty
import selectors
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

binary = str(Path('target/release/crepe').resolve())

def ready(proc, marker):
    deadline = time.monotonic() + 10
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stderr, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            assert remaining > 0 and selector.select(remaining), 'readiness timeout'
            data = bytearray()
            while not data.endswith(b'\n'):
                byte = os.read(proc.stderr.fileno(), 1)
                assert byte, 'unexpected end of readiness output'
                data.extend(byte)
            line = data.decode()
            if marker in line:
                return line

def finish(proc):
    out, err = proc.communicate(timeout=15)
    assert proc.returncode == 0, err
    return [json.loads(line) for line in out.splitlines()]

with tempfile.TemporaryDirectory(prefix='crepe-recipe-smoke-') as directory:
    directory = Path(directory)
    # Bare recipes explain their purpose before prompting, without polluting JSON data.
    for recipe in ['chocolate', 'suzette', 'maison', 'complete']:
        for serious in [False, True]:
            master, slave = pty.openpty()
            command = [binary, recipe] + (['--serious'] if serious else [])
            proc = subprocess.Popen(command, stdin=slave, cwd=directory,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            os.close(slave)
            try:
                ready(proc, recipe.capitalize() + ':')
                if not serious:
                    ready(proc, 'Bon appétit!')
                ready(proc, 'Choose a source:' if serious else 'Choose your ingredients:')
                os.write(master, f'1\n{Path("fixtures/protocols.pcap").resolve()}\n'.encode())
                rows = finish(proc)
                assert any(row['event_type'] == 'tls.client_hello' for row in rows)
            finally:
                os.close(master)
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()
    print('PASS: bare recipe descriptions, flair/serious menus and clean JSON TLS observations.')

    # Suzette also retains a live forensic case without an explicit --store.
    forensic_root = directory / 'live-forensics'
    forensic_root.mkdir()
    interface = 'lo0' if os.uname().sysname == 'Darwin' else 'lo'
    proc = subprocess.Popen([binary, 'suzette', '-i', interface, '--duration', '1'],
                            cwd=forensic_root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready(proc, 'Capture ready')
        finish(proc)
        stores = list(forensic_root.glob('crepe-cases/case-*/history'))
        assert len(stores) == 1 and (stores[0] / 'schema.json').exists()
        subprocess.run([binary, 'query', str(stores[0]), '* | count'],
                       check=True, capture_output=True, text=True, timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill(); proc.communicate()
    print('PASS: Suzette retains a queryable live case without --store.')

    # Real local DNS datagram through live Chocolate, including custom DNS port.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(('127.0.0.1', 0))
        server.settimeout(3)
        port = server.getsockname()[1]
        config = directory / 'config.toml'
        config.write_text(f'dns_port = {port}\n')
        interface = 'lo0' if os.uname().sysname == 'Darwin' else 'lo'
        proc = subprocess.Popen([binary, 'chocolate', '-i', interface, '--duration', '2',
                                 '--config', str(config), '--store', str(directory / 'history')],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            ready(proc, 'Capture ready')
            query = struct.pack('!6H', 123, 0x100, 1, 0, 0, 0) + b'\x04test\x07example\x00' + struct.pack('!HH', 1, 1)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(query, ('127.0.0.1', port))
                assert server.recvfrom(1024)[0] == query
            # A result must be observable while the capture is still running.
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                assert selector.select(1), 'no streaming observation before capture completion'
                first_line = bytearray()
                while not first_line.endswith(b'\n'):
                    byte = os.read(proc.stdout.fileno(), 1)
                    assert byte, 'unexpected end of streaming output'
                    first_line.extend(byte)
                first = json.loads(first_line)
                assert proc.poll() is None, 'result only appeared after capture stopped'
            rows = [first] + finish(proc)
            assert any(row['event_type'] == 'dns.query' for row in rows)
            assert any(row['event_type'] == 'flow.end' for row in rows)
            assert (directory / 'history' / 'schema.json').exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
    print('PASS: crepe chocolate live loopback -> DNS + flows + persistent history.')

    proc = subprocess.Popen([binary, 'banane', '--listen', 'udp://127.0.0.1:0',
                             '--count', '1', '--duration', '5'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = ready(proc, 'Collector listening')
        port = int(line.strip().rsplit(':', 1)[1])
        header = struct.pack('!HHIIIIBBH', 5, 1, 1000, 1700000000, 0, 0, 0, 1, 0)
        record = bytearray(48)
        record[:8] = bytes([10, 0, 0, 1, 10, 0, 0, 2])
        record[16:24] = struct.pack('!II', 2, 1234)
        record[32:36] = struct.pack('!HH', 50000, 443)
        record[38] = 6
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(header + record, ('127.0.0.1', port))
        rows = finish(proc)
        assert len(rows) == 1 and rows[0]['version'] == 5
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()
    print('PASS: crepe banane udp:// listener -> actual NetFlow v5 datagram.')


    proc = subprocess.Popen([binary, 'complete', '-i', interface, '--workers', '4', '--listen', '127.0.0.1:0',
                             '--duration', '2', '--store', str(directory / 'combined')],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = ready(proc, 'Collector listening')
        port = int(line.strip().rsplit(':', 1)[1])
        ready(proc, 'Capture ready')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(b'malformed', ('127.0.0.1', port))
            client.sendto(header + record, ('127.0.0.1', port))
        rows = finish(proc)
        assert any(row['event_type'] == 'packet' for row in rows)
        exports = [row for row in rows if row['event_type'] == 'flow.export']
        assert len(exports) == 1 and exports[0]['bytes'] == 1234
        assert any(row['event_type'] == 'anomaly.export' for row in rows)
        assert len({row['event_id'] for row in rows}) == len(rows)
        result = subprocess.run([binary, 'query', str(directory/'combined'), 'event.type == flow.export | count'], capture_output=True, text=True, check=True)
        assert json.loads(result.stdout)['count'] == 1
    finally:
        if proc.poll() is None: proc.kill(); proc.communicate()
    print('PASS: combined live packets + NetFlow + malformed export -> one durable store.')


    proc = subprocess.Popen([binary, 'chocolate', '-i', interface, '--duration', '3',
                             '--workers', '2', '--config', str(config), '--query', '* | group event.type | count', '--query-interval', '1'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready(proc, 'Capture ready')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(query, ('127.0.0.1', int(config.read_text().split('=')[1])))
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            assert selector.select(2), 'no query window before capture completion'
            line = bytearray()
            while not line.endswith(b'\n'): line.extend(os.read(proc.stdout.fileno(), 1))
            first = json.loads(line)
            assert first['event_type'] == 'query.window' and proc.poll() is None
        windows = [first] + finish(proc)
        counts = [row for window in windows for row in window['rows'] if row['event_type'] == 'dns.query']
        assert sum(row['count'] for row in counts) == 1
    finally:
        if proc.poll() is None: proc.kill(); proc.communicate()
    print('PASS: bounded live CQL windows flush on idle ticks before capture ends.')
