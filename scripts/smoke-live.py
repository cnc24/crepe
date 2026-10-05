#!/usr/bin/env python3
"""Bounded live test using only locally generated loopback UDP traffic.
Requires a --features live build and existing capture permissions. Never uses sudo.
"""
import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--binary', default='target/release/crepe')
parser.add_argument('--interface', default='lo0' if os.uname().sysname == 'Darwin' else 'lo')
args = parser.parse_args()
binary = str(Path(args.binary).resolve())

def start(extra):
    process = subprocess.Popen([binary, 'capture', '-i', args.interface, *extra], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    selector = selectors.DefaultSelector()
    selector.register(process.stderr, selectors.EVENT_READ)
    try:
        if not selector.select(8):
            raise RuntimeError('capture did not become ready within 8 seconds')
        line = process.stderr.readline()
        if 'Capture ready' not in line:
            raise RuntimeError(line.strip() or 'capture exited before readiness')
        return process
    except BaseException:
        process.kill()
        process.communicate()
        raise
    finally:
        selector.close()

def finish(process, timeout=8):
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        process.kill()
        process.communicate()
        raise
    assert process.returncode == 0, stderr
    return stdout, stderr

with tempfile.TemporaryDirectory(prefix='crepe-live-') as directory:
    capture = Path(directory) / 'loopback.pcap'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        receiver.bind(('127.0.0.1', 0))
        sender.bind(('127.0.0.1', 0))
        receiver.settimeout(2)
        sender.settimeout(2)
        port = receiver.getsockname()[1]
        bpf = f'udp and host 127.0.0.1 and port {port}'
        process = start(['--bpf', bpf, '--duration', '5', '--count', '2', '--format', 'json', '--write', str(capture), 'proto == udp'])
        try:
            sender.sendto(b'crepe-local-smoke', receiver.getsockname())
            data, address = receiver.recvfrom(512)
            receiver.sendto(data, address)
            assert sender.recvfrom(512)[0] == b'crepe-local-smoke'
            stdout, stderr = finish(process)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        rows = [json.loads(line) for line in stdout.splitlines()]
        assert len(rows) == 2, rows
        assert all(row['src']['ip'] == row['dst']['ip'] == '127.0.0.1' for row in rows)
        assert rows[0]['src'] == rows[1]['dst'] and rows[0]['dst'] == rows[1]['src']
        replay = subprocess.run([binary, 'read', str(capture), '--format', 'json'], check=True, capture_output=True, text=True)
        assert [json.loads(line) for line in replay.stdout.splitlines()] == rows
        flows = subprocess.run([binary, 'flows', str(capture), '--format', 'json'], check=True, capture_output=True, text=True)
        records = [json.loads(line) for line in flows.stdout.splitlines()]
        assert len(records) == 1 and records[0]['packets_a'] == records[0]['packets_b'] == 1
        # Positional tcpdump syntax also works on the native loopback linktype.
        process = start([bpf, '--duration', '3', '--limit', '1', '--format', 'json'])
        try:
            sender.sendto(b'crepe-bpf-smoke', receiver.getsockname())
            assert receiver.recvfrom(512)[0] == b'crepe-bpf-smoke'
            filtered, _ = finish(process)
            selected = [json.loads(line) for line in filtered.splitlines()]
            assert len(selected) == 1 and selected[0]['dst']['port'] == port
        finally:
            if process.poll() is None:
                process.kill(); process.communicate()
        # Same port remains bound, but we send no traffic: duration must still end.
        process = start(['--bpf', bpf, '--duration', '1', '--format', 'json'])
        started = time.monotonic()
        quiet, _ = finish(process, timeout=4)
        assert not quiet and time.monotonic() - started < 4
        process = start(['--bpf', bpf, '--duration', '20', '--format', 'json'])
        process.send_signal(signal.SIGINT)
        interrupted, _ = finish(process, timeout=4)
        assert not interrupted
print('PASS: live UDP request/reply, PCAP replay, bidirectional flow, quiet deadline, SIGINT; temporary captures removed.')
