#!/usr/bin/env python3
"""Exercise local UDP/TCP DNS capture, PCAP export and offline L7 analysis.
Uses ephemeral loopback ports and a synthetic server; no external DNS requests.
"""
import argparse
import json
import os
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import tempfile
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument('--binary', default='target/release/crepe')
parser.add_argument('--interface', default='lo0' if os.uname().sysname == 'Darwin' else 'lo')
args = parser.parse_args()
binary = str(Path(args.binary).resolve())
query = struct.pack('!HHHHHH', 0x1234, 0x100, 1, 0, 0, 0) + b'\x07example\x04test\0' + struct.pack('!HH', 1, 1)
answer = struct.pack('!HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0) + query[12:] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + bytes([203,0,113,7])

def exact(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError('unexpected EOF')
        data += part
    return data

for protocol in ['udp', 'tcp']:
    with tempfile.TemporaryDirectory(prefix='crepe-dns-') as directory, socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == 'udp' else socket.SOCK_STREAM) as server:
        server.bind(('127.0.0.1', 0))
        server.settimeout(4)
        port = server.getsockname()[1]
        if protocol == 'tcp':
            server.listen(1)
        capture = Path(directory) / 'dns.pcap'
        process = subprocess.Popen([binary, 'capture', '-i', args.interface, '--bpf', f'{protocol} and host 127.0.0.1 and port {port}', '--duration', '3', '--format', 'json', '--write', str(capture)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stderr, selectors.EVENT_READ)
                assert selector.select(8), 'capture readiness timeout'
                line = process.stderr.readline()
                assert 'Capture ready' in line, line
            errors = []
            def serve():
                try:
                    if protocol == 'udp':
                        data, address = server.recvfrom(2048)
                        assert data == query
                        server.sendto(answer, address)
                    else:
                        connection, _ = server.accept()
                        with connection:
                            connection.settimeout(3)
                            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                            size = struct.unpack('!H', exact(connection, 2))[0]
                            assert exact(connection, size) == query
                            framed = struct.pack('!H', len(answer)) + answer
                            connection.sendall(framed[:7])
                            time.sleep(0.05)
                            connection.sendall(framed[7:])
                            # Wait for peer closure to exercise FIN and final ACKs.
                            assert connection.recv(1) == b''
                except BaseException as error:
                    errors.append(error)
            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == 'udp' else socket.SOCK_STREAM) as client:
                client.settimeout(3)
                client.connect(('127.0.0.1', port))
                if protocol == 'udp':
                    client.send(query)
                    assert client.recv(2048) == answer
                else:
                    client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    framed = struct.pack('!H', len(query)) + query
                    client.sendall(framed[:5])
                    time.sleep(0.05)
                    client.sendall(framed[5:])
                    size = struct.unpack('!H', exact(client, 2))[0]
                    assert exact(client, size) == answer
            worker.join(timeout=4)
            assert not worker.is_alive() and not errors, errors
            stdout, stderr = process.communicate(timeout=8)
            assert process.returncode == 0, stderr
            result = subprocess.run([binary, 'analyze', str(capture), '--dns-port', str(port)], check=True, capture_output=True, text=True)
            events = [json.loads(line) for line in result.stdout.splitlines()]
            assert [event['event_type'] for event in events] == ['dns.query', 'dns.response'], events
            assert events[0]['dns']['questions'][0]['name'] == 'example.test.'
            assert events[1]['dns']['answers'][0]['data']['value'] == '203.0.113.7'
            assert not any(event['midstream'] for event in events)
            print(f'PASS: {protocol.upper()} loopback DNS capture → PCAP → query/response analysis.')
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
print('All temporary DNS captures removed.')
