#!/usr/bin/env python3
"""Real loopback daemon/metrics/periodic-persistence/SIGTERM smoke test."""
import json, os, selectors, signal, socket, struct, subprocess, tempfile, time
from pathlib import Path
binary = str(Path('target/release/crepe').resolve())
with tempfile.TemporaryDirectory(prefix='crepe-service-') as directory:
    root = Path(directory)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(('127.0.0.1', 0))
        port = server.getsockname()[1]
        interface = 'lo0' if os.uname().sysname == 'Darwin' else 'lo'
        config = root/'sensor.toml'
        config.write_text(f'interface = "{interface}"\nstore = "{root / "history"}"\ndns_port = {port}\n')
        proc = subprocess.Popen([binary, '--serious', '--log-format', 'json', '--metrics', '127.0.0.1:0', 'daemon', '--config', str(config), '--duration', '30'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            line = json.loads(proc.stderr.readline()); assert line['message'].startswith('Metrics listening'), line
            metrics_port = int(line['message'].rsplit(':', 1)[1])
            line = json.loads(proc.stderr.readline()); assert 'Capture ready' in line['message'], line
            query = struct.pack('!6H', 123, 0x100, 1, 0, 0, 0) + b'\x04test\x07example\x00' + struct.pack('!HH', 1, 1)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                for _ in range(1): sender.sendto(query, ('127.0.0.1', port))
            # Ordinary historical queries include the live tail before first Parquet publication.
            hot_deadline = time.monotonic() + 3
            while True:
                hot = subprocess.run([binary, 'query', str(root/'history'), 'event.type == dns.query | count'], capture_output=True, text=True, timeout=5)
                assert hot.returncode == 0, hot.stderr
                if json.loads(hot.stdout)['count'] > 0: break
                assert time.monotonic() < hot_deadline, 'live query did not observe hot data'
                time.sleep(.05)
            assert not list((root/'history/data').rglob('*.parquet')), 'hot test missed the pre-checkpoint interval'
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and not list((root/'history/data').rglob('*.parquet')):
                time.sleep(.05)
            assert list((root/'history/data').rglob('*.parquet')), 'live checkpoint was not published'
            assert proc.poll() is None, 'daemon exited before checkpoint check'
            with socket.create_connection(('127.0.0.1', metrics_port), timeout=2) as client:
                # Split the HTTP request to exercise framing, not just one read().
                client.sendall(b'GET /met'); time.sleep(.01)
                client.sendall(b'rics HTTP/1.1\r\nHost: localhost\r\n\r\n')
                response = bytearray()
                while True:
                    part = client.recv(4096)
                    if not part: break
                    response.extend(part)
            assert b'200 OK' in response and b'crepe_events_total ' in response, response
            events = int(response.split(b'crepe_events_total ')[-1].splitlines()[0]); assert events > 0
            proc.send_signal(signal.SIGTERM)
            _, err = proc.communicate(timeout=8)
            assert proc.returncode == 0, err
            assert (root/'history/writer.lock').read_bytes() == b''
            result = subprocess.run([binary, 'query', str(root/'history'), 'event.type == dns.query | count'], capture_output=True, text=True, timeout=15)
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout)['count'] > 0
        finally:
            if proc.poll() is None: proc.kill(); proc.communicate()
        # A hard crash releases the OS lock; the next session discards only its unpublished tail.
        crashed = subprocess.Popen([binary, '--serious', 'daemon', '--config', str(config), '--duration', '30'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            assert 'Capture ready' in crashed.stderr.readline()
            assert list((root/'history').glob('.staging-*'))
            crashed.kill(); crashed.communicate(timeout=5)
            assert (root/'history/writer.lock').read_text().startswith('crepe-lock-v1 ')
            restarted = subprocess.run([binary, '--serious', 'daemon', '--config', str(config), '--duration', '1'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=10)
            assert restarted.returncode == 0, restarted.stderr
            assert not list((root/'history').glob('.staging-*'))
            result = subprocess.run([binary, 'query', str(root/'history'), 'event.type == dns.query | count'], capture_output=True, text=True, check=True)
            assert json.loads(result.stdout)['count'] > 0, 'published data was lost during recovery'
        finally:
            if crashed.poll() is None: crashed.kill(); crashed.communicate()
print('PASS: daemon checkpoints, metrics, SIGTERM, SIGKILL recovery and retained history.')
