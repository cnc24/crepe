#!/usr/bin/env python3
"""Sustained synthetic worker pressure with an independently sampled RSS ceiling."""
import argparse, json, subprocess, time
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument('--seconds', type=int, default=60)
p.add_argument('--rss-mib', type=int, default=512)
a = p.parse_args()
binary = Path('target/release/examples/pressure').resolve()
process = subprocess.Popen([str(binary), str(a.seconds)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
peak = 0
try:
    while process.poll() is None:
        sample = subprocess.run(['ps', '-o', 'rss=', '-p', str(process.pid)], capture_output=True, text=True)
        if sample.returncode == 0 and sample.stdout.strip():
            peak = max(peak, int(sample.stdout.strip()) * 1024)
            assert peak <= a.rss_mib * 1024 * 1024, f'RSS limit exceeded: {peak}'
        time.sleep(.25)
    out, err = process.communicate(timeout=5)
    assert process.returncode == 0, err
    result = json.loads(out)
    assert result['packets'] > 1000 and result['anomalies'] > 0
    result['peak_sampled_rss_bytes'] = peak
    print(json.dumps(result, indent=2))
finally:
    if process.poll() is None: process.kill(); process.communicate()
