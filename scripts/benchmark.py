#!/usr/bin/env python3
"""Repeatable synthetic offline throughput/RSS baseline and streaming soak."""
import argparse,json,os,resource,struct,subprocess,tempfile,time
from pathlib import Path
from importlib.machinery import SourceFileLoader
fixture=SourceFileLoader('fixtures',str(Path(__file__).with_name('generate-fixtures.py'))).load_module()
p=argparse.ArgumentParser();p.add_argument('--binary',default='target/release/crepe');p.add_argument('--packets',type=int,default=200000);a=p.parse_args();binary=str(Path(a.binary).resolve())
with tempfile.TemporaryDirectory(prefix='crepe-benchmark-') as tmp:
    capture=Path(tmp)/'soak.pcap';packet=fixture.frame(4,17,50000,9999,payload=b'baseline')
    with capture.open('wb') as f:
        f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for n in range(a.packets):f.write(struct.pack('<IIII',1700000000+n//10000,n%10000*100,len(packet),len(packet))+packet)
    results=[]
    for command in [['read',str(capture),'proto == udp','--format','json'],['flows',str(capture),'--format','json'],['analyze',str(capture)]]:
        before=time.perf_counter()
        with open(os.devnull,'w') as sink:subprocess.run([binary,*command],stdout=sink,check=True)
        elapsed=time.perf_counter()-before;rss=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        results.append({'command':command[0],'packets':a.packets,'seconds':round(elapsed,3),'packets_per_second':round(a.packets/elapsed),'peak_child_rss_bytes':rss if os.uname().sysname=='Darwin' else rss*1024})
    print(json.dumps(results,indent=2))
