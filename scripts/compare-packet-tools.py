#!/usr/bin/env python3
"""Functional comparison against installed tcpdump, nfpcapd and nfdump.
Only generated/test traffic. No downloads, live capture or root permissions.
Writes commands, raw output and checks to a NEW directory. Not a speed benchmark.
"""
import argparse
from collections import defaultdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--crepe', default=str(ROOT/'target/release/crepe'))
    parser.add_argument('--tcpdump', default='tcpdump')
    parser.add_argument('--nfpcapd', default='nfpcapd')
    parser.add_argument('--nfdump', default='nfdump')
    args = parser.parse_args()
    tools = {name: shutil.which(getattr(args,name)) for name in ('crepe','tcpdump','nfpcapd','nfdump')}
    if not all(tools.values()): parser.error(f'Tools must be installed first: {tools}')
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    commands=[];checks={}
    def run(label,tool,*arguments):
        cmd=[tools[tool],*map(str,arguments)]
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=120,env={**os.environ,'TZ':'UTC'})
        (out/f'{label}.stdout').write_text(p.stdout);(out/f'{label}.stderr').write_text(p.stderr)
        commands.append({'label':label,'command':cmd,'exit_code':p.returncode})
        (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if p.returncode:raise RuntimeError(f'{label}: {p.stderr}')
        return p.stdout
    versions={t:run('version-'+t,t,'--version' if t in ('crepe','tcpdump') else '-V').strip() for t in tools}
    spec=importlib.util.spec_from_file_location('fixture',ROOT/'scripts/generate-fixtures.py')
    f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
    expressions=['tcp','dst port 443','udp and port 53','src net 192.0.2.0/24 and not udp','ip6',
                 'tcp[tcpflags] & tcp-syn != 0','len == 54','dst portrange 50-443']
    files=[ROOT/'example.pcap',ROOT/'fixtures/example.pcapng',ROOT/'fixtures/flows.pcap',ROOT/'fixtures/dns.pcap']
    for index,capture in enumerate(files):
        for j,expression in enumerate(expressions):
            label=f'filter-{index}-{j}'
            selected=out/f'{label}.pcap'
            run(label+'-tcpdump','tcpdump','-nn','-r',capture,'-w',selected,expression)
            actual=run(label+'-crepe','crepe','read',capture,expression,'--format','json')
            expected=run(label+'-replay','crepe','read',selected,'--format','json')
            def packets(text):
                rows=[json.loads(line) for line in text.splitlines()]
                for row in rows: row['header'].pop('sequence')
                return rows
            checks[label]=packets(actual)==packets(expected)
    # Verify visible transport data against tcpdump in absolute-sequence/UTC mode.
    capture=ROOT/'fixtures/flows.pcap'
    c=run('summary-crepe','crepe','read',capture,'dst port 443')
    t=run('summary-tcpdump','tcpdump','-nn','-S','-r',capture,'dst port 443')
    checks['summary_syn_ack_fin_reset']=all(s in c and s in t for s in ['Flags [S]','Flags [.]','Flags [F.]','Flags [R]','win 65535','length 0'])
    checks['summary_utc_time']='22:13:20.123456000Z' in c and '22:13:20.123456' in t
    dns=run('dns-crepe','crepe','read',ROOT/'fixtures/dns.pcap','udp port 53')
    tdns=run('dns-tcpdump','tcpdump','-nn','-r',ROOT/'fixtures/dns.pcap','udp port 53')
    checks['dns_question']='example.test.' in dns and 'example.test.' in tdns and 'DNS response' in dns
    # 1,000 conversations, 20,000 packets, two directions, fixed addresses.
    generated=out/'udp.pcap'
    with generated.open('wb') as dest:
        dest.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for i in range(20000):
            flow=i//20; packet=f.frame(4,17,10000+flow,443 if flow%2 else 9999,reverse=bool(i%2),payload=b'comparison-data!')
            dest.write(struct.pack('<IIII',1700000000+i//10000,i%10000*100,len(packet),len(packet))+packet)
    def crepe_map(text):
        result=defaultdict(lambda:[0,0])
        for r in map(json.loads,text.splitlines()):
            for side,other in [('a','b'),('b','a')]:
                n=r['packets_'+side]
                if not n:continue
                key=(r['proto'],r[side]['ip'],r[side]['port'],r[other]['ip'],r[other]['port'])
                result[key][0]+=n;result[key][1]+=r['bytes_'+side]-14*n
        return dict(result)
    def nf_map(text):
        result=defaultdict(lambda:[0,0])
        for r in map(json.loads,text.splitlines()):
            key=({6:'tcp',17:'udp'}[r['proto']],r.get('src4_addr',r.get('src6_addr')),r['src_port'],r.get('dst4_addr',r.get('dst6_addr')),r['dst_port'])
            result[key][0]+=r['in_packets'];result[key][1]+=r['in_bytes']
        return dict(result)
    summaries={}
    for name,capture in [('fixture',ROOT/'fixtures/flows.pcap'),('generated',generated)]:
        folder=out/(name+'-flows');folder.mkdir()
        run(name+'-nfpcapd','nfpcapd','-r',capture,'-w',folder)
        n=run(name+'-nfdump','nfdump','-R',folder,'-q','-N','-o','ndjson')
        c=run(name+'-crepe-flows','crepe','flows',capture,'--format','json')
        nm=nf_map(n);cm=crepe_map(c)
        checks[name+'-directional-packets-ipbytes']=nm==cm
        summaries[name]={'crepe_rows':len(c.splitlines()),'nfdump_rows':len(n.splitlines()),'packets':sum(v[0] for v in nm.values()),'ip_bytes':sum(v[1] for v in nm.values())}
        for j,expression in enumerate(['dst port 443','port 9999' if name == 'generated' else 'port 53','src net 192.0.2.0/24']):
            # Same predicate in these three cases, but applied at different stages.
            n=run(f'{name}-nf-filter-{j}','nfdump','-R',folder,'-q','-N','-o','ndjson',expression)
            c=run(f'{name}-crepe-flow-filter-{j}','crepe','flows',capture,expression,'--format','json')
            checks[f'{name}-flow-filter-{j}']=nf_map(n)==crepe_map(c)
    result={'versions':versions,'host':platform.platform(),'machine':platform.machine(),
            'dataset':{'conversations':1000,'packets':20000,'sha256':hashlib.sha256(generated.read_bytes()).hexdigest()},
            'checks':checks,'flow_summary':summaries,
            'method':'Functional checks, not timings. Compare direction-normalized TCP/UDP packets and IP bytes (Crepe frame bytes minus 14 Ethernet bytes per packet). Filtered tcpdump exports are decoded to compare the complete selected packet records, except renumbered sequence. Only the listed synthetic datasets and filters were tested; no universal equivalence or production-rate claim.'}
    (out/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    if not all(checks.values()):raise SystemExit('Comparison failed')

if __name__=='__main__':main()
