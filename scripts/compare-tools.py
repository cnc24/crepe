#!/usr/bin/env python3
"""Local, synthetic comparison; requires native Zeek and SiLK, never downloads tools.

Writes raw logs, captures, commands, per-process measurements and results to a
NEW output directory. This is not a line-rate or production-readiness benchmark.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import random
import selectors
import shutil
import socket
import statistics
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]

def jsonl(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--crepe', default=str(ROOT/'target/release/crepe'))
    parser.add_argument('--zeek', default='zeek')
    parser.add_argument('--silk-bin', type=Path, required=True)
    parser.add_argument('--flows', type=int, default=10000)
    parser.add_argument('--packets-per-flow', type=int, default=20)
    parser.add_argument('--export-records', type=int, default=3000)
    parser.add_argument('--repeats', type=int, default=5)
    a = parser.parse_args()
    if not 1 <= a.flows <= 40000 or a.packets_per_flow < 2 or a.repeats < 3 or not 1 <= a.export_records <= 10000:
        parser.error('flows 1..40000, packets-per-flow >=2, repeats >=3, export-records 1..10000')
    out = a.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    crepe = str(Path(a.crepe).resolve()); zeek = shutil.which(a.zeek)
    if not zeek: raise SystemExit('Zeek is required')
    silk = {n: str((a.silk_bin/n).resolve()) for n in ['rwpdu2silk', 'rwcut', 'rwfilter', 'rwuniq']}
    commands = []
    def run(label, command, cwd=None):
        folder = out/label; folder.mkdir(parents=True, exist_ok=False)
        started = time.perf_counter()
        with (folder/'stdout').open('wb') as stdout, (folder/'stderr').open('wb') as stderr:
            proc = subprocess.Popen(list(map(str, command)), cwd=cwd or folder, stdout=stdout, stderr=stderr)
            _, status, usage = os.wait4(proc.pid, 0)
            proc.returncode = os.waitstatus_to_exitcode(status)
        record = dict(label=label, command=list(map(str, command)), cwd=str(cwd or folder),
                      seconds=time.perf_counter()-started, exit_code=proc.returncode,
                      peak_rss_bytes=usage.ru_maxrss*(1 if platform.system()=='Darwin' else 1024))
        commands.append(record)
        (out/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
        if proc.returncode: raise RuntimeError(f'{label} failed: {(folder/"stderr").read_text()}')
        return record
    versions = {}
    for name, cmd in [('crepe',[crepe,'--version']),('zeek',[zeek,'--version']),('silk',[silk['rwcut'],'--version'])]:
        run('version-'+name,cmd);versions[name]=(out/('version-'+name)/'stdout').read_text().strip()
    spec=importlib.util.spec_from_file_location('fixture',ROOT/'scripts/generate-fixtures.py')
    fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    checks = {}
    for name in ['dns','protocols','flows','fragments']:
        capture=(ROOT/'fixtures'/f'{name}.pcap').resolve()
        run('crepe-'+name,[crepe,'analyze' if name!='flows' else 'flows',capture,'--format','json'])
        run('zeek-'+name,[zeek,'-r',capture,'LogAscii::use_json=T'])
    cp=jsonl(out/'crepe-protocols/stdout')
    protocols=[r['protocol'] for r in cp if r.get('protocol')]
    zs=jsonl(out/'zeek-protocols/ssl.log'); zh=jsonl(out/'zeek-protocols/http.log');zssh=jsonl(out/'zeek-protocols/ssh.log')
    checks['tls_sni']=any(p.get('server_name')=='example.test' for p in protocols) and any(p.get('server_name')=='example.test' for p in zs)
    checks['http_host_method_uri']=any(p.get('host')=='example.test' and p.get('method')=='GET' and p.get('target')=='/research' for p in protocols) and any(p.get('host')=='example.test' and p.get('method')=='GET' and p.get('uri')=='/research' for p in zh)
    checks['ssh_banner']=any(p.get('identification')=='SSH-2.0-CrepeFixture' for p in protocols) and any('SSH-2.0-CrepeFixture' in (p.get('client',''),p.get('server','')) for p in zssh)
    cd=jsonl(out/'crepe-dns/stdout');zd=jsonl(out/'zeek-dns/dns.log')
    checks['dns_question']=any(q['name'].rstrip('.')=='example.test' for r in cd if r.get('dns') for q in r['dns']['questions']) and any(r.get('query')=='example.test' for r in zd)
    checks['dns_answer']=any(v.get('data',{}).get('value')=='203.0.113.7' for r in cd if r.get('dns') for v in r['dns']['answers']) and any('203.0.113.7' in r.get('answers',[]) for r in zd)
    def flowmap(rows, kind):
        result={}
        for r in rows:
            if kind=='crepe':
                endpoints=[(r['a']['ip'],r['a']['port']),(r['b']['ip'],r['b']['port'])];proto=r['proto'];packets=r['packets_a']+r['packets_b'];ipbytes=r['bytes_a']+r['bytes_b']-14*packets
            else:
                endpoints=[(r['id.orig_h'],r['id.orig_p']),(r['id.resp_h'],r['id.resp_p'])];proto=r['proto'];packets=r['orig_pkts']+r['resp_pkts'];ipbytes=r['orig_ip_bytes']+r['resp_ip_bytes']
            key=repr((proto,sorted(endpoints)));prior=result.get(key,(0,0));result[key]=(prior[0]+packets,prior[1]+ipbytes)
        return result
    cf=jsonl(out/'crepe-flows/stdout');zf=jsonl(out/'zeek-flows/conn.log')
    checks['fixture_flow_packets_ip_bytes']=flowmap(cf,'crepe')==flowmap(zf,'zeek')
    # Record edge-case observations, without treating output row counts as comparable semantics.
    edge={}
    for name in ['dns','fragments']:
        c=jsonl(out/f'crepe-{name}/stdout'); z=out/f'zeek-{name}'
        edge[name]={'crepe_event_types':{t:sum(r['event_type']==t for r in c) for t in sorted({r['event_type'] for r in c})},'zeek_log_rows':{p.name:len(jsonl(p)) for p in z.glob('*.log')}}
    capture=out/'udp.pcap'
    with capture.open('wb') as f:
        f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for n in range(a.flows*a.packets_per_flow):
            flow=n//a.packets_per_flow;reverse=bool(n%2)
            packet=fixture.frame(4,17,10000+flow,9999,reverse=reverse,payload=b'comparison-data!')
            f.write(struct.pack('<IIII',1700000000+n//100000,n%100000*10,len(packet),len(packet))+packet)
    def bench_crepe(label): return [run(label,[crepe,'flows',capture,'--format','json'])]
    def bench_zeek(label): return [run(label,[zeek,'-r',capture,'LogAscii::use_json=T'])]
    def bench_zeek_conn(label): return [run(label,[zeek,'-b','-r',capture,'base/protocols/conn','LogAscii::use_json=T'])]
    bench_crepe('warmup-crepe-flows');bench_zeek('warmup-zeek-flows');bench_zeek_conn('warmup-zeek-conn')
    c=flowmap(jsonl(out/'warmup-crepe-flows/stdout'),'crepe');z=flowmap(jsonl(out/'warmup-zeek-flows/conn.log'),'zeek')
    checks['generated_udp_flows_packets_ip_bytes']=c==z and len(c)==a.flows and sum(v[0] for v in c.values())==a.flows*a.packets_per_flow
    checks['generated_udp_zeek_conn_only']=c==flowmap(jsonl(out/'warmup-zeek-conn/conn.log'),'zeek')
    # Identical NetFlow v5 records: raw UDP to Crepe, padded Cisco PDU file to SiLK.
    datagrams=[]; expected=[]
    for start in range(0,a.export_records,30):
        records=[]
        for i in range(start,min(start+30,a.export_records)):
            proto=17 if i%3==1 else 6;dport=[443,53,80][i%3];packets=1+i%20;size=packets*(60+i%200)
            b=bytearray(48);b[:8]=bytes([192,0,2,10,198,51,100,20]);b[16:32]=struct.pack('!IIII',packets,size,90000,95000);b[32:36]=struct.pack('!HH',10000+i,dport);b[37]=0x10 if proto==6 else 0;b[38]=proto
            records.append(b);expected.append((10000+i,dport,proto,packets,size))
        datagrams.append(struct.pack('!HHIIIIBBH',5,len(records),100000,1700000000,0,start,0,1,0)+b''.join(records))
    pdus=out/'exports.pdu';pdus.write_bytes(b''.join(d.ljust(1464,b'\0') for d in datagrams));sf=out/'exports.rw'
    run('silk-import',[silk['rwpdu2silk'],f'--silk-output={sf}',pdus])
    run('silk-records',[silk['rwcut'],'--fields=sport,dport,protocol,packets,bytes','--no-titles','--delimited=,',sf])
    got=[tuple(map(int,line.rstrip(',').split(','))) for line in (out/'silk-records/stdout').read_text().splitlines()]
    checks['silk_export_records']=sorted(got)==sorted(expected)
    store=out/'history';log=out/'collector.jsonl'
    with log.open('w') as dest:
        cmd=[crepe,'collect','--listen','127.0.0.1:0','--duration','30','--count',str(len(datagrams)),'--store',str(store)]
        proc=subprocess.Popen(cmd,stdout=dest,stderr=subprocess.PIPE,text=True)
        try:
            with selectors.DefaultSelector() as sel:
                sel.register(proc.stderr,selectors.EVENT_READ)
                if not sel.select(15):raise RuntimeError('collector readiness timeout')
                line=proc.stderr.readline();port=int(line.strip().rsplit(':',1)[1])
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                for data in datagrams:sock.sendto(data,('127.0.0.1',port));time.sleep(.005)
            _,err=proc.communicate(timeout=35)
            (out/'collector.stderr').write_text(line+err)
            if proc.returncode:raise RuntimeError(err)
        finally:
            if proc.poll() is None:proc.kill();proc.communicate()
    run('crepe-export-records',[crepe,'query',store,'event.type == flow.export | select src.port,dst.port,proto,packets,bytes'])
    rows=jsonl(out/'crepe-export-records/stdout')
    got=[(r['src_port'],r['dst_port'],{'tcp':6,'udp':17}[r['proto']],r['packets'],r['bytes']) for r in rows]
    checks['crepe_export_records']=sorted(got)==sorted(expected)
    query='event.type == flow.export && dst.port == 443 | group proto | sum bytes as total'
    def bench_cquery(label):return [run(label,[crepe,'query',store,query])]
    def bench_squery(label):
        selected=out/(label+'.rw')
        one=run(label+'-filter',[silk['rwfilter'],'--dport=443',f'--pass={selected}',sf])
        two=run(label+'-sum',[silk['rwuniq'],'--fields=protocol','--values=bytes','--no-titles','--delimited=,','--sort-output',selected])
        return [one,two]
    bench_cquery('warmup-crepe-query');bench_squery('warmup-silk-query')
    cr=jsonl(out/'warmup-crepe-query/stdout');sr=(out/'warmup-silk-query-sum/stdout').read_text().strip().strip(',').split(',')
    expected_sum=sum(r[4] for r in expected if r[1]==443)
    checks['historical_filtered_byte_sum']=len(cr)==1 and cr[0]['total']==int(sr[1])==expected_sum and sr[0]=='6'
    samples={name:[] for name in ['crepe-flows','zeek-flows','zeek-conn','crepe-query','silk-query']}
    funcs=dict(zip(samples,[bench_crepe,bench_zeek,bench_zeek_conn,bench_cquery,bench_squery]));rng=random.Random(20261004)
    for repetition in range(a.repeats):
        order=list(samples);rng.shuffle(order)
        for name in order:
            measured=funcs[name](f'measured-{repetition}-{name}')
            samples[name].append({'seconds':sum(m['seconds'] for m in measured),'peak_rss_bytes':max(m['peak_rss_bytes'] for m in measured)})
    measurements={name:{'samples':v,'median_seconds':statistics.median(r['seconds'] for r in v),'min_seconds':min(r['seconds'] for r in v),'max_seconds':max(r['seconds'] for r in v),'median_peak_rss_bytes':statistics.median(r['peak_rss_bytes'] for r in v)} for name,v in samples.items()}
    result={'versions':versions,'crepe_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'host':platform.platform(),'machine':platform.machine(),'checks':checks,'edge_observations':edge,'dataset':{'udp_flows':a.flows,'udp_packets':a.flows*a.packets_per_flow,'netflow_records':a.export_records,'expected_filtered_bytes':expected_sum,'sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [capture,pdus,*sorted((ROOT/'fixtures').glob('*.pcap'))]}},'measurements':measurements,'method':'One untimed warmup; seeded mixed order; five repetitions by default; wall clock includes startup and output. wait4 records fresh per-process peak RSS. SiLK query time is the sum of sequential filter and aggregate processes; RSS is their maximum, not a sum. Page caches are not cleared. Flow extraction: Crepe flows vs Zeek default scripts and bare mode with base/protocols/conn; output/schema/work differ. Query: same logical filter/sum, different native storage/layout. No universal speed or safety ranking.'}
    (out/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'checks':checks,'measurements':measurements},indent=2))
    if not all(checks.values()):raise SystemExit('Some comparison checks differ; inspect results before drawing conclusions')

if __name__=='__main__':main()
