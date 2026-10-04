#!/usr/bin/env python3
"""Local TCP protocol servers, UDP exporters, persistence, restart/query/trace checks."""
import argparse,json,os,selectors,socket,ssl,struct,subprocess,tempfile,threading,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--binary',default='target/release/crepe');p.add_argument('--interface',default='lo0' if os.uname().sysname=='Darwin' else 'lo');p.add_argument('--offline',action='store_true');a=p.parse_args();binary=str(Path(a.binary).resolve())
def run(*args):
    r=subprocess.run([binary,*map(str,args)],capture_output=True,text=True,timeout=45)
    assert r.returncode==0,(args,r.stderr)
    return [json.loads(x) for x in r.stdout.splitlines()]
def ready(proc,text):
    with selectors.DefaultSelector() as s:
        s.register(proc.stderr,selectors.EVENT_READ);assert s.select(15),'readiness timeout'
        line=proc.stderr.readline();assert text in line,line

def set_(id,body):return struct.pack('!HH',id,4+len(body))+body
def export(version):
    if version==5:
        h=struct.pack('!HHIIIIBBH',5,1,1000,1700000000,0,0,0,1,0)
        b=bytearray(48);b[:8]=bytes([10,0,0,1,10,0,0,2]);b[16:24]=struct.pack('!II',2,1234);b[32:36]=struct.pack('!HH',50000,443);b[38]=6
        return h+b
    fields=[(8,4),(12,4),(7,2),(11,2),(4,1),(1,4),(2,4)]
    t=set_(0 if version==9 else 2,struct.pack('!HH',256,len(fields))+b''.join(struct.pack('!HH',*f) for f in fields))
    d=set_(256,bytes([10,0,0,1,10,0,0,2])+struct.pack('!HHBII',50000,443,6,1234,2))
    h=struct.pack('!HHIIII',9,2,1000,1700000000,0,1) if version==9 else struct.pack('!HHIII',10,16+len(t+d),1700000000,0,1)
    return h+t+d
with tempfile.TemporaryDirectory(prefix='crepe-platform-') as td:
    td=Path(td);store=td/'history'
    run('ingest','fixtures/protocols.pcap','--store',store,'--sensor','lab')
    run('ingest','fixtures/fragments.pcap','--store',store,'--sensor','lab')
    rows=run('query',store,'event.type == tls.client_hello');assert len(rows)==1
    assert len(run('trace',store,rows[0]['flow_id']))==5
    assert run('query',store,'event.type == dns.query | count')[0]['count']==2
    assert len(run('timeline',store,'--limit','3'))==3
    repeated=subprocess.run([binary,'ingest','fixtures/protocols.pcap','--store',str(store),'--sensor','lab'],capture_output=True);assert repeated.returncode!=0
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
        proc=subprocess.Popen([binary,'collect','--listen','127.0.0.1:0','--duration','10','--count','3','--store',str(store),'--sensor','lab'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            with selectors.DefaultSelector() as s:
                s.register(proc.stderr,selectors.EVENT_READ);assert s.select(15)
                line=proc.stderr.readline();port=int(line.strip().rsplit(':',1)[1])
            for v in [5,9,10]:sender.sendto(export(v),('127.0.0.1',port))
            out,err=proc.communicate(timeout=15);assert proc.returncode==0,err
            assert [r['version'] for r in map(json.loads,out.splitlines())]==[5,9,10]
            assert run('query',store,'event.type == flow.export | group proto')[0]['bytes']==3702
        finally:
            if proc.poll() is None:proc.kill();proc.communicate()
    print('PASS: atomic import, restart/query/group/trace/timeline and v5/v9/IPFIX UDP → Parquet.')
    if not a.offline:
        # Actual TLS handshake with a throwaway localhost certificate, plus HTTP and SSH.
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(td/'key.pem'),'-out',str(td/'cert.pem'),'-days','1','-subj','/CN=localhost'],check=True,capture_output=True)
        for proto in ['http','ssh','tls']:
            with socket.socket() as server:
                server.bind(('127.0.0.1',0));server.listen(1);server.settimeout(5);port=server.getsockname()[1];capture=td/f'{proto}.pcap'
                proc=subprocess.Popen([binary,'capture','-i',a.interface,'--bpf',f'tcp and host 127.0.0.1 and port {port}','--duration','3','--write',str(capture),'--format','json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                errors=[]
                def serve():
                    try:
                        conn,_=server.accept()
                        with conn:
                            conn.settimeout(4)
                            if proto=='tls':
                                ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(td/'cert.pem',td/'key.pem');ctx.set_alpn_protocols(['h2'])
                                with ctx.wrap_socket(conn,server_side=True) as secure:assert secure.recv(4)==b'ping';secure.sendall(b'pong')
                            elif proto=='http':
                                request=b''
                                while b'\r\n\r\n' not in request:request+=conn.recv(1024)
                                conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nServer: CrepeLocal\r\n\r\nOK')
                            else:conn.sendall(b'SSH-2.0-CrepeLocal\r\n');assert conn.recv(128).startswith(b'SSH-2.0-')
                    except BaseException as e:errors.append(e)
                try:
                    ready(proc,'Capture ready');worker=threading.Thread(target=serve,daemon=True);worker.start()
                    with socket.create_connection(('127.0.0.1',port),timeout=4) as client:
                        if proto=='tls':
                            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE;ctx.set_alpn_protocols(['h2'])
                            with ctx.wrap_socket(client,server_hostname='localhost') as secure:secure.sendall(b'ping');assert secure.recv(4)==b'pong'
                        elif proto=='http':
                            client.sendall(b'GET /local HTTP/1.1\r\n');time.sleep(.04);client.sendall(b'Host: localhost\r\n\r\n');assert b'200 OK' in client.recv(4096)
                        else:assert client.recv(128).startswith(b'SSH-2.0-');client.sendall(b'SSH-2.0-CrepeClient\r\n')
                    worker.join(5);assert not worker.is_alive() and not errors,errors
                    _,err=proc.communicate(timeout=10);assert proc.returncode==0,err
                    events=run('analyze',capture);kinds=[e['protocol']['type'] for e in events if e.get('protocol')]
                    expected={'http':['http_request','http_response','file_metadata'],'ssh':['ssh_banner','ssh_banner'],'tls':['tls_client_hello','tls_server_hello']}[proto]
                    assert sorted(kinds)==sorted(expected),(proto,events)
                    if proto == 'http':
                        import hashlib
                        file = next(e['protocol'] for e in events if e.get('protocol', {}).get('type') == 'file_metadata')
                        assert file['size'] == 2 and file['sha256'] == hashlib.sha256(b'OK').hexdigest()
                    run('ingest',capture,'--store',store,'--sensor','lab')
                    print(f'PASS: actual local {proto.upper()} connection → capture → metadata → Parquet.')
                finally:
                    if proc.poll() is None:proc.kill();proc.communicate()
print('All temporary captures, certificates and stores removed.')
