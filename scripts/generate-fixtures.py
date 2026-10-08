#!/usr/bin/env python3
"""Generate tiny deterministic synthetic captures; no captured user traffic."""
import ipaddress
from pathlib import Path
import struct as s

ROOT = Path(__file__).resolve().parents[1]

def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(s.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535

def frame(version, proto, src_port=0, dst_port=0, reverse=False, flags=2, payload=b'', sequence=1):
    src = ipaddress.ip_address('192.0.2.10' if version == 4 else '2001:db8::10').packed
    dst = ipaddress.ip_address('198.51.100.20' if version == 4 else '2001:db8::20').packed
    if reverse:
        src, dst = dst, src
        src_port, dst_port = dst_port, src_port
    if proto == 6:
        transport = s.pack('!HHIIBBHHH', src_port, dst_port, sequence, 0, 0x50, flags, 65535, 0, 0)
        check_offset = 16
    elif proto == 17:
        transport = s.pack('!HHHH', src_port, dst_port, 8 + len(payload), 0)
        check_offset = 6
    else:
        transport = s.pack('!BBHHH', 8 if version == 4 else 128, 0, 0, 1, 1)
        check_offset = 2
    transport += payload
    pseudo = src + dst + (s.pack('!BBH', 0, proto, len(transport)) if version == 4 else s.pack('!I3xB', len(transport), proto))
    c = checksum((b'' if proto == 1 else pseudo) + transport)
    transport = transport[:check_offset] + s.pack('!H', c or 65535) + transport[check_offset + 2:]
    if version == 4:
        ip = s.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(transport), 1, 0, 64, proto, 0, src, dst)
        ip = ip[:10] + s.pack('!H', checksum(ip)) + ip[12:]
    else:
        ip = s.pack('!IHBB16s16s', 6 << 28, len(transport), proto, 64, src, dst)
    return bytes.fromhex('020000000002020000000001') + s.pack('!H', 0x0800 if version == 4 else 0x86dd) + ip + transport

PACKETS = [frame(4, 6, 50000, 443), frame(4, 17, 53000, 53), frame(6, 6, 50001, 443), frame(6, 17, 53001, 53), frame(4, 1), frame(6, 58)]

def pcap(endian='<', nano=False, packets=PACKETS):
    data = s.pack(endian + 'IHHIIII', 0xa1b23c4d if nano else 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for i, packet in enumerate(packets):
        data += s.pack(endian + 'IIII', 1700000000 + i, 123456789 if nano else 123456, len(packet), len(packet)) + packet
    return data

def block(kind, body, endian='<'):
    body += b'\0' * (-len(body) % 4)
    return s.pack(endian + 'II', kind, len(body) + 12) + body + s.pack(endian + 'I', len(body) + 12)

def pcapng(endian='<', resolution=6, offset=0, simple=False):
    data = block(0x0a0d0d0a, s.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, -1), endian)
    options = s.pack(endian + 'HHB3x', 9, 1, resolution) + s.pack(endian + 'HHq', 14, 8, offset) + b'\0' * 4
    data += block(1, s.pack(endian + 'HHI', 1, 0, 65535) + options, endian)
    units = (2 ** (resolution & 127)) if resolution & 128 else 10 ** resolution
    for i, packet in enumerate(PACKETS):
        ticks = (1700000000 + i) * units + units // 2
        if simple:
            data += block(3, s.pack(endian + 'I', len(packet)) + packet, endian)
        else:
            data += block(6, s.pack(endian + 'IIIII', 0, ticks >> 32, ticks & 0xffffffff, len(packet), len(packet)) + packet, endian)
    return data

if __name__ == '__main__':
    ROOT.joinpath('example.pcap').write_bytes(pcap())
    files = {'example.pcapng': pcapng(), 'big-endian.pcap': pcap('>'), 'nanosecond.pcap': pcap(nano=True), 'big-endian.pcapng': pcapng('>'), 'binary-resolution.pcapng': pcapng(resolution=0x8a, offset=-1), 'simple.pcapng': pcapng(simple=True), 'multi-section.pcapng': pcapng() + pcapng('>', resolution=9)}
    files['flows.pcap'] = pcap(packets=[
        frame(4, 6, 50000, 443),
        frame(4, 6, 50000, 443, reverse=True, flags=0x12),
        frame(4, 6, 50000, 443, flags=0x10),
        frame(4, 17, 53000, 53),
        frame(4, 17, 53000, 53, reverse=True),
        frame(4, 6, 50000, 443, flags=0x11),
        frame(4, 6, 50000, 443, reverse=True, flags=0x11),
        frame(4, 6, 50002, 443, flags=4),
    ])
    query = s.pack('!HHHHHH', 0x1234, 0x100, 1, 0, 0, 0) + b'\x07example\x04test\0' + s.pack('!HH', 1, 1)
    response = s.pack('!HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0) + query[12:] + b'\xc0\x0c' + s.pack('!HHIH', 1, 1, 60, 4) + bytes([203, 0, 113, 7])
    framed = s.pack('!H', len(query)) + query
    reply = s.pack('!H', len(response)) + response
    files['dns.pcap'] = pcap(packets=[
        frame(4, 17, 53000, 53, payload=query),
        frame(4, 17, 53000, 53, reverse=True, payload=response),
        frame(6, 17, 53000, 53, payload=query),
        frame(4, 6, 50000, 53, sequence=100),
        frame(4, 6, 50000, 53, reverse=True, flags=0x12, sequence=500),
        frame(4, 6, 50000, 53, flags=0x10, sequence=111, payload=framed[10:]),
        frame(4, 6, 50000, 53, flags=0x10, sequence=101, payload=framed[:10]),
        frame(4, 6, 50000, 53, flags=0x10, sequence=101, payload=framed[:10]),
        frame(4, 6, 50000, 53, reverse=True, flags=0x10, sequence=501, payload=reply),
        frame(4, 6, 50000, 53, flags=0x11, sequence=101 + len(framed)),
        frame(4, 6, 50000, 53, reverse=True, flags=0x11, sequence=501 + len(reply)),
    ])
    files['dns-malformed.pcap'] = pcap(packets=[
        frame(4, 17, 53000, 53, payload=b'\x12\x34'),
        frame(4, 6, 50000, 53, sequence=100),
        frame(4, 6, 50000, 53, flags=0x10, sequence=101, payload=framed[:5]),
    ])
    # Split/reordered HTTP and SSH, deterministic TLS ClientHello with SNI and ALPN.
    host = b'example.test'
    extensions = s.pack('!HHHBH', 0, len(host)+5, len(host)+3, 0, len(host)) + host
    extensions += bytes.fromhex('002b0003020304001000050003026832')
    hello = b'\x03\x03' + bytes(range(32)) + bytes.fromhex('00000213010100') + s.pack('!H',len(extensions)) + extensions
    handshake = b'\x01' + len(hello).to_bytes(3,'big') + hello
    tls = b'\x16\x03\x03' + s.pack('!H',len(handshake)) + handshake
    app_packets = []
    for port, payload in [(443,tls),(80,b'GET /research HTTP/1.1\r\nHost: example.test\r\n\r\n'),(22,b'SSH-2.0-CrepeFixture\r\n')]:
        app_packets += [frame(4,6,50000+port,port,sequence=100),frame(4,6,50000+port,port,sequence=109,flags=16,payload=payload[8:]),frame(4,6,50000+port,port,sequence=101,flags=16,payload=payload[:8])]
    files['protocols.pcap'] = pcap(packets=app_packets)
    # One DNS answer followed by two distinct TLS connections reusing the tuple.
    story_response = s.pack('!HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0) + query[12:] + bytes.fromhex('c00c') + s.pack('!HHIH', 1, 1, 60, 4) + bytes([198,51,100,20])
    story = [frame(4,17,53000,53,payload=query), frame(4,17,53000,53,reverse=True,payload=story_response)]
    for seq in [100,1000]:
        story += [frame(4,6,50443,443,sequence=seq), frame(4,6,50443,443,sequence=seq+1,flags=24,payload=tls), frame(4,6,50443,443,reverse=True,flags=4)]
    files['target-story.pcap'] = pcap(packets=story)
    fragments = []
    for version in [4,6]:
        full = frame(version,17,53000,53,payload=query)
        eth, ip = full[:14], full[14:]
        length = 20 if version == 4 else 40
        payload = ip[length:]
        pieces = []
        for offset, part, more in [(0,payload[:16],True),(16,payload[16:],False)]:
            header = bytearray(ip[:length])
            if version == 4:
                header[2:4] = s.pack('!H',20+len(part));header[6:8] = s.pack('!H',offset//8 | (0x2000 if more else 0));header[10:12]=b'\0\0';header[10:12]=s.pack('!H',checksum(bytes(header)))
                pieces.append(eth+header+part)
            else:
                header[4:6]=s.pack('!H',8+len(part));header[6]=44
                pieces.append(eth+header+s.pack('!BBHI',17,0,offset|int(more),42)+part)
        fragments += list(reversed(pieces))
    files['fragments.pcap'] = pcap(packets=fragments)
    # Packet display and application filters: HTTP on a nonstandard port, ARP and VLAN LLDP.
    eth = bytes.fromhex('ffffffffffff020000000001')
    arp = s.pack('!HHBBH',1,0x0800,6,4,1) + bytes.fromhex('020000000001') + bytes([192,0,2,10]) + bytes(6) + bytes([192,0,2,1])
    display_packets = [eth+s.pack('!H',0x0806)+arp,
        eth+s.pack('!HHH',0x8100,7,0x88cc)+bytes.fromhex('0207040200000000010403057030060200780000'),
        frame(4,6,50123,8088,flags=24,payload=b'GET /search?q=crepe HTTP/1.1\r\nHost: example.test\r\nX-Test: \x1b[31munsafe\r\n\r\n'),
        frame(4,6,50123,8088,reverse=True,flags=24,payload=b'HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nhello web'),
        frame(4,6,50080,80,flags=24,payload=b'not an HTTP request'),
        eth+s.pack('!H',0x88b5)+b'opaque protocol']
    files['packet-display.pcap'] = pcap(packets=display_packets)
    for name, data in files.items():
        ROOT.joinpath('fixtures', name).write_bytes(data)
