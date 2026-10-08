#!/usr/bin/env python3
"""Offline, bounded PCAP/PCAPNG container inventory, never replays packets.
Not an application protocol oracle. Python 3 standard library only.
"""
import collections, gzip, hashlib, json, pathlib, struct, sys
MAX_FILE = 32 << 20
MAX_BLOCK = 16 << 20

def read_bytes(path):
    data = path.read_bytes()
    if len(data) > MAX_FILE:
        raise ValueError('compressed/input file exceeds 32 MiB')
    if data[:2] == b'\x1f\x8b':
        import io
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
            data = f.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise ValueError('decompressed input exceeds 32 MiB')
    return data

def packets(data):
    """Return records with bytes, exact integer timestamp units, per-section IDB."""
    rec, info = [], {'anomalies': [], 'interfaces': [], 'sections': 0, 'decryption_secret_blocks': 0}
    magics = {b'\xd4\xc3\xb2\xa1': ('<', 1000000), b'\xa1\xb2\xc3\xd4': ('>', 1000000), b'\x4d\x3c\xb2\xa1': ('<', 1000000000), b'\xa1\xb2\x3c\x4d': ('>', 1000000000)}
    if data[:4] in magics:
        e, units = magics[data[:4]]
        if len(data) < 24: raise ValueError('truncated pcap global header')
        major, minor, zone, sigfig, snap, link = struct.unpack_from(e+'HHiiII',data,4)
        info.update(format='pcap', endian=e, sections=1)
        info['interfaces']=[{'section':0,'id':0,'link_type':link & 0xffff,'snaplen':snap,'timestamp_units':units}]
        pos=24
        while pos < len(data):
            if len(data)-pos < 16:
                info['anomalies'].append('truncated packet record header'); break
            sec,sub,cap,wire=struct.unpack_from(e+'IIII',data,pos);pos+=16
            if cap > MAX_BLOCK or pos+cap > len(data):
                info['anomalies'].append('truncated/oversize packet record'); break
            if cap > wire: info['anomalies'].append('captured length exceeds wire length')
            if sub >= units: info['anomalies'].append('timestamp fraction outside resolution')
            rec.append({'data':data[pos:pos+cap],'wire':wire,'cap':cap,'link':link & 0xffff,'section':0,'interface':0,'ts':sec*units+sub,'units':units})
            pos+=cap
        return rec,info
    if data[:4] != b'\x0a\x0d\x0d\x0a': raise ValueError('not pcap/pcapng')
    info['format']='pcapng'; pos=0; e=None; ids=[]; section=-1
    while pos < len(data):
        if len(data)-pos < 12:
            info['anomalies'].append('truncated pcapng block header');break
        if data[pos:pos+4]==b'\x0a\x0d\x0d\x0a':
            bom=data[pos+8:pos+12]
            if bom==b'\x4d\x3c\x2b\x1a': e='<'
            elif bom==b'\x1a\x2b\x3c\x4d': e='>'
            else: raise ValueError('invalid pcapng byte-order magic')
            section+=1; ids=[]; info['sections']+=1
        if e is None: raise ValueError('missing section header')
        typ,size=struct.unpack_from(e+'II',data,pos)
        if size<12 or size%4 or size>MAX_BLOCK or pos+size>len(data):
            info['anomalies'].append('invalid/truncated/oversize pcapng block');break
        if struct.unpack_from(e+'I',data,pos+size-4)[0]!=size:
            info['anomalies'].append('pcapng trailing length mismatch');break
        body=data[pos+8:pos+size-4]
        if typ==1:
            if len(body)<8: raise ValueError('short interface block')
            link,_,snap=struct.unpack_from(e+'HHI',body);units=1000000; offset=0; opt=8
            while opt+4<=len(body):
                code,n=struct.unpack_from(e+'HH',body,opt);opt+=4
                if opt+n>len(body): raise ValueError('truncated interface option')
                value=body[opt:opt+n];opt+=(n+3)&~3
                if code==0: break
                if code==9 and n==1:
                    exp=value[0]; units=(2**(exp&127)) if exp&128 else 10**exp
                if code==14 and n==8: offset=struct.unpack(e+'q',value)[0]
            ident={'section':section,'id':len(ids),'link_type':link,'snaplen':snap,'timestamp_units':units,'timestamp_offset':offset}
            ids.append(ident);info['interfaces'].append(ident)
        elif typ in (2,6):
            if len(body)<20: raise ValueError('short packet block')
            if typ==6: i,hi,lo,cap,wire=struct.unpack_from(e+'IIIII',body)
            else:
                i,drop,hi,lo,cap,wire=struct.unpack_from(e+'HHIIII',body)
            if i>=len(ids): raise ValueError('packet references nonexistent interface')
            if cap>MAX_BLOCK or 20+((cap+3)&~3)>len(body): raise ValueError('packet exceeds block')
            if cap>wire: info['anomalies'].append('captured length exceeds wire length')
            ident=ids[i]; ts=(hi<<32)|lo;ts+=ident['timestamp_offset']*ident['timestamp_units']
            rec.append({'data':body[20:20+cap],'wire':wire,'cap':cap,'link':ident['link_type'],'section':section,'interface':i,'ts':ts,'units':ident['timestamp_units']})
        elif typ==3:
            if not ids or len(body)<4: raise ValueError('short simple packet block')
            wire=struct.unpack_from(e+'I',body)[0];snap=ids[0]['snaplen'];cap=min(wire,snap) if snap else wire
            if 4+((cap+3)&~3)>len(body): raise ValueError('simple packet exceeds block')
            rec.append({'data':body[4:4+cap],'wire':wire,'cap':cap,'link':ids[0]['link_type'],'section':section,'interface':0,'ts':None,'units':ids[0]['timestamp_units']})
        elif typ==10: info['decryption_secret_blocks']+=1
        pos+=size
    return rec,info

def transport(record):
    d=record['data']; link=record['link'];p=0;tags=[]
    if link==1:
        if len(d)<14:return {}
        typ=struct.unpack_from('!H',d,12)[0];p=14
        while typ in (0x8100,0x88a8,0x9100) and p+4<=len(d):
            tci,typ=struct.unpack_from('!HH',d,p);tags.append(tci&4095);p+=4
    elif link in (101,228,229): typ=0x86dd if d and d[0]>>4==6 else 0x0800
    elif link in (0,108):
        p=4;typ=0x86dd if len(d)>4 and d[4]>>4==6 else 0x0800
    elif link==113:
        if len(d)<16:return {}
        typ=struct.unpack_from('!H',d,14)[0];p=16
    elif link==276:
        if len(d)<20:return {}
        typ=struct.unpack_from('!H',d)[0];p=20
    else:return {'unsupported_link':link}
    out={'ethertype':typ,'vlan_ids':tags}
    if typ==0x800 and p+20<=len(d):
        ihl=(d[p]&15)*4;total=struct.unpack_from('!H',d,p+2)[0];frag=struct.unpack_from('!H',d,p+6)[0]
        if ihl<20 or p+ihl>len(d): return out
        out.update(ip_version=4,src=d[p+12:p+16].hex(),dst=d[p+16:p+20].hex(),fragment=bool(frag&0x3fff),protocol=d[p+9])
        end=min(len(d),p+total);p+=ihl
        if frag&0x1fff:return out
    elif typ==0x86dd and p+40<=len(d):
        plen=struct.unpack_from('!H',d,p+4)[0];proto=d[p+6];end=min(len(d),p+40+plen)
        out.update(ip_version=6,src=d[p+8:p+24].hex(),dst=d[p+24:p+40].hex(),protocol=proto)
        p+=40
        if proto in (0,43,44,50,51,60):out['extension_header']=True;return out
    else:return out
    proto=out['protocol']
    if proto==17 and p+8<=end:
        sp,dp,n,cs=struct.unpack_from('!HHHH',d,p);out.update(transport='udp',sport=sp,dport=dp,payload=d[p+8:min(end,p+n)])
    elif proto==6 and p+20<=end:
        sp,dp,seq,ack,offflags=struct.unpack_from('!HHIIH',d,p);hl=(offflags>>12)*4
        if hl<20 or p+hl>end:return out
        out.update(transport='tcp',sport=sp,dport=dp,seq=seq,ack=ack,flags=offflags&0x1ff,payload=d[p+hl:end])
    return out

def inventory(path):
    raw=path.read_bytes(); data=read_bytes(path); rec,info=packets(data)
    counts=collections.Counter(); flows=set(); interfaces=collections.Counter(); dns_types=collections.Counter()
    for r in rec:
        interfaces[f"{r['section']}:{r['interface']}"]+=1
        if r['cap']<r['wire']:counts['snaplen_truncated_packets']+=1
        t=transport(r)
        for k in ('fragment','extension_header'):
            if t.get(k):counts[k]+=1
        if t.get('vlan_ids'): counts['vlan']+=1
        if t.get('transport'):
            proto=t['transport']; counts[proto]+=1
            flows.add((r['section'],r['interface'],proto,t['src'],t['dst'],t['sport'],t['dport']))
            if proto=='tcp':
                for n,m in [('syn',2),('fin',1),('rst',4)]:
                    if t['flags']&m:counts[n]+=1
            if t.get('payload'): counts[proto+'_payload_packets']+=1
            if proto=='udp' and t['dport'] in (4789,8472):counts['vxlan_port']+=1
    return dict(file=path.name,sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw),uncompressed_sha256=hashlib.sha256(data).hexdigest(),uncompressed_size_bytes=len(data),packet_count=len(rec),interface_packets=dict(interfaces),directed_transport_flows=len(flows),observations=dict(counts),**info)

if __name__=='__main__':
    for arg in sys.argv[1:]:
        p=pathlib.Path(arg)
        try: print(json.dumps(inventory(p),sort_keys=True))
        except Exception as e: print(json.dumps({'file':str(p),'error':str(e)}))
