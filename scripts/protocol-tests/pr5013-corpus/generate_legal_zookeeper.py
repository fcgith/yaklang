"""CC0-1.0 offline control: legal paths exercise cumulative pending budget."""
import struct
from pathlib import Path
U16=lambda x:struct.pack('!H',x)
U32=lambda x:struct.pack('!I',x)
I32=lambda x:struct.pack('!i',x)
U64=lambda x:struct.pack('!Q',x)
A=bytes([192,0,2,1]);B=bytes([192,0,2,2]); MAC=bytes.fromhex('0200000000020200000000010800')

def checksum(b):
    if len(b)%2:b+=b'\0'
    n=sum(struct.unpack('!%dH'%(len(b)//2),b))
    while n>>16:n=(n&65535)+(n>>16)
    return (~n)&65535

def ip(payload,proto,reverse=False):
    a,b=(B,A) if reverse else (A,B)
    h=b'\x45\0'+U16(20+len(payload))+b'\0\0\x40\0\x40'+bytes([proto])+b'\0\0'+a+b
    return MAC+h[:10]+U16(checksum(h))+h[12:]+payload

def udp(payload,sp,dp):
    h=U16(sp)+U16(dp)+U16(8+len(payload))+b'\0\0'
    cs=checksum(A+B+b'\0\x11'+U16(len(h)+len(payload))+h+payload) or 65535
    return ip(h[:6]+U16(cs)+payload,17)

def tcp(payload,sp,dp,seq,ack,flags,reverse=False):
    h=U16(sp)+U16(dp)+U32(seq)+U32(ack)+U16(0x5000|flags)+U16(65535)+b'\0\0\0\0'
    a,b=(B,A) if reverse else (A,B)
    cs=checksum(a+b+b'\0\x06'+U16(len(h)+len(payload))+h+payload)
    return ip(h[:16]+U16(cs)+h[18:]+payload,6,reverse)

def stream(steps,port=80,ending='fin',chunk=1460):
    cs,ss=1001,9001;sp=40000
    r=[tcp(b'',sp,port,1000,0,2),tcp(b'',port,sp,9000,cs,0x12,True),tcp(b'',sp,port,cs,ss,0x10)]
    for direction,data in steps:
        for n in range(0,len(data),chunk):
            part=data[n:n+chunk]
            if direction:r.append(tcp(part,port,sp,ss,cs,0x18,True));ss+=len(part)
            else:r.append(tcp(part,sp,port,cs,ss,0x18));cs+=len(part)
    if ending=='fin':r.extend([tcp(b'',port,sp,ss,cs,0x11,True),tcp(b'',sp,port,cs,ss+1,0x11)])
    elif ending=='rst':r.append(tcp(b'',port,sp,ss,cs,0x14,True))
    return r

def pcap(records):
    out=struct.pack('<IHHIIII',0xa1b23c4d,2,4,0,0,65535,1)
    for i,p in enumerate(records):out+=struct.pack('<IIII',1700000000,i*1000,len(p),len(p))+p
    return out

def block(t,b):
    b+=b'\0'*((-len(b))%4);n=len(b)+12;return struct.pack('<II',t,n)+b+struct.pack('<I',n)

def pcapng(interleaved,interfaces=2):
    out=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))
    for _ in range(interfaces):out+=block(1,struct.pack('<HHI',1,0,65535)+struct.pack('<HH',9,1)+b'\x09\0\0\0'+b'\0'*4)
    for n,(i,p) in enumerate(interleaved):
        ts=1700000000*10**9+n*1000;out+=block(6,struct.pack('<IIIII',i,ts>>32,ts&0xffffffff,len(p),len(p))+p)
    return out

def dns(name,answer=False):
    q=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+U16(1)+U16(1)
    h=U16(0)+U16(0x8180 if answer else 0x0100)+U16(1)+U16(int(answer))+b'\0'*4
    return h+q+(b'\xc0\x0c'+U16(1)+U16(1)+U32(60)+U16(4)+bytes([192,0,2,99]) if answer else b'')


frame=lambda b:U32(len(b))+b
password=bytes(16)
connect=frame(I32(0)+U64(0)+I32(30000)+U64(0)+I32(16)+password+b"\0")
connected=frame(I32(0)+I32(30000)+U64(0x5013)+I32(16)+password+b"\0")
steps=[(0,connect),(1,connected)]
for xid in range(1,25):
    path=("/"+str(xid)).ljust(4096,"x").encode()
    steps.append((0,frame(I32(xid)+I32(4)+I32(len(path))+path+b"\0")))
output=Path(__file__).resolve().parents[3]/"common/pcapx/pcaputil/testdata/protocol-sessions/pr5013-review/zookeeper-pending-budget-legal.pcap"
output.write_bytes(pcap(stream(steps,2181,"eof")))
