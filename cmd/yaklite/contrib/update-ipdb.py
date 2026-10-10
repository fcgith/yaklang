#!/usr/bin/env python3
"""Rebuild data/ip2asn.bin.gz (IPv4 address -> network owner and country).

    curl -sSLo ip2asn-v4.tsv.gz https://iptoasn.com/data/ip2asn-v4.tsv.gz
    python3 contrib/update-ipdb.py ip2asn-v4.tsv.gz data/ip2asn.bin.gz

The source is iptoasn.com's table (Public Domain, PDDL v1.0). Output, gzipped:
  "YLIP1", uint32 N, N x (uint32 start, uint32 asn, 2-byte country),
  uint32 M, M x (uint32 asn, uint16 len, owner name)
Ranges are contiguous, so a lookup finds the last start <= ip.
"""
import gzip, ipaddress, struct, sys

ranges, names = [], {}
for line in gzip.open(sys.argv[1], "rt", encoding="utf-8"):
    start, end, asn, cc, name = line.rstrip("\n").split("\t")
    asn = int(asn)
    cc = (cc if len(cc) == 2 else "--").encode()
    if ranges and ranges[-1][1] == asn and ranges[-1][2] == cc:
        continue  # same owner and country as the range before it
    ranges.append((int(ipaddress.ip_address(start)), asn, cc))
    if asn:
        names[asn] = " ".join(name.split())[:60]

out = bytearray(b"YLIP1")
out += struct.pack(">I", len(ranges))
for start, asn, cc in ranges:
    out += struct.pack(">II2s", start, asn, cc)
out += struct.pack(">I", len(names))
for asn, name in sorted(names.items()):
    b = name.encode()
    out += struct.pack(">IH", asn, len(b)) + b
with gzip.open(sys.argv[2], "wb", compresslevel=9) as f:
    f.write(out)
print(len(ranges), "ranges,", len(names), "owners")
