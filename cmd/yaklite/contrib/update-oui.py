#!/usr/bin/env python3
"""Rebuild data/oui.txt.gz from the IEEE MA-L registry.

    curl -sSLo oui.csv https://standards-oui.ieee.org/oui/oui.csv
    python3 contrib/update-oui.py oui.csv data/oui.txt.gz

Output: one "AABBCC<TAB>Short vendor name" line per assignment, sorted.
"""
import csv, gzip, re, sys

SUFFIXES = re.compile(
    r"[ ,.]*\b(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|l\.l\.c|gmbh|ag|s\.?a|s\.?p\.?a|b\.?v|"
    r"pte|pty|plc|oy|ab|as|a/s|kg|srl|s\.r\.l|sas|kk|k\.k|technology|technologies|electronics|"
    r"communications|communication|international)\b\.?",
    re.I,
)

def short(name: str) -> str:
    name = " ".join(name.split())
    prev = None
    while prev != name:
        prev = name
        name = SUFFIXES.sub("", name).strip(" ,.-")
    return name[:40] or "unknown"

rows = {}
with open(sys.argv[1], newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        if r["Registry"] == "MA-L" and len(r["Assignment"]) == 6:
            rows[r["Assignment"].upper()] = short(r["Organization Name"])
with gzip.open(sys.argv[2], "wt", encoding="utf-8", compresslevel=9) as out:
    for k in sorted(rows):
        out.write(f"{k}\t{rows[k]}\n")
print(len(rows), "entries")
