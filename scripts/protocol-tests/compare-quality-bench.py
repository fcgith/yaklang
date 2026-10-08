#!/usr/bin/env python3
"""Five alternating A/B rounds on identical harness/corpus; preserve all results."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import time

HARNESS=['common/pcapx/pcaputil/first_batch_t06_quality_test.go','common/pcapx/pcaputil/protocol_native_dns_doh_test.go']
PROFILES=['udp-heavy-native','tls-h2-native','long-connection-synthetic','large-body-synthetic','mixed-small-synthetic']
MODES=['full','framed-capture','deferred-fields','export']
RESULT_KEYS=['Messages','Bytes','Opaque','Unknown','Limited','Drops','Envelopes','Digest','FieldDigest','OrderedDigest']

def fingerprints(root):
    paths=[root/name for name in HARNESS]
    for folder in ['common/bin-parser/testdata','common/pcapx/pcaputil/testdata']:
        paths.extend(sorted((root/folder).rglob('*')))
    return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}

def git_state(root, requested):
    actual=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
    if actual!=requested:raise ValueError('requested revision does not match checkout HEAD: '+str(root))
    status=subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True)
    if status:raise ValueError('A/B checkout must be clean so the revision identifies all inputs: '+str(root))
    names=subprocess.check_output(['git','ls-files','-z'],cwd=root).split(b'\0')
    sources={}
    for name in names:
        if not name:continue
        path=root/os.fsdecode(name)
        if path.suffix in ['.go','.yaml','.yml'] or path.name in ['go.mod','go.sum','go.work','rules.tar.zst']:
            sources[str(path.relative_to(root))]=hashlib.sha256(path.read_bytes()).hexdigest()
    return {'head':actual,'status':status,'source_fingerprints':sources}

def inventory():
    return {f'BenchmarkT06Pipeline/{p}/workers{w}/{m}/procs{c}' for p in PROFILES for w in [1,2,4] for m in MODES for c in [1,2,4]} | {f'BenchmarkT06CaptureReader/{p}/procs{c}' for p in PROFILES for c in [1,2,4]}

def benchmark_inventory(rows):
    result=set()
    for name in rows:
        match=re.fullmatch(r'(.*?)(?:-(\d+))?',name)
        result.add(match[1]+'/procs'+(match[2] or '1'))
    return result

def validate_round(rows, evidence):
    expected=inventory()
    for arm in ['base','head']:
        if set(evidence[arm])!=expected:raise ValueError(arm+' oracle inventory is missing or unexpected')
        if benchmark_inventory(rows[arm])!=expected:raise ValueError(arm+' benchmark inventory is missing or unexpected')
        for name,e in evidence[arm].items():
            if e.get('iterations',0)<=1:raise ValueError('oracle has only calibration iterations: '+name)
            if not re.fullmatch('[0-9a-f]{64}',e.get('raw_profile_sha256','')):raise ValueError('missing raw profile fingerprint: '+name)
            cpu=int(name.rsplit('/procs',1)[1])
            bench=name.rsplit('/procs',1)[0]+('' if cpu==1 else '-'+str(cpu))
            metrics=rows[arm][bench]
            required={'ns/op','B/op','allocs/op','gomaxprocs','capture-bytes/batch'}
            reader=name.startswith('BenchmarkT06CaptureReader/')
            if reader:required.add('records/batch')
            else:required.update(['cpu-ns/batch','p50-ns/batch','p95-ns/batch','p99-ns/batch','heap-bytes','rss-bytes','peak-buffer-bytes','semantic-msg/batch','semantic-bytes/batch','unknown/batch','limited-bytes/batch','rejected/batch'])
            if not required<=metrics.keys():raise ValueError('incomplete benchmark metrics: '+name)
            if any(not math.isfinite(v) or v<0 for v in metrics.values()) or metrics['ns/op']<=0:raise ValueError('invalid benchmark metrics: '+name)
            if metrics['gomaxprocs']!=cpu or e.get('gomaxprocs')!=cpu:raise ValueError('benchmark CPU evidence mismatch: '+name)
            result=e['result']
            if reader:
                if set(result)!=set(['Records','Bytes','Digest']) or any(type(result[k]) is not int or result[k]<=0 for k in ['Records','Bytes']) or not re.fullmatch('[0-9a-f]{64}',result['Digest']):raise ValueError('incomplete reader oracle: '+name)
                if metrics['records/batch']!=result['Records']:raise ValueError('reader record count mismatch: '+name)
                continue
            if any(k not in result for k in RESULT_KEYS):raise ValueError('incomplete semantic result: '+name)
            for key in RESULT_KEYS[:7]:
                if type(result[key]) is not int or result[key]<0:raise ValueError('invalid semantic count: '+name)
            if result['Messages']==0 or any(result[k] for k in ['Unknown','Limited','Drops']):raise ValueError('invalid semantic workload: '+name)
            for key in ['Digest','OrderedDigest']+([] if '/framed-capture/' in name else ['FieldDigest']):
                if not re.fullmatch('[0-9a-f]{64}',result[key]):raise ValueError('missing independent semantic digest: '+name)
    for name in expected:
        if evidence['base'][name]['raw_profile_sha256']!=evidence['head'][name]['raw_profile_sha256']:raise ValueError('A/B raw profile mismatch: '+name)
        for key in (['Records','Bytes','Digest'] if name.startswith('BenchmarkT06CaptureReader/') else RESULT_KEYS):
            if evidence['base'][name]['result'][key]!=evidence['head'][name]['result'][key]:raise ValueError('A/B semantic mismatch: '+name+' '+key)

def benchmark_rows(log):
    rows={}
    for line in log.splitlines():
        if not line.startswith('BenchmarkT06'):
            continue
        cells=line.split()
        if len(cells)<4 or not cells[1].isdigit():
            continue
        metrics={}
        for i in range(2,len(cells)-1,2):
            try:metrics[cells[i+1]]=float(cells[i])
            except ValueError:pass
        if cells[0] in rows:raise ValueError('duplicate final benchmark row: '+cells[0])
        rows[cells[0]]=metrics
    return rows

def evidence_rows(path):
    rows={}
    for line in path.read_text().splitlines():
        e=json.loads(line);key=e['benchmark']+'/procs'+str(e['gomaxprocs'])
        if type(e.get('iterations')) is not int or e['iterations']<=0:raise ValueError('invalid oracle iteration count')
        # Go runs one-iteration discovery at the previous CPU setting before
        # recalibrating each case. Discovery is never a final oracle.
        if e['iterations']==1:continue
        if key in rows and e['iterations']<=rows[key]['iterations']:raise ValueError('duplicate/non-increasing final oracle: '+key)
        rows[key]=e
    return rows

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base',type=Path);parser.add_argument('head',type=Path)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--benchtime',default='200ms')
    parser.add_argument('--base-sha',required=True);parser.add_argument('--head-sha',required=True)
    args=parser.parse_args();base=args.base.resolve();head=args.head.resolve();out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
    inputs=fingerprints(head)
    if fingerprints(base)!=inputs:parser.error('A/B must use byte-identical harness and corpus')
    states={arm:git_state(root,sha) for arm,root,sha in [('base',base,args.base_sha),('head',head,args.head_sha)]}
    meta={'started_unix':time.time(),'platform':platform.platform(),'machine':platform.machine(),'go':subprocess.check_output(['go','version'],text=True).strip(),'base':str(base),'head':str(head),'base_sha':args.base_sha,'head_sha':args.head_sha,'inputs':fingerprints(head),'round_order':[],'verification_in_timing':True}
    meta['logical_cpus']=os.cpu_count()
    meta.update(checkouts=states,case_inventory=sorted(inventory()),build_environment={k:os.environ.get(k) for k in ['GOFLAGS','GOTOOLCHAIN','CGO_ENABLED','GOOS','GOARCH','GOWORK','GOPROXY']})
    if platform.system()=='Darwin':
        meta['hardware']={key:subprocess.check_output(['sysctl','-n',key],text=True).strip() for key in ['machdep.cpu.brand_string','hw.physicalcpu','hw.memsize']}
    (out/'environment.json').write_text(json.dumps(meta,indent=2)+'\n')
    arm_rows={'base':[],'head':[]};all_evidence=[]
    command=['go','test','./common/pcapx/pcaputil','-run','^$','-bench','^BenchmarkT06(Pipeline|CaptureReader)$','-benchtime='+args.benchtime,'-count=1','-cpu=1,2,4','-timeout=20m']
    for round_no in range(1,6):
        pair={}
        for arm in (['base','head'] if round_no%2 else ['head','base']):
            evidence=out/f'round{round_no}-{arm}-oracles.jsonl';evidence.unlink(missing_ok=True)
            env=os.environ.copy();env['GOMAXPROCS']='2';env['YAK_T06_BENCH_EVIDENCE']=str(evidence)
            path=out/f'round{round_no}-{arm}.log';begin=time.time()
            with path.open('w') as log:result=subprocess.run(command,cwd=base if arm=='base' else head,env=env,stdout=log,stderr=subprocess.STDOUT)
            meta['round_order'].append({'round':round_no,'arm':arm,'exit_code':result.returncode,'elapsed_seconds':time.time()-begin,'command':command})
            (out/'environment.json').write_text(json.dumps(meta,indent=2)+'\n')
            if result.returncode:raise SystemExit('benchmark failed: '+str(path))
            rows=benchmark_rows(path.read_text())
            if not rows:raise ValueError('empty benchmark output')
            if not evidence.exists():raise ValueError('missing oracle evidence file')
            arm_rows[arm].append(rows);pair[arm]=evidence_rows(evidence)
        validate_round({arm:arm_rows[arm][-1] for arm in ['base','head']},pair)
        if fingerprints(base)!=inputs or fingerprints(head)!=inputs:raise ValueError('A/B inputs changed during execution')
        for arm,root,sha in [('base',base,args.base_sha),('head',head,args.head_sha)]:
            if git_state(root,sha)!=states[arm]:raise ValueError('A/B source changed during execution: '+arm)
        all_evidence.append({'round':round_no,'case_count':len(pair['base']),'semantics_equal':True})
    keys=set(arm_rows['base'][0])
    if any(set(rows)!=keys for arm in arm_rows.values() for rows in arm):raise SystemExit('benchmark case mismatch')
    comparisons=[]
    for name in sorted(keys):
        metrics={}
        for metric in arm_rows['base'][0][name]:
            a=[r[name][metric] for r in arm_rows['base']];b=[r[name][metric] for r in arm_rows['head']]
            am,bm=statistics.median(a),statistics.median(b)
            metrics[metric]={'base':a,'head':b,'base_median':am,'head_median':bm,'change_percent':100*(bm/am-1) if am else None,'base_range':[min(a),max(a)],'head_range':[min(b),max(b)]}
        comparisons.append({'benchmark':name,'metrics':metrics})
    (out/'comparison.json').write_text(json.dumps({'rounds':5,'oracle_equivalence':all_evidence,'comparisons':comparisons},indent=2)+'\n')
    meta['completed_unix']=time.time();meta['complete']=True;(out/'environment.json').write_text(json.dumps(meta,indent=2)+'\n')
    print(json.dumps({'complete':True,'rounds':5,'benchmark_cases':len(comparisons),'oracle_equivalence':all_evidence},indent=2))

if __name__=='__main__':main()
