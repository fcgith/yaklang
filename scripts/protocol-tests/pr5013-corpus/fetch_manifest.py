#!/usr/bin/env python3
"""Fetch ONLY pinned public capture bytes; never execute contents or replay traffic.
Honor network/access errors. Standard library; no installation. Use --ids for a subset.
"""
import argparse,hashlib,json,pathlib,urllib.error,urllib.parse,urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise urllib.error.HTTPError(req.full_url,code,'redirect refused for pinned source',headers,fp)
opener=urllib.request.build_opener(NoRedirect())
p=argparse.ArgumentParser();p.add_argument('--manifest',default=str(pathlib.Path(__file__).resolve().parents[3]/'common/pcapx/pcaputil/testdata/protocol-sessions/pr5013-review/upstream-manifest.json'));p.add_argument('--output',required=True,help='external quarantine/cache directory; captures are never published');p.add_argument('--ids',nargs='*');p.add_argument('--include-test-secrets',action='store_true',help='explicitly opt into public test captures containing decryption-secrets blocks');a=p.parse_args()
root=pathlib.Path(a.output).resolve();repo=pathlib.Path(__file__).resolve().parents[3]
if root==repo or repo in root.parents:raise ValueError('download cache must be outside the repository')
m=json.loads(pathlib.Path(a.manifest).read_text());selected=set(a.ids or [])
for c in m['captures']:
    if selected and c['id'] not in selected:continue
    if c['decryption_secret_blocks'] and not a.include_test_secrets:print('SKIP public test secret blocks:',c['id']);continue
    path=(root/c['file']).resolve()
    if root not in path.parents:raise ValueError('destination escapes manifest root')
    url=urllib.parse.urlparse(c['source_url'])
    if url.scheme!='https' or url.hostname!='raw.githubusercontent.com' or c['commit'] not in url.path:raise ValueError('unpinned/nonapproved source URL')
    if path.exists():
        b=path.read_bytes()
        if len(b)==c['size_bytes'] and hashlib.sha256(b).hexdigest()==c['sha256']:print('VERIFIED existing:',c['id']);continue
        raise ValueError('existing file differs; refusing to overwrite: '+str(path))
    with opener.open(c['source_url'],timeout=30) as r:
        # Normal HTTPS redirects must remain on the same permitted public host.
        if urllib.parse.urlparse(r.url).hostname!='raw.githubusercontent.com':raise ValueError('unexpected redirect host')
        b=r.read(min(c['size_bytes']+1,32*1024*1024+1))
    if len(b)!=c['size_bytes'] or hashlib.sha256(b).hexdigest()!=c['sha256']:raise ValueError('size/SHA256 mismatch: '+c['id'])
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as f:f.write(b)
    print('DOWNLOADED verified:',c['id'])
