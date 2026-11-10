"""Carlo Corti: read-only fixed-prefix arithmetic coverage supplement."""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path

R=Path(__file__).resolve().parents[2]
K=170000000000000;START=166539042068893
P=lambda k:k*(17*k-15)//2

def prefix_map(k):
    small=[2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61]
    high=P(k);cap=high//math.prod(small)
    sieve=bytearray(b'\1')*(cap+1);sieve[:2]=b'\0\0'
    for p in range(2,math.isqrt(cap)+1):
        if sieve[p]:sieve[p*p::p]=b'\0'*(((cap-p*p)//p)+1)
    primes=[p for p in range(2,cap+1) if sieve[p]]
    def tail(m,i,r):return i+r<=len(primes) and m*math.prod(primes[i:i+r])<=high
    result=[]
    def visit(m,i,prefix):
        if len(prefix)==3:result.append(prefix);return
        r=19-len(prefix)
        for j in range(i,len(primes)):
            if not tail(m,j,r):break
            q=primes[j];v=m*q;e=1
            while v<=high:
                if not tail(v,j+1,r-1):break
                visit(v,j+1,prefix+[[q,e]]);v*=q;e+=1
    visit(1,0,[])
    assert result==sorted(result) and len({tuple(map(tuple,p)) for p in result})==len(result)
    return result

def excluded(prefix):
    return any(p in (3,5) and e==1 for p,e in prefix)

def build():
    old=prefix_map(START);new=prefix_map(K)
    assert len(old)==577 and len(new)==590
    assert old[0]==new[0]==[[2,1],[3,1],[5,1]]
    positive=json.loads((R/'outputs/r30w1/cert.json').read_text())
    pairs=[list(map(int,x.split('^'))) for x in positive['factors'].split(',')]
    assert old[positive['owner']]==pairs[:3] and not excluded(old[positive['owner']])
    service={i:0 for i in range(577)};current=False;done=set();segments=0;closure_segment=None
    for line in (R/'outputs/run2/cover.tsv').read_text().splitlines():
        f=line.split('\t')[:-1]
        if f[0]=='W':current=f[2]==str(START)
        if not current:continue
        if f[0] in ('P','U'):
            service[int(f[1])]+=int(f[6])
            if f[0]=='U':done.add(int(f[1]))
        if f[0]=='S':
            segments+=1
            if closure_segment is None and all(i in done or excluded(old[i]) for i in range(577)):
                closure_segment=segments
    needed=[i for i,p in enumerate(old) if not excluded(p)]
    assert all(i in done for i in needed)
    out=dict(author='Carlo Corti',status='STATIC_PREFIX_MAP_VALIDATED',n=19,K=str(K),start_k=str(START),depth=3,
        total=590,low=str(P(START)+1),high=str(P(K)),
        source_sha256=hashlib.sha256((R/'src/a358321.c').read_bytes()).hexdigest(),
        theorem='For n19 and p=3 or5,p|P(k) implies p^2|P(k); a fixed prefix containing3^1 or5^1 has no polygonal leaf.',
        acceptance='outputs/arith19/agree.md',known_owner32_replay=True,
        units=[dict(id=i,prefix=p,excluded_prime_powers_one=[q for q,e in p if q in (3,5) and e==1]) for i,p in enumerate(new)],
        old_total=577,old_nonexcluded_units=len(needed),old_analytic_class=sum(map(excluded,old)),
        old_nonexcluded_service_seconds=sum(service[i] for i in needed)/1e9,
        old_largest_nonexcluded_service_seconds=max(service[i] for i in needed)/1e9,
        old_first_all_nonexcluded_closed_call=closure_segment,
        old_call_semantics='R30000 NEXT calls only; old total4 first-window segments excluded',
        official_actions=0,native_calibration_seconds=0)
    return out

def classify(state,latest,mapping):
    assert state['schema']==4 and state['n']==19 and state['depth']==3
    assert state['windows']==1 and state['K']==str(K) and state['initial_start_k']==str(START)
    assert state['low']==str(P(START)+1) and state['high']==str(P(K))
    assert state['total']==state['allocated']==mapping['total']==590
    units=mapping['units'];assert [u['id'] for u in units]==list(range(590))
    assert set(latest)<=set(range(590))
    completed={i for i,f in latest.items() if f[0]=='U'}
    assert state['completed']==len(completed) and state['complete']==(len(completed)==590)
    for i,f in latest.items():
        assert f[0] in ('P','U')
        if f[0]=='P':
            cursor=[list(map(int,x.split('^'))) for x in f[7].split(',')]
            assert cursor[:3]==units[i]['prefix'],'Cursor/prefix ID mismatch'
    pending=set(range(590))-completed
    analytical={i for i in pending if excluded(units[i]['prefix'])}
    required=pending-analytical
    return dict(native_complete=state['complete'],computational_completed=len(completed),
        total=590,pending=len(pending),analytically_excluded_pending=sorted(analytical),
        computational_required_pending=sorted(required),scientific_complete=not required,
        mixed_covered_units=len(completed)+len(analytical),interval_candidate=state['candidate'],
        global_a19_unchanged=153290693815740,head=state['head'],
        scope='Local interval(166539042068893,170000000000000],not a new a19 value or all-hit list')

def audit(job):
    mapping=json.loads((R/'outputs/limit17/units.json').read_text())
    assert mapping['status']=='STATIC_PREFIX_MAP_VALIDATED' and mapping['K']==str(K)
    assert mapping['source_sha256']==hashlib.sha256((R/'src/a358321.c').read_bytes()).hexdigest()
    assert [u['prefix'] for u in mapping['units']]==prefix_map(K)
    assert [P(k)%9 for k in range(9)]==[0,1,1,0,7,4,0,4,7]
    assert not any(P(k)%25 in (5,10,15,20) for k in range(25))
    assert all(P(k+25)-P(k)==25*(17*k+205) for k in range(25))
    spec=importlib.util.spec_from_file_location('frozen_artifact_auditor',R/'validation/check_a358321.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    names=['cfg.json','state.json','cover.tsv','hits.tsv','env.txt']
    before={n:hashlib.sha256((job/n).read_bytes()).hexdigest() for n in names}
    state=module.audit_artifact(job)
    cfg=json.loads((job/'cfg.json').read_text())
    assert cfg['schema']==4 and cfg['n']==19 and cfg['K']==str(K) and cfg['start_k']==str(START) and cfg['depth']==3
    latest={}
    for line in (job/'cover.tsv').read_text().splitlines():
        f=line.split('\t')[:-1]
        if f[0]=='W':latest={}
        if f[0] in ('P','U'):latest[int(f[1])]=f
        if f[0]=='H':
            pairs=[list(map(int,x.split('^'))) for x in f[3].split(',')]
            owner=int(f[1]);assert pairs[:3]==mapping['units'][owner]['prefix']
            assert not excluded(mapping['units'][owner]['prefix'])
    out=classify(state,latest,mapping)
    assert before=={n:hashlib.sha256((job/n).read_bytes()).hexdigest() for n in names}
    out.update(author='Carlo Corti',status='VERIFIED_MIXED_INTERVAL_COVERAGE',job_sha256=before,
               source_or_job_modified=False,independent_full_negative_census=False)
    return out

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',action='store_true');p.add_argument('--job',type=Path)
    a=p.parse_args();assert a.build!=(a.job is not None)
    print(json.dumps(build() if a.build else audit(a.job),indent=2))

if __name__=='__main__':main()
