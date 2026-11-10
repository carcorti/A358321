"""Carlo Corti: independent positive witness only, never a minimum claim."""
import json
import math
from pathlib import Path

R=Path(__file__).resolve().parents[2]

def factor_trial(v):
    assert v>=1
    out={};d=2
    while d<=v//d:
        while v%d==0:out[d]=out.get(d,0)+1;v//=d
        d+=1 if d==2 else 2
    if v>1:out[v]=out.get(v,0)+1
    return out

def certify(n,k,value,pairs):
    assert len(pairs)==n and len({p for p,e in pairs})==n
    assert pairs==sorted(pairs) and all(e>=1 and factor_trial(p)=={p:1} for p,e in pairs)
    assert k*((n-2)*k-(n-4))==2*value==2*math.prod(p**e for p,e in pairs)
    combined=factor_trial(k)
    for p,e in factor_trial((n-2)*k-(n-4)).items():combined[p]=combined.get(p,0)+e
    assert combined.get(2,0)>=1
    combined[2]-=1
    if combined[2]==0:del combined[2]
    assert combined==dict(pairs)
    disc=(n-4)**2+8*(n-2)*value;t=math.isqrt(disc)
    assert t*t==disc and (t+n-4)%(2*(n-2))==0 and (t+n-4)//(2*(n-2))==k
    return dict(n=n,k=k,value=str(value),distinct_primes=n,factor_value=combined,
                exact_inverse=str(t),linear_factors_independently_trial_factored=True)

state=json.loads((R/'outputs/run2/state.json').read_text())
assert state['n']==19 and state['candidate']==153290693815740 and not state['complete']
rows=[l.split('\t') for l in (R/'outputs/run2/cover.tsv').read_text().splitlines() if l.startswith('H\t')]
row=[r for r in rows if int(r[2])==state['candidate']][-1]
pairs=[tuple(map(int,s.split('^'))) for s in row[3].split(',')]
k=int(row[2]);value=k*(17*k-15)//2
answer=certify(19,k,value,pairs)
known=json.loads((R/'outputs/a18/cert.json').read_text())
certify(18,known['k'],int(known['value']),sorted((int(p),e) for p,e in known['factor_value'].items()))
for args in [(19,k+1,value,pairs),(19,k,value+1,pairs),(19,k,value,pairs[:-1]),
             (19,k,value,[(4,pairs[0][1])]+pairs[1:])]:
    try:certify(*args)
    except AssertionError:pass
    else:raise AssertionError('negative control accepted')
answer.update(author='Carlo Corti',status='INDEPENDENT_POSITIVE_WITNESS_PASS',
              minimum_proven=False,independent_negative_census=False,
              known_n18_replay=True,negative_controls_rejected=4,
              factors=row[3],owner=int(row[1]),source_job_head=state['head'])
print(json.dumps(answer,indent=2))
