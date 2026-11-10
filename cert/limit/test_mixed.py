"""Carlo Corti: arithmetic-coverage controls on in-memory models,not native jobs."""
import copy
import importlib.util
import json
from pathlib import Path

p=Path(__file__).with_name('mixed.py');spec=importlib.util.spec_from_file_location('mix',p)
x=importlib.util.module_from_spec(spec);spec.loader.exec_module(x)
mapping=json.loads(p.with_name('units.json').read_text())
assert len(x.prefix_map(117760885979226))==451
assert x.prefix_map(x.START)[32]==[[2,1],[3,3],[5,2]]
assert [u['prefix'] for u in mapping['units']]==x.prefix_map(x.K)
required={u['id'] for u in mapping['units'] if not x.excluded(u['prefix'])}
excluded=set(range(590))-required
assert len(required)==311 and len(excluded)==279 and 0 in excluded
state=dict(schema=4,n=19,depth=3,windows=1,K=str(x.K),initial_start_k=str(x.START),
           low=str(x.P(x.START)+1),high=str(x.P(x.K)),total=590,allocated=590,
           completed=len(required),complete=False,candidate=0,head='test-only')
latest={i:['U',str(i)] for i in required}
result=x.classify(state,latest,mapping)
assert result['scientific_complete'] and not result['native_complete']
assert result['mixed_covered_units']==590 and set(result['analytically_excluded_pending'])==excluded
one=min(required);pending=dict(latest);del pending[one]
result=x.classify(dict(state,completed=len(required)-1),pending,mapping)
assert not result['scientific_complete'] and result['computational_required_pending']==[one]
prefix=mapping['units'][one]['prefix'];cursor=','.join(f'{p}^{e}' for p,e in prefix)
pending[one]=['P',str(one),'0','0','0','0','0',cursor]
assert x.classify(dict(state,completed=len(required)-1),pending,mapping)['computational_required_pending']==[one]
bad=copy.deepcopy(pending);bad[one][7]='2^1,3^1,5^1'
assert mapping['units'][one]['prefix']!=[[2,1],[3,1],[5,1]]
bad_cases=[(dict(state,n=20),latest),(dict(state,complete=True),latest),
           (dict(state,completed=590),latest),
           (dict(state,completed=len(required)-1),bad)]
for s,rows in bad_cases:
    try:x.classify(s,rows,mapping)
    except AssertionError:pass
    else:raise AssertionError('negative coverage control accepted')
assert x.classify(dict(state,completed=590,complete=True),{i:['U',str(i)] for i in range(590)},mapping)['native_complete']
out=dict(author='Carlo Corti',status='PASS',known_prefix_counts=[451,577,590],
         old_owner32_semantic_replay=True,new_computational_units=311,new_arithmetic_class=279,
         positive_coverage_controls=4,negative_controls_rejected=len(bad_cases),
         synthetic_models_only=True,native_job_mutations=0,official_actions=0)
p.with_name('tests.json').write_text(json.dumps(out,indent=2)+'\n')
print('PASS mixed coverage:311 computational/279 arithmetic classes,4 rejected controls; no native job')
