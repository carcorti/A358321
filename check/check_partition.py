#!/usr/bin/env python3
"""Carlo Corti: bounded configurable-partition and explicit-frontier regressions.

Independent small sets use a direct omega sieve. Native jobs use known n13
data only. No official campaign or new n19 range is searched.
"""
import argparse
import json
import math
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import time

from check_a358321 import ROOT, audit_artifact, call, polygon


FIXTURE = r'''
#define main producer_main
#include "SOURCE"
#undef main
int main(int argc,char **argv) {
    if(argc==2 && strcmp(argv[1],"bounds")==0) {
        require(sizeof(Unit)*MAX_UNITS<MEMORY_GUARD,"unit memory bound");
        for(unsigned n=13;n<=MAX_N;n++) {
            uint64_t k=maximum_k(n);valid_initial(n,k,k-1,n-1);
            require(polygon(n,k-1)+1<=polygon(n,k)&&polygon(n,k)<=ceiling(n),"initial boundary");
        }
        puts("BOUNDS PASS");return 0;
    }
    if(argc==7 && strcmp(argv[1],"sets")==0) {
        Window w;memset(&w,0,sizeof w);w.n=(unsigned)number(argv[2],7);
        w.low=number(argv[3],600000);w.high=number(argv[4],600000);
        w.depth=(unsigned)number(argv[5],6);require(w.depth>=3&&w.depth<w.n,"fixture depth");
        w.primes=primes_make((uint32_t)(w.high/primorial(w.n-1)));masks(&w);
        w.units=calloc(MAX_UNITS,sizeof *w.units);require(w.units!=NULL,"fixture allocation");
        Unit u={0};if(tail(&w,1,0,w.n))prefixes(&w,1,0,0,u);
        for(size_t id=0;id<w.count;id++) {
            Worker a;memset(&a,0,sizeof a);a.w=&w;a.id=id;a.deadline=UINT64_MAX;
            a.filters=number(argv[6],1)!=0;a.emit=stdout;
            memcpy(a.p,w.units[id].p,sizeof w.units[id].p);memcpy(a.e,w.units[id].e,sizeof w.units[id].e);
            require(dfs(&a,w.units[id].product,w.units[id].next,w.depth),"fixture set complete");
        }
        window_free(&w);return 0;
    }
    if(argc==4 && strcmp(argv[1],"checkpoint")==0) {
        Campaign *c=load_campaign(argv[2],false);unsigned count=(unsigned)number(argv[3],3);
        require(count<c->w.count&&c->done==0,"fresh checkpoint fixture");
        uint64_t start=ns_now();
        for(unsigned id=0;id<count;id++) {
            Result r=calculate(&c->w,id,UINT64_MAX);require(r.done&&!r.error,"known unit complete");
            require(commit_result(c,id,&r),"fixture commit");
        }
        char payload[128];int z=snprintf(payload,sizeof payload,"S\t1\t%" PRIu64 "\tINTERRUPTED\t%" PRIu64,ns_now()-start,c->max_quantum_ns);
        require(z>0&&(size_t)z<sizeof payload,"fixture segment");append_record(c,payload);
        save_snapshots(c);campaign_free(c);return 2;
    }
    if(argc==3 && strcmp(argv[1],"prefix-cert")==0) {
        Campaign *c=load_campaign(argv[2],false);
        for(size_t i=0;i<c->w.count;i++) {
            Result r=calculate(&c->w,i,UINT64_MAX);
            if(r.best) {
                char text[512];factors_text(&r,c->w.n,text);
                c->w.units[i].p[c->w.depth-1]=2;
                certificate(&c->w,i,r.best,text);
                die("fixture failed to reject wrong deep prefix");
            }
        }
        die("fixture had no known positive");
    }
    return producer_main(argc,argv);
}
'''


def run_checks(binary, cc, instrument):
    with tempfile.TemporaryDirectory(prefix='a358321-part-') as tmp:
        work = Path(tmp)
        source = work / 'fixture.c'
        source.write_text(FIXTURE.replace('SOURCE', str(ROOT / 'src/a358321.c')))
        flags = ['-O2', '-std=c17', '-fopenmp', '-Wall', '-Wextra', '-Wpedantic',
                 '-Wshadow', '-Wconversion', '-Wdouble-promotion', '-Wformat=2', '-Werror']
        if instrument:
            flags += ['-O1', '-g', '-fno-omit-frame-pointer', '-fsanitize=address,undefined']
        cmd = shlex.split(cc) + flags + [str(source), '-lm', '-o', str(work / 'fixture')]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        fixture = work / 'fixture'
        # Fixture-owned jobs bind this instrumented executable, not the production binary.
        shutil.copyfile(ROOT / 'src/a358321.c', work / 'a358321.c')
        shutil.copyfile(ROOT / 'src/Makefile', work / 'Makefile')
        call(fixture, 'bounds')
        omega = [0] * 600001
        for p in range(2, len(omega)):
            if not omega[p]:
                for v in range(p, len(omega), p):
                    omega[v] += 1
        cases = []
        for n, lo, hi in [(4, 44100, 44100), (4, 44101, 44101), (5, 11, 50000),
                          (6, 30000, 60000), (7, 1, 600000), (7, 1, 10000)]:
            expected = {v for v in range(lo, hi + 1) if omega[v] == n}
            hits = {(k, polygon(n, k)) for k in range(1, math.isqrt(2 * hi) + 2)
                    if polygon(n, k) in expected}
            for depth in range(3, n):
                for filters in (0, 1):
                    out = call(fixture, 'sets', n, lo, hi, depth, filters)
                    values, found = [], set()
                    for line in out.stdout.splitlines():
                        if line.startswith('H '):
                            _, k, v = line.split(); found.add((int(k), int(v)))
                        else:
                            values.append(int(line))
                    assert len(values) == len(set(values)) and set(values) == expected
                    assert found == hits
                    cases.append((n, lo, hi, depth, filters, len(values), len(found)))

        known = 122574155
        outcomes = []
        for depth, threads in [(3, 1), (8, 8), (5, 16)]:
            job = work / f'd{depth}'
            started = time.monotonic()
            call(binary, 'init', job, 13, known, known - 1, depth)
            state = audit_artifact(job)
            assert state['depth'] == depth and int(state['low']) == polygon(13, known - 1) + 1
            assert state['completed'] == 0 and not state['complete']
            execution = call(binary, 'next', job, threads, 40, timeout=50)
            elapsed = time.monotonic() - started
            state = audit_artifact(job)
            assert state['complete'] and state['candidate'] == known
            runtime = json.loads(execution.stdout)
            outcomes.append({'depth': depth, 'threads': threads, 'candidate': state['candidate'],
                             'wall_seconds_including_setup': elapsed,
                             'leaves': int(state['leaves']), 'units': state['total'],
                             'cpu_seconds_next': runtime['cpu_seconds'],
                             'reported_rss_bytes': runtime['rss_bytes']})
        # Exact lower exclusion of the known positive; the next index is checked directly.
        job = work / 'after'
        call(binary, 'init', job, 13, known + 1, known, 8)
        call(binary, 'next', job, 8, 40, timeout=50)
        state = audit_artifact(job)
        value = polygon(13, known + 1)
        # Factor the two linear factors directly, including exact division by two.
        def trial(v):
            f = {}; d = 2
            while d <= v // d:
                while v % d == 0:
                    f[d] = f.get(d, 0) + 1; v //= d
                d += 1 if d == 2 else 2
            if v > 1:
                f[v] = f.get(v, 0) + 1
            return f
        support = trial(known + 1)
        for q, exponent in trial(11 * (known + 1) - 9).items():
            support[q] = support.get(q, 0) + exponent
        support[2] -= 1
        if not support[2]:
            del support[2]
        assert math.prod(q ** e for q, e in support.items()) == value
        assert state['candidate'] == (known + 1 if len(support) == 13 else 0)

        state_cases = []
        for count in (0, 1, 3):
            job = work / f's{count}'
            call(fixture, 'init', job, 13, known, known - 1, 4)
            call(fixture, 'checkpoint', job, count, expected=2)
            partial = audit_artifact(job)
            assert partial['completed'] == count and not partial['complete']
            assert int(partial['low']) > 0
            call(fixture, 'verify', job)
            call(fixture, 'next', job, 8, 40, timeout=50)
            final = audit_artifact(job)
            assert final['complete'] and final['candidate'] == known
            state_cases.append({'committed_before_resume': count, 'final_candidate': known})
        # Deep certificate ownership is checked beyond the legacy first3 positions.
        job = work / 'cert'
        call(fixture, 'init', job, 13, known, known - 1, 8)
        out = call(fixture, 'prefix-cert', job, expected=1)
        assert 'certificate prefix differs from unit' in out.stderr
        for start, depth in [(known, 8), (known + 1, 8), (known - 1, 0),
                             (0, 2), (0, 13), (0, 24), ('01', 8), ('-1', 8),
                             ('18446744073709551616', 8), (0, '+8')]:
            bad = work / 'invalid'
            call(binary, 'init', bad, 13, known, start, depth, expected=1)
            assert not bad.exists()
        call(binary, 'init', work / 'invalid', 13, known, 0, expected=1)
        # Exact cfg grammar and source binding cannot be bypassed by changing depth/start.
        job = work / 'alter'
        call(binary, 'init', job, 13, known, known - 1, 8)
        cfg = (job / 'cfg.json').read_bytes()
        for changed in [cfg.replace(b'"depth":8', b'"depth":9'),
                        cfg.replace(b'"depth":8', b'"depth":08'),
                        cfg.replace(b'"start_k":"122574154"', b'"start_k":"0"')]:
            (job / 'cfg.json').write_bytes(changed)
            call(binary, 'verify', job, expected=1)
        (job / 'cfg.json').write_bytes(cfg)
        call(binary, 'verify', job)
        return {'status': 'PASS', 'author': 'Carlo Corti', 'small_exact_set_observations': cases,
                'known_positive_partition_threads': outcomes, 'checkpoint_state_matrix': state_cases,
                'deep_certificate_rejection': True, 'initial_frontier_boundary': True,
                'official_campaign': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'src/a358321')
    parser.add_argument('--cc', default='gcc-13')
    parser.add_argument('--instrument', action='store_true')
    args = parser.parse_args()
    print(json.dumps(run_checks(args.binary.resolve(), args.cc, args.instrument), indent=2))


if __name__ == '__main__':
    main()
