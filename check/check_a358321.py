#!/usr/bin/env python3
"""Bounded validation for A358321, Carlo Corti.

Small exact sets use direct integer factor-count sieving, independently of the
producer's prime-power recursion. Positive certificates use elementary primality
and exact integer arithmetic. Journal hashes establish integrity, not coverage.
No official campaign or b-file mutation is performed. Python >=3.10, stdlib only.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import pty
import re
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MAX128 = (1 << 128) - 1
BASELINE = {13: 122574155, 14: 630341910, 15: 6066475415}


def polygon(n, k):
    return k * ((n - 2) * k - (n - 4)) // 2


def trial_prime(p):
    return p >= 2 and all(p % d for d in range(2, math.isqrt(p) + 1))


def factors(text, n, v):
    pairs = [tuple(map(int, x.split('^'))) for x in text.split(',')]
    assert len(pairs) == n and all(1 <= e <= 127 and trial_prime(p) for p, e in pairs)
    assert all(pairs[i][0] < pairs[i + 1][0] for i in range(n - 1))
    assert math.prod(p ** e for p, e in pairs) == v


def audit_artifact(path):
    """Independent integrity/certificate audit; NOT independent negative coverage."""
    path = Path(path)
    cfg = (path / 'cfg.json').read_bytes()
    config = json.loads(cfg)
    if config['schema'] == 4:
        return audit_cursor_artifact(path)
    assert config['schema'] in (1, 2, 3)
    initial_start = int(config.get('start_k', '0'))
    depth = config.get('depth', 3)
    assert 0 <= initial_start < int(config['K'])
    assert 3 <= depth < config['n']
    head = hashlib.sha256(hashlib.sha256(cfg).hexdigest().encode() + (path / 'env.txt').read_bytes()).hexdigest()
    records = (path / 'cover.tsv').read_bytes().splitlines(keepends=True)
    windows = []
    allocated = 0
    if config['schema'] == 3:
        assert 0 < int(config['slice_ns']) <= 60000000000
    observed_heads = []
    for raw in records:
        assert raw.endswith(b'\n') and b'\r' not in raw and b'\0' not in raw
        payload, digest = raw[:-1].rsplit(b'\t', 1)
        head = hashlib.sha256(head.encode() + payload).hexdigest()
        assert head.encode() == digest
        observed_heads.append(head)
        f = payload.decode().split('\t')
        if f[0] == 'W':
            assert len(f) == 4
            n, k, total = map(int, f[1:])
            if not windows:
                assert n == config['n'] and k == int(config['K'])
                low = polygon(n, initial_start) + 1 if initial_start else math.prod(
                    (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37,
                     41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89)[:n])
            else:
                old = windows[-1]
                assert len(old['units']) == old['total']
                if n == old['n']:
                    assert old['best'] == 0 and k > old['k']
                    low = old['high'] + 1
                else:
                    assert n == old['n'] + 1 and old['best'] > 0
                    low = math.prod((2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37,
                                     41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89)[:n])
            allocated += total
            assert allocated <= 60000
            windows.append({'n': n, 'k': k, 'total': total, 'defined': total,
                            'retired': set(), 'units': {}, 'best': 0,
                            'low': low, 'high': polygon(n, k)})
        elif f[0] == 'U':
            assert len(f) == 9
            w = windows[-1]
            uid, nodes, leaves, pass64, roots, k, duration = map(int, f[1:8])
            assert 0 <= uid < w['defined'] and uid not in w['units'] and uid not in w['retired']
            assert 0 <= roots <= pass64 <= leaves and nodes >= 0 and duration >= 0
            if k:
                assert 1 <= k <= w['k']
                factors(f[8], w['n'], polygon(w['n'], k))
                w['best'] = min(w['best'] or k, k)
            else:
                assert f[8] == '-'
            w['units'][uid] = (nodes, leaves, pass64, roots)
        elif f[0] == 'R':
            assert config['schema'] == 3 and len(f) == 3
            w = windows[-1]
            uid, children = map(int, f[1:])
            assert 0 <= uid < w['defined'] and uid not in w['units'] and uid not in w['retired']
            assert children > 0
            w['retired'].add(uid)
            w['defined'] += children
            w['total'] += children - 1
            allocated += children
            assert allocated <= 60000
        else:
            assert f[0] == 'S' and len(f) == 4 and 1 <= int(f[1]) <= 16
            assert int(f[2]) >= 0 and f[3] in {'COMPLETE', 'BUDGET', 'INTERRUPTED'}
            assert (f[3] == 'COMPLETE') == (len(windows[-1]['units']) == windows[-1]['total'])
    state = json.loads((path / 'state.json').read_text())
    assert state['head'] == head
    w = windows[-1]
    assert state['schema'] == config['schema'] and state['windows'] == len(windows)
    assert state['n'] == w['n'] and int(state['K']) == w['k']
    assert int(state['low']) == w['low'] and int(state['high']) == w['high']
    if config['schema'] >= 2:
        assert state['depth'] == depth and int(state['initial_start_k']) == initial_start
    assert state['completed'] == len(w['units']) and state['total'] == w['total']
    if config['schema'] == 3:
        assert state['defined'] == w['defined'] and state['refined'] == len(w['retired'])
        assert state['allocated'] == allocated
    assert state['candidate'] == w['best']
    assert state['complete'] == (len(w['units']) == w['total'])
    for i, name in enumerate(('nodes', 'leaves', 'pass64', 'roots')):
        assert int(state[name]) == sum(row[i] for row in w['units'].values())
    rows = (path / 'hits.tsv').read_text().splitlines()
    closed = [x for x in windows if len(x['units']) == x['total']]
    assert rows[0] == 'n\tk\tv\tfactors' and len(rows) == len(closed) + 1
    for row, window in zip(rows[1:], closed):
        n, k, v, cert = row.split('\t')
        n, k, v = int(n), int(k), int(v)
        assert n == window['n'] and k == window['best']
        if k:
            assert v == polygon(n, k)
            factors(cert, n, v)
        else:
            assert v == 0 and cert == '-'
    return state


def audit_cursor_artifact(path):
    """Independent schema4 chain, base-state, counters and positive certificates.

    Structural replay is evidence of integrity, never an exhaustive oracle.
    This audit requires current caches; native verify also accepts valid lag.
    """
    cfg = (path / 'cfg.json').read_bytes(); config = json.loads(cfg)
    depth = config['depth']; initial_start = int(config['start_k'])
    assert config['schema'] == 4 and 3 <= depth < config['n']
    assert 0 < int(config['slice_ns']) <= 60000000000
    head = hashlib.sha256(hashlib.sha256(cfg).hexdigest().encode() + (path / 'env.txt').read_bytes()).hexdigest()
    allocated = segments = elapsed = checkpoints = maximum = generation = 0
    windows = []; base = False; history = hashlib.sha256(b'').hexdigest()
    primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37,
              41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89)
    def whash(w):
        text = f"W\t{w['n']}\t{w['k']}\t{depth}\t{w['low']}\t{w['high']}\t{w['total']}\n"
        for i in range(w['total']):
            text += w['units'][i]['payload'] + '\n' if i in w['units'] else f'Z\t{i}\n'
        text += w['hit_payload'] if w['best'] else 'NO_H'
        return hashlib.sha256(text.encode()).hexdigest()
    def semhash():
        rows = sum(x['done'] for w in windows for x in w['units'].values())
        meta = f"{len(windows)}\t{allocated}\t{rows}\t{segments}\t{elapsed}\t{checkpoints}\t{maximum}"
        return hashlib.sha256((hashlib.sha256(cfg).hexdigest() + history + whash(windows[-1]) + meta).encode()).hexdigest()
    for raw in (path / 'cover.tsv').read_bytes().splitlines(keepends=True):
        assert raw.endswith(b'\n') and b'\r' not in raw and b'\0' not in raw
        payload, digest = raw[:-1].rsplit(b'\t', 1)
        head = hashlib.sha256(head.encode() + payload).hexdigest(); assert head.encode() == digest
        text = payload.decode(); f = text.split('\t'); tag = f[0]
        if tag == 'B':
            assert len(f) == 8 and not windows and not base and not generation
            generation = int(f[1]); assert generation > 0
            segments, elapsed, checkpoints, maximum = map(int, f[3:7])
            declared = f[7]; base = True
        elif tag == 'E':
            assert len(f) == 1 and base and windows
            base = False; assert declared == semhash()
        elif tag == 'W':
            assert len(f) == 4; n, k, total = map(int, f[1:])
            if not windows:
                assert (n, k) == (config['n'], int(config['K']))
                low = polygon(n, initial_start) + 1 if initial_start else math.prod(primes[:n])
            else:
                old = windows[-1]; assert sum(x['done'] for x in old['units'].values()) == old['total']
                history = hashlib.sha256((history + whash(old)).encode()).hexdigest()
                if n == old['n']:
                    assert old['best'] == 0 and k > old['k']; low = old['high'] + 1
                else:
                    assert n == old['n'] + 1 and old['best']; low = math.prod(primes[:n])
            allocated += total; assert allocated <= 60000 and len(windows) < 1000
            windows.append(dict(n=n, k=k, total=total, low=low, high=polygon(n, k),
                                units={}, best=0, owner=None, cert='', hit_payload=''))
        elif tag in ('P', 'U'):
            done = tag == 'U'; assert len(f) == (7 if done else 8)
            w = windows[-1]; uid, nodes, leaves, passed, roots, ns = map(int, f[1:7])
            assert 0 <= uid < w['total'] and 0 <= roots <= passed <= leaves <= w['high']
            old = w['units'].get(uid); counters = (nodes, leaves, passed, roots)
            assert all(0 <= v <= MAX128 for v in counters) and 0 <= ns < 2**64
            if old:
                assert not old['done'] and all(a >= b for a, b in zip(counters, old['counters']))
                assert not base
            cursor = None
            if not done:
                cursor = tuple(tuple(map(int, x.split('^'))) for x in f[7].split(','))
                product = math.prod(p**e for p, e in cursor)
                factors(f[7], w['n'], product); assert product <= w['high']
                assert leaves > (old['counters'][1] if old else 0)
                if old: assert cursor > old['cursor']
                if not base: checkpoints += 1
            w['units'][uid] = dict(done=done, counters=counters, cursor=cursor, payload=text)
            maximum = max(maximum, ns)
        elif tag == 'H':
            assert len(f) == 4; w = windows[-1]; uid, k = map(int, f[1:3])
            assert 0 <= uid < w['total'] and 0 < k <= w['k'] and polygon(w['n'], k) >= w['low']
            assert not w['best'] or (not base and k < w['best'])
            if not base: assert uid not in w['units'] or not w['units'][uid]['done']
            factors(f[3], w['n'], polygon(w['n'], k))
            w.update(best=k, owner=uid, cert=f[3], hit_payload=text)
        elif tag == 'S':
            assert len(f) == 5 and not base and 1 <= int(f[1]) <= 16
            w = windows[-1]; complete = sum(x['done'] for x in w['units'].values()) == w['total']
            assert f[3] in ('COMPLETE', 'BUDGET', 'INTERRUPTED') and (f[3] == 'COMPLETE') == complete
            segments += 1; elapsed += int(f[2]); assert int(f[4]) >= maximum; maximum = int(f[4])
        else: raise AssertionError(tag)
    assert not base and windows
    state = json.loads((path / 'state.json').read_bytes()); w = windows[-1]
    done = sum(x['done'] for x in w['units'].values())
    assert state['head'] == head and state['schema'] == 4
    for name, value in dict(windows=len(windows), n=w['n'], K=w['k'], depth=depth,
                            initial_start_k=initial_start, low=w['low'], high=w['high'], completed=done,
                            total=w['total'], allocated=allocated, candidate=w['best'], generation=generation,
                            segments=segments, elapsed_ns=elapsed, checkpoints=checkpoints, max_quantum_ns=maximum).items():
        assert int(state[name]) == value, (name, state[name], value)
    assert state['best_owner'] == w['owner'] and state['complete'] == (done == w['total'])
    for i, name in enumerate(('nodes', 'leaves', 'pass64', 'roots')):
        assert int(state[name]) == sum(x['counters'][i] for x in w['units'].values())
    expected = 'n\tk\tv\tfactors\n'
    for w in windows:
        if sum(x['done'] for x in w['units'].values()) == w['total']:
            expected += f"{w['n']}\t{w['best']}\t{polygon(w['n'], w['best']) if w['best'] else 0}\t{w['cert'] or '-'}\n"
    assert (path / 'hits.tsv').read_text() == expected
    return state


def call(binary, *args, expected=0, timeout=25):
    p = subprocess.run([str(binary), *map(str, args)], stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=timeout)
    assert p.returncode == expected, (args, p.returncode, p.stdout, p.stderr)
    return p


def small_sets(binary, work):
    fixture = work / 'fixture.c'
    fixture.write_text('#define main producer_main\n#include "' + str(ROOT / 'src/a358321.c') + '"\n#undef main\n' + r'''
int main(int argc,char **argv) {
    if(argc!=5)return 1;
    Window w;memset(&w,0,sizeof w);w.n=(unsigned)number(argv[1],7);w.depth=3;
    w.low=number(argv[2],1000000);w.high=number(argv[3],1000000);
    w.primes=primes_make((uint32_t)(w.high/primorial(w.n-1)));masks(&w);
    w.units=calloc(MAX_UNITS,sizeof *w.units);require(w.units!=NULL,"fixture allocation");
    Unit u={0};if(tail(&w,1,0,w.n))prefixes(&w,1,0,0,u);
    for(size_t id=0;id<w.count;id++) {
        Worker a;memset(&a,0,sizeof a);a.w=&w;a.id=id;a.deadline=UINT64_MAX;
        a.filters=number(argv[4],1)!=0;a.emit=stdout;
        memcpy(a.p,w.units[id].p,sizeof w.units[id].p);memcpy(a.e,w.units[id].e,sizeof w.units[id].e);
        require(dfs(&a,w.units[id].product,w.units[id].next,w.depth),"fixture complete");
    }
    window_free(&w);return 0;
}
''')
    subprocess.run(['gcc-13', '-std=c17', '-O2', '-fopenmp', '-Wall', '-Wextra',
                    str(fixture), '-lm', '-o', str(work / 'fixture')], check=True, capture_output=True)
    omega = [0] * 600001
    for p in range(2, len(omega)):
        if omega[p] == 0:
            for v in range(p, len(omega), p):
                omega[v] += 1
    evidence = []
    for n, lo, hi in [(4, 1, 10000), (4, 210, 44100), (5, 11, 50000),
                      (6, 30000, 60000), (7, 1, 600000), (7, 1, 10000),
                      (4, 44100, 44100), (4, 44101, 44101)]:
        expected = {v for v in range(lo, hi + 1) if omega[v] == n}
        hits = {(k, polygon(n, k)) for k in range(1, math.isqrt(2 * hi) + 2)
                if polygon(n, k) in expected}
        for filtering in (0, 1):
            p = call(work / 'fixture', n, lo, hi, filtering)
            actual, found = [], set()
            for line in p.stdout.splitlines():
                if line.startswith('H '):
                    _, k, v = line.split(); found.add((int(k), int(v)))
                else:
                    actual.append(int(line))
            assert len(actual) == len(set(actual)) and set(actual) == expected
            assert found == hits
        evidence.append({'n': n, 'low': lo, 'high': hi, 'distinct_values': len(expected), 'positive_values': len(hits)})
    return evidence


def quick(binary, work):
    call(binary, 'selftest')
    domain = call(binary, 'domain').stdout.splitlines()
    model = json.loads((ROOT / 'outputs/plan/model.json').read_text())['proposed_capacity'][:12]
    assert len(domain) == 13
    for line, row in zip(domain[1:], model):
        n, u, k, cap = map(int, line.split('\t'))
        assert (n, u, k, cap) == (row['n'], row['max_value'], row['max_index'], row['max_prime_base'])
        assert polygon(n, k) <= u < polygon(n, k + 1)
        call(binary, 'init', work / f'bad{n}', n, k + 1, expected=1)
    for token in ('0', '-1', '+1', '01', ' 1', '1 ', '1e3', '1\n', '18446744073709551616'):
        call(binary, 'next', work / 'absent', token, 1, expected=1)
    for args in [[], ['--unknown'], ['selftest', 13], ['init', work / 'absent', 12, 1],
                 ['init', work / 'absent', 25, 1], ['next', work / 'absent', 1, 0],
                 ['next', work / 'absent', 17, 1], ['next', work / 'absent', 1, 3301]]:
        call(binary, *args, expected=1)
    run = work / 'run'
    call(binary, 'init', run, 13, 10000000)
    initial_state = (run / 'state.json').read_bytes()
    audit_artifact(run)
    call(binary, 'init', run, 13, 10000000, expected=1)
    call(binary, 'extend', run, 13, 10000001, expected=1)
    call(binary, 'next', run, 1, 1)
    before = {p.name: p.read_bytes() for p in run.iterdir()}
    audit_artifact(run)
    call(binary, 'next', run, 16, 1)
    assert before == {p.name: p.read_bytes() for p in run.iterdir()}
    # Snapshot lag and torn tail: only incomplete final bytes may be removed.
    (run / 'state.json').write_bytes(initial_state)
    with (run / 'cover.tsv').open('ab') as f:
        f.write(b'U\t999')
    call(binary, 'verify', run, expected=1)
    # A complete window must repair the tail too; this regression checks it.
    call(binary, 'next', run, 1, 1)
    call(binary, 'verify', run)
    audit_artifact(run)
    call(binary, 'extend', run, 13, 20000000)
    call(binary, 'next', run, 8, 1)
    audit_artifact(run)
    for name in ('cfg.json', 'cover.tsv', 'state.json', 'hits.tsv', 'env.txt'):
        bad = work / ('bad_' + name)
        shutil.copytree(run, bad)
        with (bad / name).open('ab') as f:
            f.write(b'corrupt\n')
        call(binary, 'verify', bad, expected=1)
    extra = run / 'unknown'; extra.write_text('x')
    call(binary, 'verify', run, expected=1); extra.unlink()
    # Fail-closed I/O path without changing directory permissions or user data.
    (run / 'state.json.tmp').mkdir()
    call(binary, 'next', run, 1, 1, expected=1)
    (run / 'state.json.tmp').rmdir()
    call(binary, 'seal', run)
    call(binary, 'verify', run)
    call(binary, 'seal', run)
    call(binary, 'extend', run, 13, 30000000, expected=1)
    # A verified archive reconstructs exactly the six intended files.
    import tarfile
    with tarfile.open(run / 'run.tgz') as t:
        names = t.getnames()
        assert sorted(names) == sorted(['cfg.json', 'cover.tsv', 'state.json', 'hits.tsv', 'env.txt', 'sha.txt'])
        for name in names:
            assert t.extractfile(name).read() == (run / name).read_bytes()
    zero = work / 'zero'
    call(binary, 'init', zero, 13, 1)
    assert audit_artifact(zero)['candidate'] == 0
    return small_sets(binary, work)


def calibrate(binary, out):
    out.mkdir(parents=True, exist_ok=False)
    observations = []
    started = time.monotonic()
    # Predetermined scope; no n>=16 searches. All setup is charged.
    for n, threads in [(13, 8), (14, 8), (15, 1), (15, 8), (15, 16)]:
        assert time.monotonic() - started < 175, 'calibration ceiling reached'
        run = out / f'n{n}t{threads}'
        start = time.monotonic()
        init = call(binary, 'init', run, n, BASELINE[n], timeout=15)
        p = call(binary, 'next', run, threads, 25, timeout=min(35, 179 - (time.monotonic() - started)))
        wall = time.monotonic() - start
        state = audit_artifact(run)
        assert state['complete'] and state['candidate'] == BASELINE[n]
        result = json.loads(p.stdout)
        record = {'n': n, 'threads': threads, 'wall_seconds_including_init': wall,
                  'cpu_seconds_next': result['cpu_seconds'], 'peak_rss_bytes_next': result['rss_bytes'],
                  'leaves': int(state['leaves']), 'nodes': int(state['nodes']), 'root_calls': int(state['roots']),
                  'units': state['total'], 'rate_leaves_per_second': int(state['leaves']) / wall}
        (out / f'n{n}t{threads}.log').write_text(init.stdout + init.stderr + p.stdout + p.stderr)
        observations.append(record)
    elapsed = time.monotonic() - started
    assert elapsed <= 180
    report = {'scope': 'Known full-path replay only, no new terms', 'elapsed_seconds': elapsed,
              'candidate': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in (ROOT / 'src/a358321.c', ROOT / 'src/Makefile', binary)},
              'observations': observations}
    (out / 'bench.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=ROOT / 'src/a358321')
    p.add_argument('--artifact', type=Path)
    p.add_argument('--calibrate', type=Path)
    args = p.parse_args()
    binary = args.binary.resolve()
    if args.artifact:
        print(json.dumps(audit_artifact(args.artifact), indent=2)); return
    if args.calibrate:
        calibrate(binary, args.calibrate.resolve()); return
    with tempfile.TemporaryDirectory(prefix='a358321-') as tmp:
        evidence = quick(binary, Path(tmp))
    print(json.dumps({'status': 'PASS', 'exact_set_cases': evidence}, indent=2))


if __name__ == '__main__':
    main()
