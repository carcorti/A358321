#!/usr/bin/env python3
"""A358321 round-02 regressions, Carlo Corti.

Bounded known n13 windows only. Wide-counter continuation state is synthesized using valid
hash-chained interrupted-invocation records, never by running 60000 jobs.
Signals are injected synchronously after handler installation, without sleeps.
No official campaign, n>=16 predicate search or canonical data mutation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile


def invoke(binary, *args, env=None, rc=0):
    p = subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True,
                       stdin=subprocess.DEVNULL, timeout=20, env=env)
    if rc is not None:
        assert p.returncode == rc, (args, p.returncode, p.stdout, p.stderr)
    return p


def insert_interrupted_segments(directory, count):
    f = directory / 'cover.tsv'
    head = f.read_bytes().splitlines()[-1].rsplit(b'\t', 1)[1]
    with f.open('ab') as stream:
        for _ in range(count):
            payload = b'S\t1\t1000000\tINTERRUPTED\t0'
            head = hashlib.sha256(head + payload).hexdigest().encode()
            stream.write(payload + b'\t' + head + b'\n')


def run(binary, cc):
    with tempfile.TemporaryDirectory(prefix='a358321-review02-') as tmp:
        work = Path(tmp)
        exact = work / 'exact'
        invoke(binary, 'init', exact, 13, 10000000)
        insert_interrupted_segments(exact, 59999)
        invoke(binary, 'next', exact, 1, 5)
        assert int(json.loads((exact / 'state.json').read_text())['segments']) == 60000
        invoke(binary, 'verify', exact)
        invoke(binary, 'extend', exact, 13, 20000000)
        invoke(binary, 'next', exact, 2, 5)
        s = json.loads((exact / 'state.json').read_text())
        assert int(s['segments']) == 60001 and s['complete'] and s['candidate'] == 0
        invoke(binary, 'verify', exact)

        shim = work / 'signal.c'
        shim.write_text(r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
int sigaction(int sig,const struct sigaction *action,struct sigaction *old) {
    int (*real_action)(int,const struct sigaction *,struct sigaction *) =
        (int (*)(int,const struct sigaction *,struct sigaction *))dlsym(RTLD_NEXT,"sigaction");
    int rc=real_action(sig,action,old);
    if(rc==0 && sig==SIGTERM && action && action->sa_handler!=SIG_DFL && action->sa_handler!=SIG_IGN)
        raise(SIGTERM);
    return rc;
}
''')
        subprocess.run(cc + ['-shared', '-fPIC', '-O1', str(shim), '-ldl', '-o', str(work / 'signal.so')],
                       check=True, capture_output=True)
        signaled = work / 'signaled'
        invoke(binary, 'init', signaled, 13, 10000000)
        env = os.environ.copy()
        env['LD_PRELOAD'] = str(work / 'signal.so') + (':' + env['LD_PRELOAD'] if env.get('LD_PRELOAD') else '')
        p = invoke(binary, 'next', signaled, 1, 5, env=env, rc=None)
        status = json.loads(p.stdout)
        signal_retained = p.returncode == 2 and not status['complete'] and status['completed'] == 0
        assert signal_retained, (p.returncode, p.stdout, p.stderr)
        invoke(binary, 'verify', signaled)
        invoke(binary, 'next', signaled, 2, 5)
        assert json.loads((signaled / 'state.json').read_text())['complete']

        fixture = work / 'heartbeat.c'
        source = binary.parent / 'a358321.c'
        fixture.write_text('#define main producer_main\n#include ' + json.dumps(str(source)) + '\n#undef main\n' + r'''
int main(void) {
    Window w;memset(&w,0,sizeof w);w.n=13;w.count=1;
    Worker a;memset(&a,0,sizeof a);a.w=&w;a.deadline=UINT64_MAX;a.ticks=16383;
    uint64_t future=ns_now()+UINT64_C(10000000000);atomic_store(&heartbeat,future);
    require(pulse(&a),"heartbeat fixture pulse");
    return atomic_load(&heartbeat)==future?0:3;
}
''')
        subprocess.run(cc + ['-std=c17', '-O1', '-fopenmp', str(fixture), '-lm', '-o', str(work / 'heartbeat')],
                       check=True, capture_output=True)
        p = invoke(work / 'heartbeat', rc=None)
        heartbeat_monotone = p.returncode == 0
        assert heartbeat_monotone, (p.returncode, p.stderr)
        return {'status': 'PASS',
                'wide_segment_counter_continues_beyond60000': True,
                'signal_during_registration_is_retained': signal_retained,
                'heartbeat_never_moves_backwards': heartbeat_monotone,
                'scope': 'known n13 windows and synthetic quota/clock state only'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--cc', default='gcc-13')
    args = parser.parse_args()
    binary = args.binary.resolve()
    result = run(binary, shlex.split(args.cc))
    result['tested_binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
