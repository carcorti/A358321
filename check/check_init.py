#!/usr/bin/env python3
"""Bounded A358321 init-parent durability regression, Carlo Corti.

Observes fsync on the actual CLI with a test-only interposer. No power-loss
simulation or official search. Tests known n13 setup only; no new terms.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile


def run(binary, cc, original):
    with tempfile.TemporaryDirectory(prefix='a358321-init-') as tmp:
        base = Path(tmp)
        shim = base / 'fslog.c'
        shim.write_text(r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
int fsync(int fd) {
    int (*real_sync)(int)=(int (*)(int))dlsym(RTLD_NEXT,"fsync");
    if(!real_sync)_exit(125);
    char link[64],path[4096];
    snprintf(link,sizeof link,"/proc/self/fd/%d",fd);
    ssize_t n=readlink(link,path,sizeof path-1);
    if(n>0){path[n]=0;fprintf(stderr,"FSYNC %s\n",path);}
    return real_sync(fd);
}
''')
        subprocess.run(cc + ['-shared', '-fPIC', '-O1', str(shim), '-ldl', '-o', str(base / 'fslog.so')],
                       check=True, capture_output=True)
        env = os.environ.copy()
        env['LD_PRELOAD'] = str(base / 'fslog.so') + (':' + env['LD_PRELOAD'] if env.get('LD_PRELOAD') else '')
        (base / 'nested').mkdir()

        def invoke(action, path):
            args = [str(binary), action, str(path)]
            if action == 'init':
                args += ['13', '10000000']
            return subprocess.run(args, cwd=base, env=env, capture_output=True,
                                  text=True, stdin=subprocess.DEVNULL, timeout=15)

        paths = ['plain', 'slash/', './dot/', 'multi////', 'nested/plain',
                 'nested/slash/', 'nested///multi///', str(base / 'absolute'),
                 str(base / 'absolute space') + '/']
        observations = []
        for path in paths:
            directory = (base / path).resolve()
            result = invoke('init', path)
            assert result.returncode == 0, (path, result.returncode, result.stderr)
            synced = [Path(x[6:]) for x in result.stderr.splitlines() if x.startswith('FSYNC ')]
            assert synced, (path, result.stderr)
            correct = synced[0] == directory.parent
            assert correct == (not original or not path.endswith('/')), (path, synced)
            assert invoke('verify', path).returncode == 0
            before = {x.name: x.read_bytes() for x in directory.iterdir()}
            refused = invoke('init', path)
            assert refused.returncode == 1 and 'FSYNC ' not in refused.stderr
            assert before == {x.name: x.read_bytes() for x in directory.iterdir()}
            observations.append({'input_form': path.replace(str(base), 'ABS'),
                                 'first_fsync_is_parent': correct,
                                 'verify_and_existing_no_clobber': True})
        for path in ['', '.', '/', '//', 'missing/child/']:
            result = invoke('init', path)
            assert result.returncode == 1 and 'FSYNC ' not in result.stderr, (path, result.stderr)
        return {'status': 'ORIGINAL_DEFECT_REPRODUCED' if original else 'PASS',
                'scope': 'nine actual init paths, known n13 setup only; no search or power-loss test',
                'observations': observations,
                'invalid_or_existing_paths_refused_before_fsync': 5,
                'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--cc', default='gcc-13')
    parser.add_argument('--expect-original', action='store_true')
    args = parser.parse_args()
    print(json.dumps(run(args.binary.resolve(), shlex.split(args.cc), args.expect_original), indent=2))
