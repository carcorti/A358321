#!/usr/bin/env python3
"""Carlo Corti: bounded package/retained-evidence checks, not a new negative census.

Original validators run only in an external temporary restoration. Default mode
needs Python >=3.10; --pari, --native, --build and --tex are explicit additions.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = 'files.sha'


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def safe(name):
    need(isinstance(name, str) and name, 'empty/non-string path')
    p = PurePosixPath(name)
    need(not p.is_absolute() and '..' not in p.parts and '\\' not in name
         and p.as_posix() == name and name != '.', 'unsafe/noncanonical path: ' + name)
    return p


def payload(extra=None):
    expected = {}
    for line in (ROOT / MANIFEST).read_text().splitlines():
        need(re.fullmatch(r'[0-9a-f]{64}  .+', line), 'malformed checksum line')
        h, name = line.split('  ', 1)
        safe(name)
        need(name not in expected and name != MANIFEST, 'duplicate/self checksum')
        expected[name] = h
    need(bool(expected), 'empty checksum inventory')
    actual = set()
    allowed_dirs = {'.'}
    for name in set(expected) | {MANIFEST} | ({extra} if extra else set()):
        allowed_dirs.update(str(p) for p in PurePosixPath(name).parents)
    for directory, dirs, files in os.walk(ROOT, followlinks=False):
        rel = Path(directory).relative_to(ROOT)
        if rel == Path('.') and '.git' in dirs:
            need(not (ROOT / '.git').is_symlink(), 'symlink .git metadata')
            dirs.remove('.git')  # Only the root clone-metadata directory.
        for child in dirs + files:
            p = Path(directory) / child
            name = p.relative_to(ROOT).as_posix()
            need(not p.is_symlink(), 'payload symlink: ' + name)
            if p.is_dir():
                need(name in allowed_dirs, 'unexpected directory: ' + name)
            else:
                need(p.is_file(), 'nonregular payload: ' + name)
                actual.add(name)
    wanted = set(expected) | {MANIFEST} | ({extra} if extra else set())
    need(actual == wanted, 'missing/unexpected payload: ' + repr(sorted(actual ^ wanted)))
    for name, h in expected.items():
        need(digest(ROOT / name) == h, 'changed payload: ' + name)
    return expected


def restore(destination):
    destination = Path(destination).resolve()
    need(not destination.exists() and not destination.is_relative_to(ROOT),
         'restore destination must be new and outside the payload')
    index = json.loads((ROOT / 'proof/map.json').read_text())
    need(index['schema'] == 1 and index['author'] == 'Carlo Corti', 'wrong index schema/author')
    need(index['archive'] == 'proof/run.tgz', 'wrong archive name')
    archive = ROOT / index['archive']
    need(archive.stat().st_size == index['archive_bytes']
         and digest(archive) == index['archive_sha256'], 'archive identity')
    rows = index['files']
    seen, members, data = set(), set(), {}
    for row in rows:
        name = row['path']; safe(name)
        need(name not in seen, 'duplicate restoration path')
        seen.add(name)
        need(isinstance(row['bytes'], int) and row['bytes'] >= 0
             and re.fullmatch(r'[0-9a-f]{64}', row['sha256']), 'bad object identity')
        need(isinstance(row['mode'], int) and 0 <= row['mode'] <= 0o777, 'unsafe mode')
        need(('public' in row) != ('member' in row), 'ambiguous object source')
        if 'public' in row:
            safe(row['public'])
            data[name] = (ROOT / row['public']).read_bytes()
        else:
            need(re.fullmatch(r'r[0-9]{4}', row['member']), 'unsafe archive member')
            members.add(row['member'])
    with tarfile.open(archive, 'r:gz') as t:
        entries = t.getmembers()
        need(len(entries) == len(members) == index['objects'], 'extra/duplicate archive objects')
        need({m.name for m in entries} == members and all(m.isfile() for m in entries),
             'wrong archive members/types')
        blobs = {}
        sizes = {row['member']: row['bytes'] for row in rows if 'member' in row}
        for m in entries:
            need(m.size == sizes[m.name], 'object length mismatch')
            blobs[m.name] = t.extractfile(m).read()
        for row in rows:
            if 'member' in row:
                data[row['path']] = blobs[row['member']]
    need(len(rows) == index['restored_paths'] and sum(map(len, data.values())) == index['restored_bytes'],
         'restored inventory/count differs')
    for row in rows:
        b = data[row['path']]
        need(len(b) == row['bytes'] and hashlib.sha256(b).hexdigest() == row['sha256'],
             'object hash differs: ' + row['path'])
    destination.mkdir(parents=True)
    for row in rows:
        p = destination / row['path']
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data[row['path']]); p.chmod(row['mode'])
    return index


def original_hashes(work, index):
    for row in index['files']:
        need(digest(work / row['path']) == row['sha256'], 'restored original changed: ' + row['path'])


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def execute(command, cwd, timeout=90, verbose=False):
    command = list(map(str, command))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONOPTIMIZE='0')
    p = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True,
                       text=True, env=env, timeout=timeout)
    print('COMMAND', json.dumps(command), 'EXIT', p.returncode)
    if verbose or p.returncode:
        print(p.stdout, end=''); print(p.stderr, end='', file=sys.stderr)
    need(p.returncode == 0, 'command failed; see stdout/stderr above')
    return p


def records(work, verbose):
    v = load('current_artifact', work / 'validation/check_a358321.py')
    old = load('earlier_artifact', work / 'old/validation/check_a358321.py')
    pins = json.loads((work / 'outputs/part/old.json').read_text())['files']
    for name, h in pins.items():
        need(digest(work / 'old' / name) == h, 'earlier producer identity: ' + name)
    for job, checker, c, t in [('run1', old, 343, 343), ('run2', v, 576, 577), ('run3', v, 588, 590)]:
        state = checker.audit_artifact(work / 'outputs' / job)
        need((state['completed'], state['total'], state['complete']) == (c, t, c == t), 'native count')
        print('RECORD', job, f'{c}/{t}', 'candidate', state['candidate'])
    mix = load('mixed_arithmetic', work / 'outputs/limit17/mixed.py')
    need(mix.build() == json.loads((work / 'outputs/limit17/units.json').read_text()), 'exact prefix map')
    m = mix.audit(work / 'outputs/run3')
    need(m['scientific_complete'] and not m['native_complete']
         and m['analytically_excluded_pending'] == [0, 110], 'supplement mixed closure')
    # These original deterministic drivers write only disposable certificate copies;
    # original_hashes() requires their regenerated bytes to equal the frozen outputs.
    for name in ('outputs/arith19/check.py', 'outputs/a19/check.py', 'outputs/limit17/test_mixed.py'):
        execute([sys.executable, '-I', '-B', work / name], work, verbose=verbose)
    for n in (16, 17, 18):
        execute([sys.executable, '-I', '-B', work / f'outputs/a{n}/cert.py', '--directory', work / 'outputs/run1'], work, verbose=verbose)
    execute([sys.executable, '-I', '-B', work / 'outputs/r30w1/cert.py'], work, verbose=verbose)
    b = (work / 'data/b358321.txt').read_bytes()
    need(b.endswith(b'\n\n') and not b.endswith(b'\n\n\n') and b'\r' not in b, 'b-file framing')
    pairs = [tuple(map(int, l.split())) for l in b.splitlines() if l]
    need([n for n, _ in pairs] == list(range(3, 20)), 'contiguous 17-row domain')
    seq = (work / 'reference/a358321.seq').read_text()
    historical = [int(x) for x in ''.join(re.findall(r'^%[STU] A358321 (.+)$', seq, re.M)).split(',') if x]
    values = list(historical)
    tex = (ROOT / 'paper/A358321_v4.tex').read_text()
    for n in (16, 17, 18, 19):
        result = json.loads((work / f'outputs/a{n}/result.json').read_text())
        k = result['k']; value = k * ((n - 2) * k - (n - 4)) // 2
        need(value == int(result[f'P{n}']), 'polygonal value')
        need(re.search(rf'^{n} & {k} & {value}\\\\', tex, re.M), 'manuscript result table')
        values.append(k)
    regenerated = ''.join(f'{n} {k}\n' for n, k in enumerate(values, 3)).encode() + b'\n'
    need(regenerated == b == (work / 'outputs/a19/b19.txt').read_bytes(), 'data regeneration')
    labels = re.findall(r'\\label\{([^}]+)\}', tex)
    need(len(labels) == len(set(labels)) and set(re.findall(r'\\(?:ref|eqref)\{([^}]+)\}', tex)) <= set(labels), 'TeX labels')
    need('10.5281/zenodo.xxxxxxxx' in tex, 'author-required sentinel')
    # Verify joins explicitly, including the previously mistyped private-guide constant.
    P = lambda k: k * (17 * k - 15) // 2
    need(P(81587135064138) + 1 == 56579915167777506930163324840, 'producer transition')
    need(P(117760885979226) + 1 == 117874823266203383819035407952, 'decisive lower bound')
    print('PASS exact positive/arithmetic certificates; contiguous data regeneration; native incompleteness preserved')


def implementation(work, binary, cc, verbose):
    execute([binary, 'selftest'], work, verbose=verbose)
    for name, options in [('check_a358321.py', ['--binary', binary]),
                          ('check_review02.py', ['--binary', binary, '--cc', cc]),
                          ('check_init.py', ['--binary', binary, '--cc', cc]),
                          ('check_partition.py', ['--binary', binary, '--cc', cc]),
                          ('check_cursor.py', ['--cc', cc])]:
        execute([sys.executable, '-B', work / 'validation' / name, *options], work, timeout=300, verbose=verbose)
    print('PASS original five bounded implementation validators; no production campaign')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('pari', 'native', 'build', 'tex', 'verbose'):
        parser.add_argument('--' + name, action='store_true')
    parser.add_argument('--restore', type=Path, help='restore original layout to a NEW external directory, then stop')
    parser.add_argument('--test-build', type=Path, help='Makefile test route: bounded checks of this generated public binary')
    parser.add_argument('--cc', default='gcc-13')
    args = parser.parse_args()
    need(sys.version_info >= (3, 10) and not sys.flags.optimize,
         'Python >=3.10 without -O is required (original validators use assertions)')
    extra = None
    if args.test_build:
        need(args.test_build.resolve() == ROOT / 'src/a358321', 'unexpected generated binary path')
        extra = 'src/a358321'
    expected = payload(extra)
    if args.restore:
        need(not any((args.pari, args.native, args.build, args.tex, args.test_build)), 'restore cannot be combined with execution modes')
        index = restore(args.restore)
        original_hashes(args.restore.resolve(), index)
        payload(extra)
        print('RESTORE PASS', index['restored_paths'], 'paths; no checks/search executed')
        return
    with tempfile.TemporaryDirectory(prefix='a358321-check-') as temporary:
        base = Path(temporary); work = base / 'original'
        index = restore(work)
        records(work, args.verbose)
        if args.pari:
            jobs = [(f'outputs/a{n}/cert.gp', f'outputs/a{n}/pari.log') for n in (16, 17, 18)]
            jobs += [('outputs/r30w1/cert.gp', 'outputs/r30w1/pari.log'),
                     ('outputs/arith19/check.gp', 'outputs/arith19/pari.log'),
                     ('outputs/limit17/lemma.gp', 'outputs/limit17/lemma.log')]
            for script, log in jobs:
                p = execute(['gp', '-q', '-f', work / script], work, verbose=args.verbose)
                need(not p.stderr and p.stdout == (work / log).read_text(), 'GP output differs from original; inspect version/diagnostics')
            print('PASS six GP outputs byte-identical to original logs')
        if args.native:
            for producer, job in [('old/src/a358321', 'old/outputs/run1'),
                                  ('src/a358321', 'outputs/run2'), ('src/a358321', 'outputs/run3')]:
                execute([work / producer, 'verify', work / job], work, verbose=args.verbose)
        if args.test_build:
            need(not args.build, '--test-build and --build are mutually exclusive')
            implementation(work, args.test_build.resolve(), args.cc, args.verbose)
        if args.build:
            build = base / 'public'; build.mkdir()
            for name in set(expected) | {MANIFEST}:
                q = build / name; q.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, q)
            execute(['make', '-C', build / 'src', 'CC=' + args.cc, 'test'], build, timeout=600, verbose=args.verbose)
            print('PUBLIC BUILD', digest(build / 'src/a358321'), '(new build; never substituted into historical jobs)')
        if args.tex:
            out = base / 'tex'; out.mkdir()
            for _ in range(2):
                execute(['pdflatex', '-draftmode', '-interaction=nonstopmode', '-halt-on-error',
                         '-output-directory=' + str(out), ROOT / 'paper/A358321_v4.tex'], ROOT, verbose=args.verbose)
            log = (out / 'A358321_v4.log').read_text()
            need(not re.search(r'Overfull|Underfull|undefined|LaTeX Warning:|Package hyperref Warning:|^!', log, re.M), 'TeX warnings/references unresolved')
            need(not list(out.glob('*.pdf')), 'unexpected PDF')
            print('PASS two draftmode compilations; no PDF or visual inspection')
        original_hashes(work, index)
    payload(extra)
    print('PACKAGE CHECK PASS; records/arithmetic, not independent exhaustive negative enumeration')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, AssertionError, subprocess.SubprocessError, tarfile.TarError) as error:
        print('PACKAGE CHECK FAIL:', str(error), file=sys.stderr)
        sys.exit(1)
