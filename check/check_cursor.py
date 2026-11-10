#!/usr/bin/env python3
"""Carlo Corti: independent cursor-set and bounded native compaction checks.

Synthetic state is labelled; known n13 jobs only, no official campaign.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

from check_a358321 import ROOT, audit_artifact, call, polygon

FIXTURE = r'''
#define main producer_main
#include "SOURCE"
#undef main
int main(int argc,char **argv) {
    if(argc==3&&strcmp(argv[1],"compact")==0) {
        Campaign *c=load_campaign(argv[2],false);c=compact_campaign(c,argv[2]);
        print_status(c,"COMPACTED");campaign_free(c);return 0;
    }
    if(argc==3&&strcmp(argv[1],"partial")==0) {
        Campaign *c=load_campaign(argv[2],false);
        for(size_t id=0;id<c->w.count;id++)if(!c->seen[id]) {
            Result r=calculate(&c->w,id,UINT64_MAX);require(commit_result(c,id,&r),"partial progress");break;
        }
        save_snapshots(c);print_status(c,"PARTIAL_FIXTURE");campaign_free(c);return 0;
    }
    if(argc==4&&strcmp(argv[1],"metadata")==0) {
        Campaign *c=load_campaign(argv[2],false);c->segments=number(argv[3],UMAX);
        save_snapshots(c);c=compact_campaign(c,argv[2]);campaign_free(c);return 0;
    }
    if(argc==4&&strcmp(argv[1],"witness")==0) {
        Campaign *c=load_campaign(argv[2],false);char tuple[512];require(strlen(argv[3])<sizeof tuple,"fixture witness length");strcpy(tuple,argv[3]);
        char copy[512];strcpy(copy,tuple);char *parts[MAX_N];require(split(copy,parts,MAX_N,',')==c->w.n,"fixture factors");
        uint32_t p[MAX_N]={0};unsigned e[MAX_N]={0};
        for(unsigned i=0;i<c->w.n;i++){char *v[2];require(split(parts[i],v,2,'^')==2,"fixture factor");p[i]=(uint32_t)number(v[0],UINT32_MAX);e[i]=(unsigned)number(v[1],127);}
        size_t id=0;for(;id<c->w.count;id++)if(!memcmp(c->w.units[id].p,p,c->depth*sizeof *p)&&!memcmp(c->w.units[id].e,e,c->depth*sizeof *e))break;
        require(id<c->w.count,"fixture owner");Result r;memset(&r,0,sizeof r);r.nodes=1;r.leaves=1;r.pass64=1;r.roots=1;r.best=c->w.k;r.cursor_valid=true;
        memcpy(r.p,p,sizeof p);memcpy(r.e,e,sizeof e);memcpy(r.cursor_p,p,sizeof p);memcpy(r.cursor_e,e,sizeof e);
        require(commit_result(c,id,&r),"synthetic witness commit");save_snapshots(c);campaign_free(c);return 0;
    }
    if(argc==2&&strcmp(argv[1],"bounds")==0) {
        printf("{\"unit_bytes\":%zu,\"max_unit_array\":%zu,\"base_max\":%u,\"compact_at\":%u,\"commit_reserve\":%u,\"journal_max\":%u}\n",sizeof(Unit),sizeof(Unit)*MAX_UNITS,BASE_MAX,COMPACT_AT,COMMIT_RESERVE,JOURNAL_MAX);
        return 0;
    }
    if(argc==7&&strcmp(argv[1],"sets")==0) {
        Window w;memset(&w,0,sizeof w);w.n=(unsigned)number(argv[2],7);w.depth=(unsigned)number(argv[3],6);
        w.low=number(argv[4],600000);w.high=600000;w.primes=primes_make((uint32_t)(w.high/primorial(w.n-1)));masks(&w);
        w.units=calloc(MAX_UNITS,sizeof *w.units);require(w.units!=NULL,"fixture allocation");
        Unit u={0};prefixes(&w,1,0,0,u);
        FILE *fp=fopen(argv[5],"r");require(fp!=NULL,"cursor fixture input");char text[512],count[40];
        while(fscanf(fp,"%511s %39s",text,count)==2) {
            uint32_t p[MAX_N]={0};unsigned e[MAX_N]={0};char copy[512];strcpy(copy,text);char *fields[MAX_N];
            require(split(copy,fields,MAX_N,',')==w.n,"fixture tuple size");
            for(unsigned i=0;i<w.n;i++){char *v[2];require(split(fields[i],v,2,'^')==2,"fixture tuple");p[i]=(uint32_t)number(v[0],UINT32_MAX);e[i]=(unsigned)number(v[1],127);}
            size_t id=0;for(;id<w.count;id++)if(!memcmp(w.units[id].p,p,w.depth*sizeof *p)&&!memcmp(w.units[id].e,e,w.depth*sizeof *e))break;
            require(id<w.count,"fixture prefix ownership");Saved *saved=&w.units[id].saved;
            (void)decode_tuple(&w,id,text,w.high,saved->cursor_p,saved->cursor_e);saved->cursor_valid=true;saved->leaves=number(count,UMAX);
        }
        require(feof(fp)&&!ferror(fp),"fixture read");require(fclose(fp)==0,"fixture close");
        for(size_t id=0;id<w.count;id++) {
            const Unit *unit=&w.units[id];const Saved *old=&unit->saved;
            Result r=calculate(&w,id,UINT64_MAX);require(r.done&&!r.error,"calculate resumed completion");
            printf("C %zu %s %" PRIu64 "\n",id,dec(r.leaves,(char[40]){0}),r.best);
            Worker a;memset(&a,0,sizeof a);a.w=&w;a.id=id;a.deadline=UINT64_MAX;a.filters=number(argv[6],1)!=0;a.emit=stdout;
            a.resume=old->cursor_valid;memcpy(a.resume_p,old->cursor_p,sizeof a.resume_p);memcpy(a.resume_e,old->cursor_e,sizeof a.resume_e);
            memcpy(a.p,unit->p,sizeof a.p);memcpy(a.e,unit->e,sizeof a.e);
            require(dfs(&a,unit->product,unit->next,unit->depth)&&!a.resume,"resumed exact set");
        }
        window_free(&w);return 0;
    }
    return producer_main(argc,argv);
}
'''

SHIM = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
static unsigned site;
static void checkpoint(const char *op) {
    ++site;fprintf(stderr,"FAULTSITE %u %s\n",site,op);fflush(stderr);
    const char *s=getenv("CURSOR_FAULT");if(s&&strtoul(s,NULL,10)==site)_exit(99);
}
int fsync(int fd) {
    int (*fn)(int)=(int (*)(int))dlsym(RTLD_NEXT,"fsync");int r=fn(fd);
    if(r==0)checkpoint("fsync");return r;
}
int renameat(int a,const char *b,int c,const char *d) {
    int (*fn)(int,const char *,int,const char *)=(int (*)(int,const char *,int,const char *))dlsym(RTLD_NEXT,"renameat");
    int r=fn(a,b,c,d);if(r==0)checkpoint(b);return r;
}
'''


def factor_tuple(v, primes):
    result = []
    for p in primes:
        if p * p > v: break
        if v % p == 0:
            e = 0
            while v % p == 0: v //= p; e += 1
            result.append((p, e))
    if v > 1: result.append((v, 1))
    return tuple(result)


def checks(cc, instrument=False):
    with tempfile.TemporaryDirectory(prefix='a358321-cursor-') as tmp:
        work = Path(tmp); fixture = work / 'fixture'
        source = work / 'fixture.c'; source.write_text(FIXTURE.replace('SOURCE', str(ROOT / 'src/a358321.c')))
        flags = ['-O2', '-std=c17', '-fopenmp', '-Wall', '-Wextra', '-Wpedantic', '-Wshadow',
                 '-Wconversion', '-Wdouble-promotion', '-Wformat=2', '-Werror']
        if instrument: flags += ['-O1', '-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run(shlex.split(cc) + flags + [str(source), '-lm', '-o', str(fixture)], check=True, capture_output=True)
        # Fixed production quantum for exact-set fixtures; separate tiny-quantum build for real P.
        shutil.copyfile(ROOT / 'src/a358321.c', work / 'a358321.c'); shutil.copyfile(ROOT / 'src/Makefile', work / 'Makefile')
        bounds = json.loads(call(fixture, 'bounds').stdout)
        omega = bytearray(600001); primes = []
        for p in range(2, len(omega)):
            if not omega[p]:
                primes.append(p)
                for v in range(p, len(omega), p): omega[v] += 1
        sets = []
        for n, depth, low in [(4, 3, 1), (4, 3, 300001), (5, 3, 1), (5, 4, 300001), (6, 3, 1), (6, 5, 1), (7, 3, 1), (7, 6, 1)]:
            groups = {}
            for v in range(2, len(omega)):
                if omega[v] == n:
                    t = factor_tuple(v, primes); groups.setdefault(t[:depth], []).append((t, v))
            for rows in groups.values(): rows.sort()
            for cut in (0, 1, 2, 3):
                cursors = []; remaining = set(); total = 0; minima = []
                for prefix, rows in sorted(groups.items()):
                    count = (0, 1, len(rows)//2, len(rows))[cut]
                    if count:
                        cursors.append(','.join(f'{p}^{e}' for p, e in rows[count-1][0]) + f' {count}\n')
                    total += len(rows)
                    remaining.update(v for _, v in rows[count:] if v >= low)
                    positive = [k for _, v in rows[count:] if v >= low
                                for k in [math.isqrt(8*(n-2)*v+(n-4)**2)]
                                if k*k == 8*(n-2)*v+(n-4)**2 and (k+n-4)%(2*(n-2)) == 0]
                    minima.append(min(((k+n-4)//(2*(n-2)) for k in positive), default=0))
                cursor = work / 'cursor.txt'; cursor.write_text(''.join(cursors))
                for filters in (0, 1):
                    out = call(fixture, 'sets', n, depth, low, cursor, filters, timeout=30)
                    emitted = [int(x) for x in out.stdout.splitlines() if x and x[0].isdigit()]
                    counts = [tuple(map(int, x.split()[1:])) for x in out.stdout.splitlines() if x.startswith('C ')]
                    assert len(emitted) == len(set(emitted)) and set(emitted) == remaining, (n, depth, low, cut, filters)
                    assert sum(row[1] for row in counts) == total
                    assert [row[2] for row in counts] == minima
                sets.append((n, depth, low, cut, len(remaining)))
        # True producer partial checkpoints, not synthetic U declarations.
        subprocess.run(shlex.split(cc) + flags + ['-DUNIT_SLICE_NS=1ULL', str(source), '-lm', '-o', str(fixture)], check=True, capture_output=True)
        known = 122574155; job = work / 'pending'
        call(fixture, 'init', job, 13, known, known - 1, 3)
        observations = []
        for _ in range(3):
            call(fixture, 'partial', job); observations.append(audit_artifact(job))
        assert any(int(x['checkpoints']) for x in observations)
        assert observations[-1]['allocated'] == observations[0]['allocated']
        before = audit_artifact(job)
        call(fixture, 'compact', job); after = audit_artifact(job)
        assert int(after['generation']) == 1
        assert {k:v for k,v in before.items() if k not in ('head','generation')} == {k:v for k,v in after.items() if k not in ('head','generation')}
        call(fixture, 'compact', job); assert int(audit_artifact(job)['generation']) == 2
        # Every fsync and rename in compaction, including journal replacement/cache gap.
        fault_rows = []
        if not instrument:
            shim = work / 'shim.c'; shim.write_text(SHIM)
            subprocess.run(shlex.split(cc) + ['-O1', '-shared', '-fPIC', str(shim), '-ldl', '-o', str(work/'shim.so')], check=True, capture_output=True)
            env = os.environ.copy(); env['LD_PRELOAD'] = str(work/'shim.so')
            probe = work/'probe'; shutil.copytree(job, probe)
            result = subprocess.run([str(fixture), 'compact', str(probe)], env=env, capture_output=True, text=True, timeout=25)
            assert result.returncode == 0, result.stderr
            sites = sum(x.startswith('FAULTSITE') for x in result.stderr.splitlines())
            for site in range(1, sites+1):
                crash = work/f'crash{site}'; shutil.copytree(job, crash); env['CURSOR_FAULT'] = str(site)
                result = subprocess.run([str(fixture), 'compact', str(crash)], env=env, capture_output=True, text=True, timeout=25)
                assert result.returncode == 99, (site,result.stderr)
                result = call(fixture, 'verify', crash); status = json.loads(result.stdout)
                assert status['allocated'] == before['allocated'] and status['leaves'] == before['leaves']
                call(fixture, 'compact', crash); audit_artifact(crash)
                fault_rows.append(dict(site=site, snapshot_current=status['snapshot_current']))
        call(fixture, 'next', job, 8, 20, timeout=25); final = audit_artifact(job)
        assert final['complete'] and final['candidate'] == known
        assert int(final['leaves']) > 0 and int(final['checkpoints']) >= 3
        # Typed metadata guard at u128, not an arbitrary invocation quota.
        wide = work/'wide'; call(fixture,'init',wide,13,10000000)
        call(fixture,'metadata',wide,(1<<128)-1); audit_artifact(wide)
        saved = {p.name:p.read_bytes() for p in wide.iterdir()}
        refusal = call(fixture,'next',wide,1,1,expected=1)
        assert 'segment counters exhausted' in refusal.stderr
        assert saved == {p.name:p.read_bytes() for p in wide.iterdir()}
        # Real threshold, synthetic short invocation history; no reduced source limit.
        large = work/'large'; call(fixture,'init',large,13,10000000)
        cover = large/'cover.tsv'; head = cover.read_bytes().splitlines()[-1].rsplit(b'\t',1)[1]
        with cover.open('ab') as stream:
            for _ in range(290000):
                payload = b'S\t1\t1000000\tINTERRUPTED\t0'
                head = hashlib.sha256(head+payload).hexdigest().encode();stream.write(payload+b'\t'+head+b'\n')
        large_before = cover.stat().st_size; assert 26000000 <= large_before <= 32000000
        call(fixture,'next',large,8,20,timeout=30); larges = audit_artifact(large)
        assert int(larges['generation']) == 1 and int(larges['segments']) == 290001
        # >64-bit positive/cursor fixture is synthetic, never a negative certificate.
        witness = work/'witness'; known15 = 6066475415
        call(fixture,'init',witness,15,known15,known15-1,3)
        v = polygon(15,known15); assert v > 2**64
        t = factor_tuple(v,primes); assert len(t) == 15
        text = ','.join(f'{p}^{e}' for p,e in t)
        initial_witness_state = (witness/'state.json').read_bytes()
        call(fixture,'witness',witness,text); ws = audit_artifact(witness)
        raw_witness = (witness/'cover.tsv').read_bytes().splitlines(keepends=True)
        assert raw_witness[1].startswith(b'H\t') and raw_witness[2].startswith(b'P\t')
        hit_crash = work/'hit-crash'; shutil.copytree(witness,hit_crash)
        (hit_crash/'cover.tsv').write_bytes(b''.join(raw_witness[:2]))
        (hit_crash/'state.json').write_bytes(initial_witness_state)
        hs = json.loads(call(fixture,'verify',hit_crash).stdout)
        assert hs['candidate'] == known15 and hs['completed'] == 0 and not hs['snapshot_current']
        call(fixture,'compact',hit_crash); audit_artifact(hit_crash)
        assert ws['candidate'] == known15 and not ws['complete'] and int(ws['checkpoints']) == 1
        call(fixture,'compact',witness); audit_artifact(witness)
        # Each partial commit writes an improved H before its advancing P.
        records = [x.rsplit(b'\t',1)[0] for x in (witness/'cover.tsv').read_bytes().splitlines()]
        assert any(x.startswith(b'H\t') for x in records)
        # Corruption at complete records is refused, including compact-base state.
        hostile = []
        original = (job/'cover.tsv').read_bytes()
        for label, change in [('hash', lambda x:x.replace(b'E\t',b'X\t',1)),
                              ('end', lambda x:b''.join(x.splitlines(keepends=True)[:-1])),
                              ('NUL', lambda x:x+b'P\t0\0\n')]:
            bad = work/label; shutil.copytree(job,bad); (bad/'cover.tsv').write_bytes(change(original))
            call(fixture,'verify',bad,expected=1); hostile.append(label)
        # Closed positive and next-n history survive two compactions and sealing.
        call(fixture, 'compact', job); audit_artifact(job)
        call(fixture, 'extend', job, 14, 1); call(fixture, 'compact', job); audit_artifact(job)
        call(fixture, 'seal', job); call(fixture, 'verify', job)
        # Closed empty history, same-n extension, zero prefixes.
        empty = work/'empty'; call(fixture,'init',empty,13,1); call(fixture,'extend',empty,13,2)
        call(fixture,'compact',empty); audit_artifact(empty); call(fixture,'seal',empty)
        return dict(status='PASS',author='Carlo Corti',exact_cursor_set_cases=sets,
                    actual_checkpoints=int(final['checkpoints']),actual_fixed_units=final['allocated'],
                    fault_sites=fault_rows,bounds=bounds,automatic_compaction_input_bytes=large_before,
                    synthetic_large_positive_value=v,hostile_complete_records=hostile,official_campaign=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cc',default='gcc-13');parser.add_argument('--instrument',action='store_true')
    args = parser.parse_args(); print(json.dumps(checks(args.cc,args.instrument),indent=2))

if __name__ == '__main__': main()
