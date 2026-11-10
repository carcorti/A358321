/* A358321: exact minima of n-gonal indices with n DISTINCT prime factors.
 * Copyright (c) 2026 Carlo Corti.
 * Canonical C17/OpenMP monolith, Linux x86-64, GCC/Clang unsigned __int128.
 * Method: increasing-prime / all-positive-power enumeration (Suteu's
 * A358862 PARI program, Dec 04 2022), exact ordered-tail bounds and streaming
 * minima. This is a fresh implementation, without the original list storage.
 *
 * Build: make -C src. See readme.md for proof, persistence and authority.
 * init never searches; next executes a finite configured window. Partial
 * units are INCOMPLETE. Only complete windows imply a window minimum.
 * A nonzero initial START_K requires separately validated earlier coverage.
 * Numerical support n=13..24 is NOT a campaign authorization or time promise.
 */
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <omp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef BUILD_FLAGS
#define BUILD_FLAGS "unspecified"
#endif
__extension__ typedef unsigned __int128 u128;
#define UMAX ((u128)-1)
#ifndef UNIT_SLICE_NS
#define UNIT_SLICE_NS UINT64_C(60000000000)
#endif
_Static_assert(UNIT_SLICE_NS > 0 && UNIT_SLICE_NS <= UINT64_C(60000000000), "invalid unit quantum");
#define MAX_N 24U
#define MAX_UNITS 60000U
#define MAX_WINDOWS 1000U
#define JOURNAL_MAX 32000000U
#define COMPACT_AT 26000000U
#define BASE_MAX 25345024U
#define COMMIT_RESERVE (16U*(416U+256U)+160U)
#define LINE_MAXIMUM 1536U
#define MEMORY_GUARD (UINT64_C(16) << 30)
_Static_assert(sizeof(size_t) >= 8, "64-bit size_t required");
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal-safe atomic int required");
static _Atomic int interrupted;
static _Atomic uint64_t heartbeat;
static _Atomic unsigned committed;
static _Atomic uint64_t announced_best;
/* Written before parallel work, read-only until the implicit join. */
static uint64_t invocation_start;
static u128 prior_elapsed_ns;
static u128 segment_number;

static void die(const char *fmt, ...) __attribute__((noreturn,format(printf,1,2)));
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap,fmt); fputs("ERROR: ",stderr);
    vfprintf(stderr,fmt,ap); va_end(ap); fputc('\n',stderr); exit(1);
}
static void require(bool yes, const char *s) { if (!yes) die("%s",s); }
static uint64_t ns_now(void) {
    struct timespec t; if (clock_gettime(CLOCK_MONOTONIC,&t)) die("clock_gettime");
    return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static void on_signal(int sig) { (void)sig; atomic_store_explicit(&interrupted,1,memory_order_relaxed); }
static bool decimal(const char *s, u128 max, u128 *out) {
    if (!*s || (s[0]=='0' && s[1])) return false;
    u128 x=0;
    for (; *s; ++s) {
        if (*s<'0'||*s>'9') return false;
        unsigned d=(unsigned)(*s-'0');
        if (x>max/10 || (x==max/10 && d>max%10)) return false;
        x=x*10+d;
    }
    *out=x; return true;
}
static u128 number(const char *s, u128 max) {
    u128 v; if (!decimal(s,max,&v)) die("invalid decimal: %s",s); return v;
}
static char *dec(u128 v, char b[40]) {
    unsigned i=39; b[i]='\0'; do { b[--i]=(char)('0'+v%10); v/=10; } while(v);
    memmove(b,b+i,40-i); return b;
}
static void add(u128 *a, u128 b) { if (*a>UMAX-b) die("counter overflow"); *a+=b; }

/* SHA-256, big-endian message words and standard FIPS initial state. */
typedef struct { uint32_t h[8]; uint64_t bytes; size_t used; unsigned char b[64]; } Sha;
static const uint32_t sk[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static uint32_t rotr(uint32_t x,unsigned n) { return (x>>n)|(x<<(32-n)); }
static void sha_block(Sha *s) {
    uint32_t w[64];
    for(unsigned i=0;i<16;i++) w[i]=((uint32_t)s->b[4*i]<<24)|((uint32_t)s->b[4*i+1]<<16)|((uint32_t)s->b[4*i+2]<<8)|s->b[4*i+3];
    for(unsigned i=16;i<64;i++) {
        uint32_t x=w[i-15],y=w[i-2];
        w[i]=w[i-16]+(rotr(x,7)^rotr(x,18)^(x>>3))+w[i-7]+(rotr(y,17)^rotr(y,19)^(y>>10));
    }
    uint32_t a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
    for(unsigned i=0;i<64;i++) {
        uint32_t t=h+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^(~e&g))+sk[i]+w[i];
        uint32_t u=(rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+u;
    }
    s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static Sha sha_init(void) {
    Sha s={{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19},0,0,{0}}; return s;
}
static void sha_feed(Sha *s,const void *raw,size_t n) {
    const unsigned char *p=raw;
    if (n>UINT64_MAX/8-s->bytes) die("hash input too large");
    s->bytes+=(uint64_t)n;
    while(n) { size_t k=64-s->used; if(k>n) k=n; memcpy(s->b+s->used,p,k); s->used+=k; p+=k;n-=k;
        if(s->used==64) {sha_block(s);s->used=0;} }
}
static void sha_end(Sha s,char out[65]) {
    uint64_t bits=s.bytes*8; s.b[s.used++]=0x80;
    if(s.used>56) {memset(s.b+s.used,0,64-s.used);sha_block(&s);s.used=0;}
    memset(s.b+s.used,0,56-s.used);
    for(unsigned i=0;i<8;i++) s.b[63-i]=(unsigned char)(bits>>(8*i));
    sha_block(&s);
    for(unsigned i=0;i<8;i++) (void)snprintf(out+8*i,9,"%08" PRIx32,s.h[i]);
}
static void hash_text(const char *s,char out[65]) { Sha h=sha_init();sha_feed(&h,s,strlen(s));sha_end(h,out); }
static void hash_fd(int fd,char out[65]) {
    Sha h=sha_init(); unsigned char b[8192]; ssize_t n;
    while((n=read(fd,b,sizeof b))!=0) {if(n<0){if(errno==EINTR)continue;die("hash read: %s",strerror(errno));}sha_feed(&h,b,(size_t)n);}
    sha_end(h,out);
}
static void hash_path(const char *path,char out[65]) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW); if(fd<0)die("open identity %s: %s",path,strerror(errno));
    hash_fd(fd,out);if(close(fd))die("close identity");
}
static void chain_hash(const char prev[65],const char *payload,char out[65]) {
    Sha h=sha_init();sha_feed(&h,prev,64);sha_feed(&h,payload,strlen(payload));sha_end(h,out);
}

static const uint32_t small_primes[25]={2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97};
static u128 primorial(unsigned n) { u128 q=1;for(unsigned i=0;i<n;i++){require(q<=UMAX/small_primes[i],"primorial overflow");q*=small_primes[i];}return q; }
static u128 ceiling(unsigned n) {
    u128 b=(UMAX-(n-4)*(n-4))/(8*(n-2)),q=primorial(n-1);
    /* Compare before multiplying: C*Q may exceed 128 bits at n23/n24. */
    return q>b/UINT32_MAX?b:q*UINT32_MAX;
}
/* At most 64 bisections, with every trial square representable in u128. */
static uint64_t isqrt128(u128 x) {
    uint64_t lo=0,hi=UINT64_MAX;
    while(lo<hi) {
        uint64_t m=lo+(hi-lo)/2+1;
        if((u128)m*m<=x)lo=m;else hi=m-1;
    }
    return lo;
}
/* Floating estimate affects speed only; correction and acceptance are exact. */
static uint64_t root(u128 x) {
    long double f=sqrtl((long double)x);
    uint64_t t=f>=(long double)UINT64_MAX?UINT64_MAX:(uint64_t)f;
    while((u128)t*t>x)--t;
    while(t!=UINT64_MAX && (u128)(t+1)*(t+1)<=x)++t;
    return t;
}
static u128 polygon(unsigned n,uint64_t k) {
    u128 a=k,b=(u128)(n-2)*k-(n-4);
    if((k&1)==0)a/=2;else b/=2;
    require(!b || a<=UMAX/b,"polygon overflow");return a*b;
}
static uint64_t maximum_k(unsigned n) {
    u128 u=ceiling(n);uint64_t t=isqrt128((n-4)*(n-4)+8*(u128)(n-2)*u);
    return (uint64_t)(((u128)t+n-4)/(2*(n-2)));
}
static void valid_target(unsigned n,uint64_t k) {
    require(n>=13 && n<=MAX_N,"n outside 13..24");
    require(k>0 && k<=maximum_k(n),"K outside exact numeric domain");
}
static uint64_t member(unsigned n,u128 v) {
    u128 d=n==16?7*v+9:(n-4)*(n-4)+8*(u128)(n-2)*v;
    uint64_t t=root(d);if((u128)t*t!=d)return 0;
    u128 numerator=(u128)t+(n==16?3:n-4);unsigned denominator=n==16?7:2*(n-2);
    if(numerator%denominator)return 0;
    u128 k=numerator/denominator;if(k==0 || k>UINT64_MAX)return 0;
    return polygon(n,(uint64_t)k)==v?(uint64_t)k:0;
}
typedef struct { uint32_t *p;size_t count;uint32_t cap; } Primes;
static Primes primes_make(uint32_t cap) {
    Primes p={NULL,0,cap}; if(cap<2)return p;
    size_t odd=(size_t)cap/2+1,bytes=(odd+7)/8,capacity=(size_t)cap/2+1;
    require(capacity<=SIZE_MAX/sizeof(uint32_t) && (u128)capacity*4+bytes<MEMORY_GUARD,"prime allocation guard");
    unsigned char *bits=calloc(bytes,1);require(bits!=NULL,"sieve allocation failed");
    for(uint64_t q=3;q*q<=cap;q+=2) if(!(bits[(q/2)/8]&(1U<<((q/2)%8))))
        for(uint64_t v=q*q;v<=cap;v+=2*q)bits[(v/2)/8]|=(unsigned char)(1U<<((v/2)%8));
    /* Allocate once; no second maximum vector and no realloc peak. */
    p.p=malloc(capacity*sizeof *p.p);if(!p.p){free(bits);die("prime vector allocation failed");}
    p.p[p.count++]=2;
    for(uint64_t q=3;q<=cap;q+=2)if(!(bits[(q/2)/8]&(1U<<((q/2)%8))))p.p[p.count++]=(uint32_t)q;
    free(bits);return p;
}
typedef struct {
    u128 nodes,leaves,pass64,roots;uint64_t elapsed_ns;
    uint32_t cursor_p[MAX_N];unsigned cursor_e[MAX_N];bool cursor_valid,done;
} Saved;
typedef struct { u128 product;size_t next;uint32_t p[MAX_N];unsigned e[MAX_N];unsigned depth;Saved saved; } Unit;
typedef struct {
    unsigned n,depth;uint64_t k;u128 low,high;Primes primes;
    unsigned char mask64[64],mask63[63];Unit *units;size_t count;
} Window;
static void masks(Window *w) {
    const unsigned mods[2]={64,63};unsigned char *masks_[2]={w->mask64,w->mask63};
    for(unsigned a=0;a<2;a++)for(unsigned v=0;v<mods[a];v++) {
        unsigned d=w->n==16?7*v+9:(w->n-4)*(w->n-4)+8*(w->n-2)*v;
        for(unsigned t=0;t<mods[a];t++)if((t*t)%mods[a]==d%mods[a])masks_[a][v]=1;
    }
}
static bool tail(const Window *w,u128 m,size_t i,unsigned r) {
    if(r>w->primes.count || i>w->primes.count-r)return false;
    for(unsigned j=0;j<r;j++) { uint32_t q=w->primes.p[i+j];if(m>w->high/q)return false;m*=q; }return true;
}
static void prefixes(Window *w,u128 m,size_t i,unsigned depth,Unit u) {
    unsigned r=w->n-depth;
    if(depth==w->depth) {
        require(w->count<MAX_UNITS,"prefix quota exceeded; horizon not operationally admitted");
        u.product=m;u.next=i;u.depth=depth;w->units[w->count++]=u;return;
    }
    for(size_t j=i;j<w->primes.count;j++) {
        if(!tail(w,m,j,r))break;
        uint32_t q=w->primes.p[j];u128 v=m;
        for(unsigned e=1;v<=w->high/q;e++) {
            v*=q;if(!tail(w,v,j+1,r-1))break;
            u.p[depth]=q;u.e[depth]=e;prefixes(w,v,j+1,depth+1,u);
        }
    }
}
static void window_free(Window *w) {free(w->primes.p);free(w->units);memset(w,0,sizeof *w);}
static void window_make_depth(Window *w,unsigned n,uint64_t k,u128 low,unsigned depth) {
    valid_target(n,k);require(depth>=3&&depth<n,"prefix depth outside3..n-1");
    memset(w,0,sizeof *w);w->n=n;w->depth=depth;w->k=k;w->low=low;w->high=polygon(n,k);
    u128 cap=w->high/primorial(n-1);require(cap<=UINT32_MAX,"prime cap overflow");
    w->primes=primes_make((uint32_t)cap);masks(w);
    w->units=calloc(MAX_UNITS,sizeof *w->units);require(w->units!=NULL,"prefix allocation failed");
    Unit u={0};if(tail(w,1,0,n))prefixes(w,1,0,0,u);
}
typedef struct {
    u128 nodes,leaves,pass64,roots;uint64_t best,elapsed_ns;
    uint32_t p[MAX_N];unsigned e[MAX_N];bool done,error,cursor_valid;
    uint32_t cursor_p[MAX_N];unsigned cursor_e[MAX_N];
} Result;
typedef struct {
    const Window *w;Result result;uint32_t p[MAX_N];unsigned e[MAX_N];
    uint64_t deadline,budget_deadline,ticks;size_t id;bool filters,resume;FILE *emit;
    uint32_t resume_p[MAX_N];unsigned resume_e[MAX_N];
} Worker;
static bool pulse(Worker *a) {
    if((++a->ticks & UINT64_C(16383))!=0)return !atomic_load_explicit(&interrupted,memory_order_relaxed);
    uint64_t now=ns_now();if(now>=a->deadline)return false;
    uint64_t old=atomic_load_explicit(&heartbeat,memory_order_relaxed);
    if(now>old && now-old>=UINT64_C(10000000000) && atomic_compare_exchange_strong_explicit(&heartbeat,&old,now,memory_order_relaxed,memory_order_relaxed)) {
        char b[40],segment[40];fprintf(stderr,"heartbeat n=%u segment=%s unit=%zu completed=%u/%zu unit_leaves=%s candidate=%" PRIu64 " frontier=PREVIOUS_CLOSED_WINDOW elapsed=%.0f s cumulative=%.0f s budget_left=%.0f s total_budget=UNSET\n",a->w->n,dec(segment_number,segment),a->id,atomic_load_explicit(&committed,memory_order_relaxed),a->w->count,dec(a->result.leaves,b),atomic_load_explicit(&announced_best,memory_order_relaxed),(double)(now-invocation_start)/1e9,((double)prior_elapsed_ns+(double)(now-invocation_start))/1e9,(double)(a->budget_deadline>now?a->budget_deadline-now:0)/1e9);
    }
    return !atomic_load_explicit(&interrupted,memory_order_relaxed);
}
static bool bump(u128 *v,Worker *a) {if(*v==UMAX){a->result.error=true;return false;}++*v;return true;}
static bool leaf(Worker *a,u128 v) {
    if(!pulse(a)||!bump(&a->result.leaves,a))return false;
    if(v<a->w->low)return true;
    if(a->emit && fprintf(a->emit,"%s\n",dec(v,(char[40]){0}))<0){a->result.error=true;return false;}
    if(a->filters && !a->w->mask64[(unsigned)(v%64)])return true;
    if(!bump(&a->result.pass64,a))return false;
    if(a->filters && !a->w->mask63[(unsigned)(v%63)])return true;
    if(!bump(&a->result.roots,a))return false;
    uint64_t k=member(a->w->n,v);
    if(k && a->emit && fprintf(a->emit,"H %" PRIu64 " %s\n",k,dec(v,(char[40]){0}))<0){a->result.error=true;return false;}
    if(k && (!a->result.best||k<a->result.best)) {
        a->result.best=k;memcpy(a->result.p,a->p,sizeof a->p);memcpy(a->result.e,a->e,sizeof a->e);
    }
    return true;
}
static size_t prime_index(const Window *w,uint32_t p) {
    size_t lo=0,hi=w->primes.count;
    while(lo<hi){size_t mid=lo+(hi-lo)/2;if(w->primes.p[mid]<p)lo=mid+1;else hi=mid;}
    return lo;
}
/* Resume uses lexical (prime index,exponent) order, never numeric product order.
 * The stored leaf is fully processed; skip it once, then visit later branches. */
static bool dfs(Worker *a,u128 m,size_t i,unsigned depth) {
    if(!bump(&a->result.nodes,a)||!pulse(a))return false;
    unsigned r=a->w->n-depth;bool matching=a->resume;
    size_t first=matching?prime_index(a->w,a->resume_p[depth]):i;
    if(matching&&(first<i||first>=a->w->primes.count||a->w->primes.p[first]!=a->resume_p[depth])){a->result.error=true;return false;}
    for(size_t j=first;j<a->w->primes.count;j++) {
        if(!tail(a->w,m,j,r))break;
        uint32_t q=a->w->primes.p[j];u128 v=m;
        unsigned begin=matching&&j==first?a->resume_e[depth]:1;
        if(!begin){a->result.error=true;return false;}
        for(unsigned e=1;e<begin;e++){if(v>a->w->high/q){a->result.error=true;return false;}v*=q;}
        for(unsigned e=begin;v<=a->w->high/q;e++) {
            v*=q;if(r>1&&!tail(a->w,v,j+1,r-1))break;
            a->p[depth]=q;a->e[depth]=e;
            if(r==1) {
                if(a->resume){a->resume=false;continue;}
                if(!leaf(a,v))return false;
                memcpy(a->result.cursor_p,a->p,sizeof a->p);memcpy(a->result.cursor_e,a->e,sizeof a->e);
                a->result.cursor_valid=true;
            } else if(!dfs(a,v,j+1,depth+1))return false;
        }
    }
    return true;
}
static Result calculate(const Window *w,size_t id,uint64_t deadline) {
    Worker a;memset(&a,0,sizeof a);a.w=w;a.id=id;a.budget_deadline=deadline;a.filters=true;
    const Unit *u=&w->units[id];const Saved *old=&u->saved;
    memcpy(a.p,u->p,sizeof u->p);memcpy(a.e,u->e,sizeof u->e);
    a.result.nodes=old->nodes;a.result.leaves=old->leaves;a.result.pass64=old->pass64;a.result.roots=old->roots;
    a.resume=old->cursor_valid;a.result.cursor_valid=old->cursor_valid;
    memcpy(a.resume_p,old->cursor_p,sizeof a.resume_p);memcpy(a.resume_e,old->cursor_e,sizeof a.resume_e);
    memcpy(a.result.cursor_p,old->cursor_p,sizeof a.result.cursor_p);memcpy(a.result.cursor_e,old->cursor_e,sizeof a.result.cursor_e);
    uint64_t start=ns_now();a.deadline=deadline;
    if(deadline>start&&deadline-start>UNIT_SLICE_NS)a.deadline=start+UNIT_SLICE_NS;
    a.result.done=dfs(&a,u->product,u->next,u->depth);a.result.elapsed_ns=ns_now()-start;
    if(a.result.done&&a.resume){a.result.error=true;a.result.done=false;}
    return a.result;
}

/* A campaign is a private locked directory; all names below are fixed. */
typedef struct {
    int dir;char cfg_hash[65],chain[65],seed[65];off_t valid_end;bool torn,sealed;
    bool base,allow_previous_cache,hit_added,cache_current,closed_hash_valid;
    char previous_head[65],base_semantic[65],history_hash[65],closed_hash[65];
    Window w;unsigned windows,rows,done,allocated;u128 segments,elapsed_ns,checkpoints,generation;
    uint64_t max_quantum_ns;size_t best_id;unsigned char seen[MAX_UNITS];
    unsigned depth;uint64_t start_k;
    u128 nodes,leaves,pass64,roots;uint64_t best;char factors[512];
    char *state,*hits,*expected_hits;size_t hits_size;
    bool state_matched,hits_matched;
} Campaign;
static int open_regular(int dir,const char *name,int flags) {
    int fd=openat(dir,name,flags|O_CLOEXEC|O_NOFOLLOW,0600);
    if(fd<0)die("open %s: %s",name,strerror(errno));
    struct stat st;if(fstat(fd,&st)||!S_ISREG(st.st_mode))die("not regular: %s",name);return fd;
}
static void close_checked(int fd) {if(close(fd))die("close: %s",strerror(errno));}
static void sync_dir(int dir) {if(fsync(dir))die("directory fsync: %s",strerror(errno));}
static void write_all(int fd,const void *raw,size_t n) {
    const char *s=raw;while(n) {ssize_t k=write(fd,s,n);if(k<0&&errno==EINTR)continue;if(k<=0)die("write: %s",strerror(errno));s+=k;n-=(size_t)k;}
}
static void file_new(int dir,const char *name,const char *s) {
    int fd=open_regular(dir,name,O_WRONLY|O_CREAT|O_EXCL);write_all(fd,s,strlen(s));
    if(fsync(fd))die("fsync %s",name);
    close_checked(fd);sync_dir(dir);
}
static void file_atomic(int dir,const char *name,const char *s) {
    char tmp[32];int z=snprintf(tmp,sizeof tmp,"%s.tmp",name);require(z>0&&(size_t)z<sizeof tmp,"temporary name");
    /* Only reserved internal temporary entries may be discarded after a crash. */
    if(unlinkat(dir,tmp,0)&&errno!=ENOENT)die("remove incomplete snapshot %s",tmp);
    int fd=open_regular(dir,tmp,O_WRONLY|O_CREAT|O_EXCL);write_all(fd,s,strlen(s));
    if(fsync(fd))die("fsync %s",tmp);
    close_checked(fd);
    if(renameat(dir,tmp,dir,name))die("rename %s",name);
    sync_dir(dir);
}
static char *read_file(int dir,const char *name,size_t limit) {
    int fd=open_regular(dir,name,O_RDONLY);struct stat st;
    if(fstat(fd,&st)||st.st_size<0||(uint64_t)st.st_size>limit)die("file size quota: %s",name);
    size_t n=(size_t)st.st_size;char *s=malloc(n+1);require(s!=NULL,"read allocation");size_t used=0;
    while(used<n) {ssize_t k=read(fd,s+used,n-used);if(k<0&&errno==EINTR)continue;if(k<=0)die("short read %s",name);used+=(size_t)k;}
    char extra;if(read(fd,&extra,1)!=0)die("file changed during read %s",name);close_checked(fd);
    if(memchr(s,0,n))die("NUL in %s",name);
    s[n]=0;return s;
}
static bool exists(int dir,const char *name) {struct stat st;if(fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW)==0)return true;if(errno!=ENOENT)die("stat %s",name);return false;}
static void inventory(int dir) {
    const char *names[]={"cfg.json","cover.tsv","cover.tmp","state.json","hits.tsv","env.txt","sha.txt","run.tgz","state.json.tmp","hits.tsv.tmp","sha.txt.tmp","run.tmp"};
    int fd=openat(dir,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);require(fd>=0,"inventory open");
    DIR *dp=fdopendir(fd);require(dp!=NULL,"inventory stream");struct dirent *entry;
    errno=0;
    while((entry=readdir(dp))) {
        if(strcmp(entry->d_name,".")==0||strcmp(entry->d_name,"..")==0)continue;
        bool known=false;for(size_t i=0;i<sizeof names/sizeof *names;i++)if(strcmp(entry->d_name,names[i])==0)known=true;
        require(known,"unexpected campaign directory entry");struct stat st;
        require(fstatat(dir,entry->d_name,&st,AT_SYMLINK_NOFOLLOW)==0&&S_ISREG(st.st_mode),"nonregular campaign entry");
        errno=0;
    }
    require(errno==0,"inventory read");if(closedir(dp))die("inventory close");
}
static int directory(const char *name) {
    int d=open(name,O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);if(d<0)die("open run directory: %s",strerror(errno));
    if(flock(d,LOCK_EX|LOCK_NB))die("campaign is already locked");
    inventory(d);return d;
}
static void identities(char source[65],char makefile[65],char binary[65]) {
    char path[PATH_MAX];ssize_t z=readlink("/proc/self/exe",path,sizeof path-1);
    require(z>0&&(size_t)z<sizeof path-1,"executable location");path[z]=0;hash_path(path,binary);
    char *slash=strrchr(path,'/');require(slash!=NULL,"executable directory");slash[1]=0;
    size_t used=strlen(path);require(used+12<sizeof path,"source path too long");
    memcpy(path+used,"a358321.c",10);hash_path(path,source);
    memcpy(path+used,"Makefile",9);hash_path(path,makefile);
}
static void valid_initial(unsigned n,uint64_t k,uint64_t start_k,unsigned depth) {
    valid_target(n,k);require(start_k<k,"START_K must be smaller than K");
    require(depth>=3&&depth<n,"prefix depth outside3..n-1");
}
static void initial_config(unsigned n,uint64_t k,uint64_t start_k,unsigned depth,char out[512]) {
    valid_initial(n,k,start_k,depth);
    char src[65],mk[65],bin[65];identities(src,mk,bin);
    int z=snprintf(out,512,"{\"schema\":4,\"n\":%u,\"K\":\"%" PRIu64 "\",\"start_k\":\"%" PRIu64 "\",\"depth\":%u,\"slice_ns\":\"%" PRIu64 "\",\"source\":\"%s\",\"makefile\":\"%s\",\"binary\":\"%s\"}\n",n,k,start_k,depth,(uint64_t)UNIT_SLICE_NS,src,mk,bin);
    require(z>0&&z<512,"config formatting");
}
static void tuple_text(const uint32_t *p,const unsigned *e,unsigned n,char out[512]) {
    size_t used=0;out[0]=0;
    for(unsigned i=0;i<n;i++) {
        int z=snprintf(out+used,512-used,"%s%" PRIu32 "^%u",i?",":"",p[i],e[i]);
        require(z>0&&(size_t)z<512-used,"factor format overflow");used+=(size_t)z;
    }
    require(used<=144,"proved factor-text bound exceeded");
}
static void factors_text(const Result *r,unsigned n,char out[512]) {
    if(!r->best){strcpy(out,"-");return;}tuple_text(r->p,r->e,n,out);
}
static void unit_payload(size_t id,const Saved *v,unsigned n,char out[512]) {
    char a[40],b[40],d[40],e[40],cursor[512];int z;
    if(v->done)z=snprintf(out,512,"U\t%zu\t%s\t%s\t%s\t%s\t%" PRIu64,id,dec(v->nodes,a),dec(v->leaves,b),dec(v->pass64,d),dec(v->roots,e),v->elapsed_ns);
    else {
        require(v->cursor_valid,"checkpoint without cursor");tuple_text(v->cursor_p,v->cursor_e,n,cursor);
        z=snprintf(out,512,"P\t%zu\t%s\t%s\t%s\t%s\t%" PRIu64 "\t%s",id,dec(v->nodes,a),dec(v->leaves,b),dec(v->pass64,d),dec(v->roots,e),v->elapsed_ns,cursor);
    }
    require(z>0&&z<512&&(unsigned)z+66<=(v->done?256U:416U),"unit record bound");
}
static size_t split(char *s,char **fields,size_t max,char delimiter) {
    size_t n=0;for(;;) {require(n<max,"too many fields");fields[n++]=s;char *p=strchr(s,delimiter);if(!p)break;*p=0;s=p+1;}return n;
}
static u128 decode_tuple(const Window *w,size_t id,const char *text,u128 upper,uint32_t p_out[MAX_N],unsigned e_out[MAX_N]) {
    char copy[512];require(strlen(text)<sizeof copy,"factor length");strcpy(copy,text);
    char *fields[MAX_N];require(split(copy,fields,MAX_N,',')==w->n,"factor cardinality");
    u128 product=1;uint32_t prev=0;
    for(unsigned i=0;i<w->n;i++) {
        char *a[2];require(split(fields[i],a,2,'^')==2,"factor syntax");
        uint32_t p=(uint32_t)number(a[0],UINT32_MAX);unsigned e=(unsigned)number(a[1],127);
        require(p>prev&&e>0,"factor ordering/exponent");prev=p;
        size_t at=prime_index(w,p);require(at<w->primes.count&&w->primes.p[at]==p,"non-prime or out-of-range factor");
        if(i<w->units[id].depth)require(p==w->units[id].p[i]&&e==w->units[id].e[i],"certificate prefix differs from unit");
        for(unsigned j=0;j<e;j++){require(product<=upper/p,"certificate overflow/product");product*=p;}
        p_out[i]=p;e_out[i]=e;
    }
    return product;
}
static void certificate(const Window *w,size_t id,uint64_t k,const char *text) {
    require(k>0&&k<=w->k,"hit outside horizon");u128 expected=polygon(w->n,k);require(expected>=w->low,"hit below window");
    uint32_t p[MAX_N]={0};unsigned e[MAX_N]={0};u128 product=decode_tuple(w,id,text,expected,p,e);
    require(product==expected&&member(w->n,product)==k,"invalid polygonal certificate");
}
static int cursor_compare(const Saved *a,const Saved *b,unsigned n) {
    for(unsigned i=0;i<n;i++) {
        if(a->cursor_p[i]!=b->cursor_p[i])return a->cursor_p[i]<b->cursor_p[i]?-1:1;
        if(a->cursor_e[i]!=b->cursor_e[i])return a->cursor_e[i]<b->cursor_e[i]?-1:1;
    }
    return 0;
}
static void validate_update(const Campaign *c,size_t id,const Saved *v) {
    require(id<c->w.count,"unit range");const Saved *old=&c->w.units[id].saved;
    require(!old->done,"unit already completed");
    require(v->leaves<=c->w.high&&v->roots<=v->pass64&&v->pass64<=v->leaves,"counter semantics");
    require(v->nodes>=old->nodes&&v->leaves>=old->leaves&&v->pass64>=old->pass64&&v->roots>=old->roots,"decreasing checkpoint counters");
    if(!v->done){require(v->cursor_valid&&v->leaves>old->leaves,"checkpoint without leaf progress");if(old->cursor_valid)require(cursor_compare(v,old,c->w.n)>0,"cursor did not advance");}
}
static void window_hash(const Campaign *c,char out[65]) {
    if(c->closed_hash_valid){if(out!=c->closed_hash)strcpy(out,c->closed_hash);return;}
    Sha sh=sha_init();char text[768],l[40],r[40];
    int z=snprintf(text,sizeof text,"W\t%u\t%" PRIu64 "\t%u\t%s\t%s\t%zu\n",c->w.n,c->w.k,c->depth,dec(c->w.low,l),dec(c->w.high,r),c->w.count);
    require(z>0&&(size_t)z<sizeof text,"semantic header");sha_feed(&sh,text,(size_t)z);
    for(size_t i=0;i<c->w.count;i++) {
        const Saved *v=&c->w.units[i].saved;
        if(v->done||v->cursor_valid)unit_payload(i,v,c->w.n,text);
        else {z=snprintf(text,sizeof text,"Z\t%zu",i);require(z>0&&(size_t)z<sizeof text,"semantic unit");}
        sha_feed(&sh,text,strlen(text));sha_feed(&sh,"\n",1);
    }
    if(c->best){z=snprintf(text,sizeof text,"H\t%zu\t%" PRIu64 "\t%s",c->best_id,c->best,c->factors);require(z>0&&(size_t)z<sizeof text,"semantic minimum");}
    else strcpy(text,"NO_H");
    sha_feed(&sh,text,strlen(text));sha_end(sh,out);
}
static void semantic_hash(const Campaign *c,char out[65]) {
    char wh[65],meta[256],a[40],b[40],d[40];window_hash(c,wh);
    Sha sh=sha_init();sha_feed(&sh,c->cfg_hash,64);sha_feed(&sh,c->history_hash,64);sha_feed(&sh,wh,64);
    int z=snprintf(meta,sizeof meta,"%u\t%u\t%u\t%s\t%s\t%s\t%" PRIu64,c->windows,c->allocated,c->rows,dec(c->segments,a),dec(c->elapsed_ns,b),dec(c->checkpoints,d),c->max_quantum_ns);
    require(z>0&&(size_t)z<sizeof meta,"semantic metadata");sha_feed(&sh,meta,(size_t)z);sha_end(sh,out);
}
static void snapshot_text(const Campaign *c,char out[1024]) {
    char l[40],r[40],a[40],b[40],d[40],e[40],elapsed[40],segments[40],checkpoints[40],generation[40],owner[32];
    if(c->best)(void)snprintf(owner,sizeof owner,"%zu",c->best_id);else strcpy(owner,"null");
    int z=snprintf(out,1024,"{\"schema\":4,\"head\":\"%s\",\"generation\":\"%s\",\"windows\":%u,\"n\":%u,\"K\":\"%" PRIu64 "\",\"depth\":%u,\"initial_start_k\":\"%" PRIu64 "\",\"low\":\"%s\",\"high\":\"%s\",\"completed\":%u,\"total\":%zu,\"allocated\":%u,\"nodes\":\"%s\",\"leaves\":\"%s\",\"pass64\":\"%s\",\"roots\":\"%s\",\"candidate\":%" PRIu64 ",\"best_owner\":%s,\"segments\":\"%s\",\"elapsed_ns\":\"%s\",\"checkpoints\":\"%s\",\"max_quantum_ns\":\"%" PRIu64 "\",\"complete\":%s}\n",c->chain,dec(c->generation,generation),c->windows,c->w.n,c->w.k,c->depth,c->start_k,dec(c->w.low,l),dec(c->w.high,r),c->done,c->w.count,c->allocated,dec(c->nodes,a),dec(c->leaves,b),dec(c->pass64,d),dec(c->roots,e),c->best,owner,dec(c->segments,segments),dec(c->elapsed_ns,elapsed),dec(c->checkpoints,checkpoints),c->max_quantum_ns,c->done==c->w.count?"true":"false");
    require(z>0&&z<1024,"snapshot formatting");
}
static void snapshots_match(Campaign *c) {
    char state[1024];snapshot_text(c,state);if(c->state&&strcmp(c->state,state)==0)c->state_matched=true;
    if(c->allow_previous_cache) {
        char head[65];strcpy(head,c->chain);strcpy(c->chain,c->previous_head);--c->generation;
        snapshot_text(c,state);if(c->state&&strcmp(c->state,state)==0)c->state_matched=true;
        ++c->generation;strcpy(c->chain,head);c->allow_previous_cache=false;
    }
    if(c->hits&&strcmp(c->hits,c->expected_hits)==0)c->hits_matched=true;
}
static void append_hit(Campaign *c) {
    if(c->done!=c->w.count||c->hit_added)return;
    char v[40],row[700];int z;
    if(c->best)z=snprintf(row,sizeof row,"%u\t%" PRIu64 "\t%s\t%s\n",c->w.n,c->best,dec(polygon(c->w.n,c->best),v),c->factors);
    else z=snprintf(row,sizeof row,"%u\t0\t0\t-\n",c->w.n);
    require(z>0&&(size_t)z<sizeof row,"hit row formatting");require(c->hits_size+(size_t)z<1000000,"hit quota");
    memcpy(c->expected_hits+c->hits_size,row,(size_t)z+1);c->hits_size+=(size_t)z;c->hit_added=true;
}
static void start_window(Campaign *c,unsigned n,uint64_t k,size_t declared_count) {
    require(c->windows<MAX_WINDOWS,"window quota");u128 low=primorial(n);
    if(!c->windows&&c->start_k)low=polygon(n,c->start_k)+1;
    if(c->windows) {
        require(c->done==c->w.count,"preceding window incomplete");if(c->base)append_hit(c);
        if(n==c->w.n){require(c->best==0&&k>c->w.k,"same-n extension requires closed empty window and larger K");low=c->w.high+1;}
        else require(n==c->w.n+1&&c->best>0,"next n requires closed positive predecessor");
        char wh[65];window_hash(c,wh);chain_hash(c->history_hash,wh,c->history_hash);window_free(&c->w);
    }
    window_make_depth(&c->w,n,k,low,c->depth);require(c->w.count==declared_count,"prefix count mismatch");
    require(c->w.count<=MAX_UNITS-c->allocated,"cumulative prefix quota");c->allocated+=(unsigned)c->w.count;
    ++c->windows;c->done=0;c->best=0;c->best_id=SIZE_MAX;c->factors[0]=0;c->hit_added=false;c->closed_hash_valid=false;
    c->nodes=0;c->leaves=0;c->pass64=0;c->roots=0;memset(c->seen,0,sizeof c->seen);
    if(!c->base&&!c->w.count)append_hit(c);
}
static bool hex_digest(const char *s) {
    if(strlen(s)!=64)return false;
    for(unsigned i=0;i<64;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return false;
    return true;
}
static void apply_payload(Campaign *c,char *s) {
    char *f[12];size_t n=split(s,f,12,'\t');
    if(strcmp(f[0],"B")==0) {
        require(n==8&&!c->windows&&!c->base&&!c->generation,"base header context");
        c->generation=number(f[1],UMAX);require(c->generation>0&&hex_digest(f[2])&&hex_digest(f[7]),"base generation/digest");
        strcpy(c->previous_head,f[2]);c->segments=number(f[3],UMAX);c->elapsed_ns=number(f[4],UMAX);c->checkpoints=number(f[5],UMAX);
        c->max_quantum_ns=(uint64_t)number(f[6],UINT64_MAX);strcpy(c->base_semantic,f[7]);c->base=true;
    } else if(strcmp(f[0],"E")==0) {
        require(n==1&&c->base&&c->windows>0,"base end context");append_hit(c);c->base=false;
        char semantic[65];semantic_hash(c,semantic);require(strcmp(semantic,c->base_semantic)==0,"base semantic checksum");c->allow_previous_cache=true;
    } else if(strcmp(f[0],"W")==0) {
        require(n==4,"window record fields");unsigned term=(unsigned)number(f[1],MAX_N);
        require(term>=13,"unsupported window n");uint64_t k=(uint64_t)number(f[2],UINT64_MAX);
        start_window(c,term,k,(size_t)number(f[3],MAX_UNITS));
    } else if(strcmp(f[0],"U")==0||strcmp(f[0],"P")==0) {
        bool done=strcmp(f[0],"U")==0;require(n==(done?7U:8U)&&c->windows>0,"unit/checkpoint fields/context");
        size_t id=(size_t)number(f[1],MAX_UNITS);require(id<c->w.count,"unit range");Saved v;memset(&v,0,sizeof v);
        v.nodes=number(f[2],UMAX);v.leaves=number(f[3],UMAX);v.pass64=number(f[4],UMAX);v.roots=number(f[5],UMAX);v.elapsed_ns=(uint64_t)number(f[6],UINT64_MAX);v.done=done;
        if(!done){(void)decode_tuple(&c->w,id,f[7],c->w.high,v.cursor_p,v.cursor_e);v.cursor_valid=true;}
        validate_update(c,id,&v);Saved *old=&c->w.units[id].saved;
        if(c->base)require(!old->cursor_valid,"duplicate base checkpoint");
        add(&c->nodes,v.nodes-old->nodes);add(&c->leaves,v.leaves-old->leaves);add(&c->pass64,v.pass64-old->pass64);add(&c->roots,v.roots-old->roots);*old=v;
        if(v.elapsed_ns>c->max_quantum_ns)c->max_quantum_ns=v.elapsed_ns;
        if(done){require(c->rows<MAX_UNITS,"unit row quota");c->seen[id]=1;++c->done;++c->rows;if(!c->base)append_hit(c);}
        else if(!c->base)add(&c->checkpoints,1);
    } else if(strcmp(f[0],"H")==0) {
        require(n==4&&c->windows>0&&!c->hit_added,"minimum record fields/context");size_t id=(size_t)number(f[1],MAX_UNITS);
        require(id<c->w.count&&(c->base||!c->w.units[id].saved.done),"minimum owner context");
        uint64_t best=(uint64_t)number(f[2],UINT64_MAX);require(best>0&&(!c->best||(!c->base&&best<c->best)),"minimum must improve");
        certificate(&c->w,id,best,f[3]);c->best=best;c->best_id=id;strcpy(c->factors,f[3]);
    } else if(strcmp(f[0],"S")==0) {
        require(n==5&&c->windows>0&&!c->base,"segment record/context");unsigned threads=(unsigned)number(f[1],16);require(threads>0,"segment workers");
        uint64_t elapsed=(uint64_t)number(f[2],UINT64_MAX),maximum=(uint64_t)number(f[4],UINT64_MAX);
        require(strcmp(f[3],"COMPLETE")==0||strcmp(f[3],"BUDGET")==0||strcmp(f[3],"INTERRUPTED")==0,"segment reason");
        require((strcmp(f[3],"COMPLETE")==0)==(c->done==c->w.count),"segment completion semantics");
        require(maximum>=c->max_quantum_ns,"decreasing quantum maximum");c->max_quantum_ns=maximum;add(&c->segments,1);add(&c->elapsed_ns,elapsed);
    } else die("unknown journal record");
}
static void save_snapshots(Campaign *c) {
    char state[1024];snapshot_text(c,state);file_atomic(c->dir,"state.json",state);file_atomic(c->dir,"hits.tsv",c->expected_hits);c->cache_current=true;
}
static void append_record(Campaign *c,const char *payload) {
    require(!c->base,"cannot append inside base");
    require(strlen(payload)<LINE_MAXIMUM-67,"journal payload too long");
    char next[65],line[LINE_MAXIMUM];chain_hash(c->chain,payload,next);
    int z=snprintf(line,sizeof line,"%s\t%s\n",payload,next);require(z>0&&(size_t)z<sizeof line,"journal formatting");
    require((uint64_t)c->valid_end+(unsigned)z<=JOURNAL_MAX,"journal byte quota");
    int fd=open_regular(c->dir,"cover.tsv",O_WRONLY|O_APPEND);struct stat st;
    require(fstat(fd,&st)==0&&st.st_size==c->valid_end,"journal size changed");
    write_all(fd,line,(size_t)z);if(fsync(fd))die("journal fsync");close_checked(fd);c->valid_end+=z;
    char copy[LINE_MAXIMUM];strcpy(copy,payload);apply_payload(c,copy);strcpy(c->chain,next);c->cache_current=false;
}
static bool commit_result(Campaign *c,size_t id,const Result *r) {
    require(id<c->w.count&&!r->error,"worker result failure/range");const Saved *old=&c->w.units[id].saved;
    if(!r->done&&r->leaves==old->leaves)return false;
    Saved v;memset(&v,0,sizeof v);v.nodes=r->nodes;v.leaves=r->leaves;v.pass64=r->pass64;v.roots=r->roots;v.elapsed_ns=r->elapsed_ns;v.done=r->done;
    if(!v.done){v.cursor_valid=r->cursor_valid;memcpy(v.cursor_p,r->cursor_p,sizeof v.cursor_p);memcpy(v.cursor_e,r->cursor_e,sizeof v.cursor_e);}
    validate_update(c,id,&v);
    require(c->nodes<=UMAX-(v.nodes-old->nodes)&&c->leaves<=UMAX-(v.leaves-old->leaves)&&c->pass64<=UMAX-(v.pass64-old->pass64)&&c->roots<=UMAX-(v.roots-old->roots),"aggregate counter overflow before commit");
    require(v.done||c->checkpoints<UMAX,"checkpoint count overflow before commit");
    if(r->best&&(!c->best||r->best<c->best)) {
        char factors[512],hit[512];factors_text(r,c->w.n,factors);certificate(&c->w,id,r->best,factors);
        int z=snprintf(hit,sizeof hit,"H\t%zu\t%" PRIu64 "\t%s",id,r->best,factors);require(z>0&&(unsigned)z+66<=256,"minimum record bound");append_record(c,hit);
    }
    char payload[512];unit_payload(id,&v,c->w.n,payload);append_record(c,payload);return true;
}
static void verify_seal(Campaign *c) {
    if(!exists(c->dir,"sha.txt")) {require(!exists(c->dir,"run.tgz"),"archive without checksum manifest");return;}
    char *s=read_file(c->dir,"sha.txt",1024);const char *names[]={"cfg.json","cover.tsv","state.json","hits.tsv","env.txt"};
    char expected[512]="";size_t used=0;
    for(unsigned i=0;i<5;i++) {
        char h[65];int fd=open_regular(c->dir,names[i],O_RDONLY);hash_fd(fd,h);close_checked(fd);
        int z=snprintf(expected+used,sizeof expected-used,"%s  %s\n",h,names[i]);require(z>0&&(size_t)z<sizeof expected-used,"checksum formatting");used+=(size_t)z;
    }
    require(strcmp(s,expected)==0,"sealed checksum mismatch");free(s);c->sealed=true;
}
static Campaign *load_journal(const char *path,bool repair,const char *journal,int inherited_dir) {
    Campaign *c=calloc(1,sizeof *c);require(c!=NULL,"campaign allocation");c->dir=inherited_dir>=0?dup(inherited_dir):directory(path);require(c->dir>=0,"inherited directory fd");hash_text("",c->history_hash);
    char *cfg=read_file(c->dir,"cfg.json",512);
    const char *prefix="{\"schema\":4,\"n\":";
    require(strncmp(cfg,prefix,strlen(prefix))==0,"config syntax");
    char config_copy[512];strcpy(config_copy,cfg+strlen(prefix));char *comma=strchr(config_copy,',');
    require(comma!=NULL,"config n delimiter");*comma++=0;
    unsigned n=(unsigned)number(config_copy,MAX_N);
    require(strncmp(comma,"\"K\":\"",5)==0,"config K syntax");char *ks=comma+5,*end=strchr(ks,'"');
    require(end!=NULL,"config K delimiter");*end=0;uint64_t k=(uint64_t)number(ks,UINT64_MAX);
    comma=end+1;const char *start_field=",\"start_k\":\"";
    require(strncmp(comma,start_field,strlen(start_field))==0,"config START_K syntax");
    char *ss=comma+strlen(start_field);end=strchr(ss,'\"');require(end!=NULL,"config START_K delimiter");
    *end=0;c->start_k=(uint64_t)number(ss,UINT64_MAX);comma=end+1;
    const char *depth_field=",\"depth\":";require(strncmp(comma,depth_field,strlen(depth_field))==0,"config depth syntax");
    char *ds=comma+strlen(depth_field);end=strchr(ds,',');require(end!=NULL,"config depth delimiter");
    *end=0;c->depth=(unsigned)number(ds,MAX_N);
    char expected[512];initial_config(n,k,c->start_k,c->depth,expected);require(strcmp(cfg,expected)==0,"foreign build or noncanonical config");
    hash_text(cfg,c->cfg_hash);free(cfg);
    char *env=read_file(c->dir,"env.txt",64000);Sha seed=sha_init();sha_feed(&seed,c->cfg_hash,64);sha_feed(&seed,env,strlen(env));sha_end(seed,c->chain);strcpy(c->seed,c->chain);free(env);
    c->state=read_file(c->dir,"state.json",1024);c->hits=read_file(c->dir,"hits.tsv",1000000);
    c->expected_hits=calloc(1000000,1);require(c->expected_hits!=NULL,"hit allocation");strcpy(c->expected_hits,"n\tk\tv\tfactors\n");c->hits_size=strlen(c->expected_hits);c->hits_matched=strcmp(c->hits,c->expected_hits)==0;
    int fd=open_regular(c->dir,journal,O_RDONLY);struct stat st;require(fstat(fd,&st)==0&&st.st_size>=0&&(uint64_t)st.st_size<=JOURNAL_MAX,"journal size quota");
    FILE *fp=fdopen(fd,"r");require(fp!=NULL,"journal stream");char line[LINE_MAXIMUM];
    while(fgets(line,sizeof line,fp)) {
        size_t len=strlen(line);if(!len||line[len-1]!='\n') {
            require(feof(fp),"overlong or malformed journal tail");c->torn=true;break;
        }
        require(!memchr(line,'\r',len),"CR in journal");line[len-1]=0;char *last=strrchr(line,'\t');require(last!=NULL,"journal hash field");*last++=0;
        char next[65];chain_hash(c->chain,line,next);require(strcmp(last,next)==0,"journal chain mismatch");
        char copy[LINE_MAXIMUM];strcpy(copy,line);apply_payload(c,copy);strcpy(c->chain,next);c->valid_end+=(off_t)len;snapshots_match(c);
    }
    require(!ferror(fp),"journal read failed");if(fclose(fp))die("journal close");
    require(c->windows>0&&!c->base&&c->state_matched&&c->hits_matched,"snapshot is not a valid journal prefix/base");
    require(c->w.n>=n,"initial config/journal relation");
    fd=open_regular(c->dir,journal,O_RDONLY);fp=fdopen(fd,"r");require(fp!=NULL,"journal stream");
    do{require(fgets(line,sizeof line,fp)!=NULL,"missing initial window");}while(strncmp(line,"W\t",2)!=0);
    if(fclose(fp))die("journal close");
    char first[96];int z=snprintf(first,sizeof first,"W\t%u\t%" PRIu64 "\t",n,k);
    require(z>0&&strncmp(line,first,(size_t)z)==0,"initial window differs from config");
    char final_state[1024];snapshot_text(c,final_state);c->cache_current=strcmp(c->state,final_state)==0&&strcmp(c->hits,c->expected_hits)==0;
    verify_seal(c);if(c->sealed)require(c->cache_current,"sealed snapshot is stale");
    if(repair) {
        require(!c->sealed,"sealed campaign cannot be changed");
        if(c->torn){fd=open_regular(c->dir,"cover.tsv",O_WRONLY);if(ftruncate(fd,c->valid_end)||fsync(fd))die("truncate incomplete journal tail");close_checked(fd);c->torn=false;}
        save_snapshots(c);
    }
    return c;
}
static Campaign *load_campaign(const char *path,bool repair) {return load_journal(path,repair,"cover.tsv",-1);}
static void campaign_free(Campaign *c) {
    window_free(&c->w);free(c->state);free(c->hits);free(c->expected_hits);close_checked(c->dir);free(c);
}
/* A base is streamed; at validation only ONE prime/unit table remains live. */
static void base_record(int fd,char head[65],const char *payload,size_t *bytes) {
    char next[65],line[LINE_MAXIMUM];chain_hash(head,payload,next);
    int z=snprintf(line,sizeof line,"%s\t%s\n",payload,next);
    require(z>0&&(size_t)z<sizeof line&&*bytes+(size_t)z<=BASE_MAX,"compacted journal bound");
    write_all(fd,line,(size_t)z);*bytes+=(size_t)z;strcpy(head,next);
}
static void discard_compaction_temp(Campaign *c) {
    if(unlinkat(c->dir,"cover.tmp",0)&&errno!=ENOENT)die("remove incomplete compaction");
    sync_dir(c->dir);
}
static Campaign *compact_campaign(Campaign *c,const char *path) {
    require(!c->sealed&&!c->torn&&c->generation<UMAX,"compaction context/generation");
    save_snapshots(c);discard_compaction_temp(c);
    char semantic[65],hits_hash[65],old_head[65],head[65],payload[1024],g[40],a[40],b[40],d[40];
    semantic_hash(c,semantic);hash_text(c->expected_hits,hits_hash);strcpy(old_head,c->chain);strcpy(head,c->seed);
    u128 generation=c->generation+1;
    int z=snprintf(payload,sizeof payload,"B\t%s\t%s\t%s\t%s\t%s\t%" PRIu64 "\t%s",dec(generation,g),old_head,dec(c->segments,a),dec(c->elapsed_ns,b),dec(c->checkpoints,d),c->max_quantum_ns,semantic);
    require(z>0&&(size_t)z<sizeof payload,"base header formatting");
    int out=open_regular(c->dir,"cover.tmp",O_WRONLY|O_CREAT|O_EXCL);size_t bytes=0;base_record(out,head,payload,&bytes);
    int in=open_regular(c->dir,"cover.tsv",O_RDONLY);FILE *fp=fdopen(in,"r");require(fp!=NULL,"compaction input stream");
    char line[LINE_MAXIMUM],old_chain[65],last_hit[512]="";strcpy(old_chain,c->seed);unsigned window=0;off_t consumed=0;
    while(fgets(line,sizeof line,fp)) {
        size_t len=strlen(line);require(len>0&&line[len-1]=='\n',"compaction malformed input");consumed+=(off_t)len;line[len-1]=0;
        char *last=strrchr(line,'\t');require(last!=NULL,"compaction hash field");*last++=0;
        char next[65];chain_hash(old_chain,line,next);require(strcmp(next,last)==0,"compaction input chain");strcpy(old_chain,next);
        if(strncmp(line,"W\t",2)==0) {
            if(last_hit[0]){base_record(out,head,last_hit,&bytes);last_hit[0]=0;}
            ++window;if(window<c->windows)base_record(out,head,line,&bytes);
        } else if(window<c->windows&&strncmp(line,"U\t",2)==0)base_record(out,head,line,&bytes);
        else if(window<c->windows&&strncmp(line,"H\t",2)==0) {
            require(strlen(line)<sizeof last_hit,"compaction minimum bound");strcpy(last_hit,line);
        }
    }
    require(!ferror(fp)&&consumed==c->valid_end&&window==c->windows&&strcmp(old_chain,old_head)==0,"compaction input changed");
    if(fclose(fp))die("compaction input close");
    require(!last_hit[0],"compaction history minimum context");
    z=snprintf(payload,sizeof payload,"W\t%u\t%" PRIu64 "\t%zu",c->w.n,c->w.k,c->w.count);require(z>0&&(size_t)z<sizeof payload,"base window formatting");base_record(out,head,payload,&bytes);
    for(size_t i=0;i<c->w.count;i++)if(c->w.units[i].saved.done||c->w.units[i].saved.cursor_valid) {
        unit_payload(i,&c->w.units[i].saved,c->w.n,payload);base_record(out,head,payload,&bytes);
    }
    if(c->best) {
        z=snprintf(payload,sizeof payload,"H\t%zu\t%" PRIu64 "\t%s",c->best_id,c->best,c->factors);require(z>0&&(size_t)z<sizeof payload,"base minimum formatting");base_record(out,head,payload,&bytes);
    }
    base_record(out,head,"E",&bytes);if(fsync(out))die("compaction fsync");close_checked(out);
    int held=dup(c->dir);require(held>=0,"compaction lock handover");campaign_free(c);
    Campaign *checked=load_journal(path,false,"cover.tmp",held);close_checked(held);
    char actual[65];semantic_hash(checked,actual);require(strcmp(actual,semantic)==0&&checked->generation==generation&&strcmp(checked->previous_head,old_head)==0,"compaction changed semantic state");
    hash_text(checked->expected_hits,actual);require(strcmp(actual,hits_hash)==0&&!checked->torn&&checked->valid_end==(off_t)bytes,"compaction changed results/bytes");
    if(renameat(checked->dir,"cover.tmp",checked->dir,"cover.tsv"))die("compaction rename");
    sync_dir(checked->dir);save_snapshots(checked);return checked;
}
static Campaign *journal_room(Campaign *c,const char *path) {
    require(!c->sealed&&!c->torn,"journal room context");
    if((uint64_t)c->valid_end>=COMPACT_AT||(uint64_t)c->valid_end+COMMIT_RESERVE>JOURNAL_MAX)c=compact_campaign(c,path);
    require((uint64_t)c->valid_end+COMMIT_RESERVE<=JOURNAL_MAX,"insufficient journal room after compaction");return c;
}
static void print_status(const Campaign *c,const char *reason) {
    char a[40],b[40],v[40],p[40],g[40],seg[40];struct rusage ru;require(getrusage(RUSAGE_SELF,&ru)==0,"getrusage");
    printf("{\"n\":%u,\"K\":\"%" PRIu64 "\",\"completed\":%u,\"total\":%zu,\"defined\":%zu,\"allocated\":%u,\"nodes\":\"%s\",\"leaves\":\"%s\",\"candidate\":%" PRIu64 ",\"complete\":%s,\"torn_tail\":%s,\"sealed\":%s,\"snapshot_current\":%s,\"generation\":\"%s\",\"checkpoints\":\"%s\",\"segments\":\"%s\",\"journal_bytes\":%jd,\"max_quantum_ns\":\"%" PRIu64 "\",\"frontier\":\"%s\",\"reason\":\"%s\",\"cpu_seconds\":%.6f,\"rss_bytes\":%" PRIu64 "}\n",c->w.n,c->w.k,c->done,c->w.count,c->w.count,c->allocated,dec(c->nodes,a),dec(c->leaves,b),c->best,c->done==c->w.count?"true":"false",c->torn?"true":"false",c->sealed?"true":"false",c->cache_current?"true":"false",dec(c->generation,g),dec(c->checkpoints,p),dec(c->segments,seg),(intmax_t)c->valid_end,c->max_quantum_ns,c->done==c->w.count?dec(c->w.high,v):"PREVIOUS_CLOSED_WINDOW",reason,(double)ru.ru_utime.tv_sec+(double)ru.ru_utime.tv_usec/1e6+(double)ru.ru_stime.tv_sec+(double)ru.ru_stime.tv_usec/1e6,(uint64_t)ru.ru_maxrss*1024);
}
static void init_campaign(const char *path,unsigned n,uint64_t k,uint64_t start_k,unsigned depth) {
    valid_initial(n,k,start_k,depth);u128 low=start_k?polygon(n,start_k)+1:primorial(n);
    Window w;window_make_depth(&w,n,k,low,depth);size_t count=w.count;window_free(&w);
    if(mkdir(path,0700))die("init refuses existing/uncreatable directory: %s",strerror(errno));
    /* Make the new directory entry durable, including when its name is relative. */
    char parent[PATH_MAX];require(strlen(path)<sizeof parent,"directory path too long");strcpy(parent,path);
    size_t length=strlen(parent);while(length>1&&parent[length-1]=='/')parent[--length]=0;
    char *slash=strrchr(parent,'/');if(slash){if(slash==parent)slash[1]=0;else *slash=0;}else strcpy(parent,".");
    int pd=open(parent,O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(pd<0)die("parent directory");sync_dir(pd);close_checked(pd);
    Campaign *c=calloc(1,sizeof *c);require(c!=NULL,"campaign allocation");c->dir=directory(path);c->depth=depth;c->start_k=start_k;
    char cfg[512];initial_config(n,k,start_k,depth,cfg);file_new(c->dir,"cfg.json",cfg);hash_text(cfg,c->cfg_hash);
    struct utsname u;require(uname(&u)==0,"uname");char env[2048];
    int z=snprintf(env,sizeof env,"A358321\nauthor=Carlo Corti\ncompiler=%s\nflags=%s\nOpenMP=%d\nhost=%s\nsystem=%s %s %s\nprime_storage=uint32\narithmetic=unsigned128\n",__VERSION__,BUILD_FLAGS,_OPENMP,u.nodename,u.sysname,u.release,u.machine);
    require(z>0&&(size_t)z<sizeof env,"environment formatting");file_new(c->dir,"env.txt",env);
    Sha seed=sha_init();sha_feed(&seed,c->cfg_hash,64);sha_feed(&seed,env,strlen(env));sha_end(seed,c->chain);strcpy(c->seed,c->chain);hash_text("",c->history_hash);
    file_new(c->dir,"cover.tsv","");c->expected_hits=calloc(1000000,1);require(c->expected_hits!=NULL,"hit allocation");strcpy(c->expected_hits,"n\tk\tv\tfactors\n");c->hits_size=strlen(c->expected_hits);
    char payload[128];z=snprintf(payload,sizeof payload,"W\t%u\t%" PRIu64 "\t%zu",n,k,count);require(z>0&&(size_t)z<sizeof payload,"window formatting");
    append_record(c,payload);save_snapshots(c);print_status(c,"INITIALIZED");campaign_free(c);
}
static int run_next(const char *path,unsigned threads,unsigned seconds) {
    uint64_t start=ns_now(),deadline=start+(uint64_t)seconds*UINT64_C(1000000000);
    Campaign *c=load_campaign(path,false);
    if(c->sealed){require(c->done==c->w.count,"sealed incomplete campaign");print_status(c,"ALREADY_COMPLETE");campaign_free(c);return 0;}
    if(c->torn){int fd=open_regular(c->dir,"cover.tsv",O_WRONLY);if(ftruncate(fd,c->valid_end)||fsync(fd))die("truncate torn tail");close_checked(fd);c->torn=false;}
    discard_compaction_temp(c);save_snapshots(c);
    if(c->done==c->w.count){print_status(c,"ALREADY_COMPLETE");campaign_free(c);return 0;}
    require(c->segments<UMAX&&c->elapsed_ns<=UMAX-UINT64_MAX,"segment counters exhausted before work");
    atomic_store(&interrupted,0);
    struct sigaction sa;memset(&sa,0,sizeof sa);sa.sa_handler=on_signal;sigemptyset(&sa.sa_mask);
    if(sigaction(SIGINT,&sa,NULL)||sigaction(SIGTERM,&sa,NULL))die("sigaction");
    atomic_store(&heartbeat,start);atomic_store(&committed,c->done);atomic_store(&announced_best,c->best);
    invocation_start=start;prior_elapsed_ns=c->elapsed_ns;segment_number=c->segments+1;
    omp_set_dynamic(0);omp_set_num_threads((int)threads);
    fprintf(stderr,"start n=%u K=%" PRIu64 " completed=%u/%zu workers=%u budget=%u s frontier=PREVIOUS_CLOSED_WINDOW\n",c->w.n,c->w.k,c->done,c->w.count,threads,seconds);
    while(c->done<c->w.count&&!atomic_load(&interrupted)&&ns_now()<deadline) {
        c=journal_room(c,path);size_t ids[16];Result results[16];unsigned batch=0;
        for(size_t i=0;i<c->w.count&&batch<threads;i++)if(!c->seen[i])ids[batch++]=i;
        #pragma omp parallel for schedule(static,1) default(none) shared(c,ids,results,batch,deadline)
        for(unsigned j=0;j<batch;j++)results[j]=calculate(&c->w,ids[j],deadline);
        bool progress=false;
        for(unsigned j=0;j<batch;j++)if(commit_result(c,ids[j],&results[j]))progress=true;
        save_snapshots(c);atomic_store(&committed,c->done);atomic_store(&announced_best,c->best);
        if(!progress)break;
    }
    const char *reason=c->done==c->w.count?"COMPLETE":atomic_load(&interrupted)?"INTERRUPTED":"BUDGET";
    c=journal_room(c,path);uint64_t elapsed_ns=ns_now()-start;char segment[160];
    int z=snprintf(segment,sizeof segment,"S\t%u\t%" PRIu64 "\t%s\t%" PRIu64,threads,elapsed_ns,reason,c->max_quantum_ns);
    require(z>0&&(unsigned)z+66<=160,"segment formatting");append_record(c,segment);save_snapshots(c);
    fprintf(stderr,"close n=%u completed=%u/%zu candidate=%" PRIu64 " wall=%.6f s reason=%s frontier=%s\n",c->w.n,c->done,c->w.count,c->best,(double)elapsed_ns/1e9,reason,c->done==c->w.count?"WINDOW_CLOSED":"PREVIOUS_CLOSED_WINDOW");
    print_status(c,reason);int rc=c->done==c->w.count?0:2;campaign_free(c);return rc;
}
static void extend_campaign(const char *path,unsigned n,uint64_t k) {
    valid_target(n,k);Campaign *c=load_campaign(path,false);require(!c->sealed&&!c->torn,"extend requires clean unsealed campaign; next repairs a torn tail");
    require(c->done==c->w.count,"cannot extend incomplete window");
    require(c->segments<UMAX&&c->elapsed_ns<=UMAX-UINT64_MAX,"segment counters exhausted before extend");
    discard_compaction_temp(c);c=journal_room(c,path);
    u128 low=primorial(n);
    if(n==c->w.n){require(!c->best&&k>c->w.k,"same-n extension needs closed empty predecessor and greater K");low=c->w.high+1;}
    else require(n==c->w.n+1&&c->best>0,"next n needs closed positive predecessor");
    require(c->windows<MAX_WINDOWS,"window quota");
    /* Replay is validated; retain scalar predecessor metadata for W semantics,
       but release old tables before preflight to avoid two maximum vectors. */
    window_hash(c,c->closed_hash);c->closed_hash_valid=true;
    free(c->w.primes.p);c->w.primes.p=NULL;free(c->w.units);c->w.units=NULL;
    Window proposed;window_make_depth(&proposed,n,k,low,c->depth);
    require(proposed.count<=MAX_UNITS-c->allocated,"cumulative unit quota");size_t count=proposed.count;window_free(&proposed);
    char p[128];int z=snprintf(p,sizeof p,"W\t%u\t%" PRIu64 "\t%zu",n,k,count);require(z>0&&(size_t)z<sizeof p,"window formatting");
    append_record(c,p);save_snapshots(c);print_status(c,"EXTENDED");campaign_free(c);
}
static void tar_call(int dir,const char *archive,bool compare) {
    pid_t p=fork();if(p<0)die("fork tar");
    if(p==0) {
        if(fchdir(dir))_exit(125);
        struct rlimit quota={35000000,35000000};if(setrlimit(RLIMIT_FSIZE,&quota))_exit(125);
        int nullfd=open("/dev/null",O_RDONLY);if(nullfd<0||dup2(nullfd,STDIN_FILENO)<0)_exit(125);if(nullfd!=STDIN_FILENO)close(nullfd);
        execl("/usr/bin/tar","tar",compare?"-dzf":"-czf",archive,"--","cfg.json","cover.tsv","state.json","hits.tsv","env.txt","sha.txt",(char *)NULL);_exit(127);
    }
    int status;pid_t r;do{r=waitpid(p,&status,0);}while(r<0&&errno==EINTR);
    require(r==p&&WIFEXITED(status)&&WEXITSTATUS(status)==0,"archive create/compare failed");
}
static void seal_campaign(const char *path) {
    Campaign *c=load_campaign(path,false);require(!c->torn&&c->done==c->w.count,"seal requires clean completed window");
    if(c->sealed&&exists(c->dir,"run.tgz")){tar_call(c->dir,"run.tgz",true);print_status(c,"ALREADY_SEALED");campaign_free(c);return;}
    discard_compaction_temp(c);save_snapshots(c);const char *names[]={"cfg.json","cover.tsv","state.json","hits.tsv","env.txt"};char text[512]="";size_t used=0;
    for(unsigned i=0;i<5;i++) {
        int fd=open_regular(c->dir,names[i],O_RDONLY);char h[65];hash_fd(fd,h);close_checked(fd);
        int z=snprintf(text+used,sizeof text-used,"%s  %s\n",h,names[i]);require(z>0&&(size_t)z<sizeof text-used,"seal formatting");used+=(size_t)z;
    }
    if(!c->sealed)file_atomic(c->dir,"sha.txt",text);
    if(unlinkat(c->dir,"run.tmp",0)&&errno!=ENOENT)die("remove incomplete archive");
    int fd=open_regular(c->dir,"run.tmp",O_WRONLY|O_CREAT|O_EXCL);close_checked(fd);
    tar_call(c->dir,"run.tmp",false);fd=open_regular(c->dir,"run.tmp",O_RDONLY);if(fsync(fd))die("archive fsync");close_checked(fd);
    tar_call(c->dir,"run.tmp",true);require(!exists(c->dir,"run.tgz"),"archive exists");
    if(renameat(c->dir,"run.tmp",c->dir,"run.tgz"))die("archive rename");
    sync_dir(c->dir);c->sealed=true;print_status(c,"SEALED");campaign_free(c);
}
static void domains(void) {
    puts("n\tmaximum_value\tmaximum_index\tprime_cap");
    for(unsigned n=13;n<=MAX_N;n++){u128 u=ceiling(n);char b[40];printf("%u\t%s\t%" PRIu64 "\t%" PRIu32 "\n",n,dec(u,b),maximum_k(n),(uint32_t)(u/primorial(n-1)));}
}
static unsigned omega_small(unsigned v) {
    unsigned count=0;for(unsigned p=2;p<=v/p;p++)if(v%p==0){++count;do{v/=p;}while(v%p==0);}return count+(v>1);
}
static void selftest(void) {
    char h[65];hash_text("abc",h);require(strcmp(h,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")==0,"SHA known vector");
    Sha s=sha_init();char block[1000];memset(block,'a',sizeof block);for(unsigned i=0;i<1000;i++)sha_feed(&s,block,sizeof block);sha_end(s,h);
    require(strcmp(h,"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")==0,"SHA long vector");
    u128 x;require(!decimal("-1",UMAX,&x)&&!decimal("+1",UMAX,&x)&&!decimal("01",UMAX,&x)&&!decimal(" 1",UMAX,&x),"parser rejection");
    require(decimal("340282366920938463463374607431768211455",UMAX,&x)&&x==UMAX,"u128 maximum parser");
    require(!decimal("340282366920938463463374607431768211456",UMAX,&x),"u128 parser overflow");
    uint64_t samples[]={0,1,2,3,UINT32_MAX,UINT64_C(1)<<63,UINT64_MAX-1,UINT64_MAX};
    for(unsigned i=0;i<sizeof samples/sizeof *samples;i++) {
        uint64_t t=samples[i];u128 v=(u128)t*t;
        require(root(v)==t&&isqrt128(v)==t,"square root at square");if(v)require(root(v-1)==t-1&&isqrt128(v-1)==t-1,"root below square");
        if(t!=UINT64_MAX) {u128 next=(u128)(t+1)*(t+1);require(root(next-1)==t&&isqrt128(next-1)==t,"root below next square");}
    }
    require(root(UMAX)==UINT64_MAX&&isqrt128(UMAX)==UINT64_MAX,"maximum root");
    for(unsigned n=13;n<=MAX_N;n++) {
        uint64_t k=maximum_k(n);u128 u=ceiling(n);require(polygon(n,k)<=u&&polygon(n,k+1)>u,"maximum K inequality");
        require(member(n,polygon(n,k))==k&&member(n,polygon(n,k-1))==k-1,"maximum K inverse");
        char b[40];require(decimal(dec(u,b),UMAX,&x)&&x==u,"domain serialization");
        Window w;memset(&w,0,sizeof w);w.n=n;masks(&w);
        for(uint64_t j=1;j<=1000;j++){u128 v=polygon(n,j);require(w.mask64[(unsigned)(v%64)]&&w.mask63[(unsigned)(v%63)]&&member(n,v)==j,"necessary mask/polygon inverse");}
    }
    /* Small unrestricted leaf sets, all powers/gaps, versus direct factoring.
       The independent Python fixture additionally compares exact sets. */
    for(unsigned n=4;n<=6;n++) {
        Window w;memset(&w,0,sizeof w);w.n=n;w.low=1;w.high=10000;w.primes=primes_make((uint32_t)(w.high/primorial(n-1)));masks(&w);
        Worker a;memset(&a,0,sizeof a);a.w=&w;a.deadline=UINT64_MAX;a.filters=true;
        require(dfs(&a,1,0,0),"small DFS");unsigned count=0;uint64_t best=0;
        for(unsigned v=1;v<=10000;v++)if(omega_small(v)==n){++count;uint64_t k=member(n,v);if(k&&(!best||k<best))best=k;}
        require(a.result.leaves==count&&a.result.best==best,"small direct count/minimum");free(w.primes.p);
    }
    puts("SELFTEST PASS: SHA, parsing, full-width roots, domains, masks, powers, direct small counts/minima");
}
static void usage(void) {
    puts("A358321 — canonical exact prime-support enumeration\n"
         "  a358321 init DIRECTORY N K [START_K DEPTH] (N=13..24; no search)\n"
         "    defaults START_K=0, DEPTH=3; require START_K<K, 3<=DEPTH<N\n"
         "    DEPTH stays fixed; all long units checkpoint after about60 seconds\n"
         "    nonzero START_K searches (START_K,K]; earlier coverage is external\n"
         "  a358321 next DIRECTORY THREADS SECONDS (1..16, 1..3300)\n"
         "  a358321 extend DIRECTORY N K       (closed predecessor only)\n"
         "  a358321 status DIRECTORY\n"
         "  a358321 verify DIRECTORY\n"
         "  a358321 seal DIRECTORY             (freeze, checksum, verified archive)\n"
         "  a358321 domain\n"
         "  a358321 selftest\n"
         "Exit 0: requested action completed; 2: incomplete search; 1: error.\n"
         "Decimal tokens: canonical unsigned integers, no leading zero except 0.\n"
         "No official campaign is authorized by a successful test or this program.");
}
int main(int argc,char **argv) {
    if(argc==2&&strcmp(argv[1],"selftest")==0){selftest();return 0;}
    if(argc==2&&strcmp(argv[1],"domain")==0){domains();return 0;}
    if(argc==2&&strcmp(argv[1],"--help")==0){usage();return 0;}
    if((argc==5||argc==7)&&strcmp(argv[1],"init")==0) {
        unsigned n=(unsigned)number(argv[3],MAX_N);uint64_t k=(uint64_t)number(argv[4],UINT64_MAX);
        uint64_t start_k=argc==7?(uint64_t)number(argv[5],UINT64_MAX):0;
        unsigned depth=argc==7?(unsigned)number(argv[6],MAX_N):3;
        init_campaign(argv[2],n,k,start_k,depth);return 0;
    }
    if(argc==5&&strcmp(argv[1],"extend")==0) {
        unsigned n=(unsigned)number(argv[3],MAX_N);uint64_t k=(uint64_t)number(argv[4],UINT64_MAX);valid_target(n,k);
        extend_campaign(argv[2],n,k);return 0;
    }
    if(argc==5&&strcmp(argv[1],"next")==0) {
        unsigned t=(unsigned)number(argv[3],16),s=(unsigned)number(argv[4],3300);require(t>0&&s>0,"positive workers/seconds required");return run_next(argv[2],t,s);
    }
    if(argc==3&&strcmp(argv[1],"seal")==0){seal_campaign(argv[2]);return 0;}
    if(argc==3&&(strcmp(argv[1],"status")==0||strcmp(argv[1],"verify")==0)) {
        Campaign *c=load_campaign(argv[2],false);
        if(strcmp(argv[1],"verify")==0){require(!c->torn,"incomplete tail: next may repair");if(c->sealed){require(exists(c->dir,"run.tgz"),"missing archive");tar_call(c->dir,"run.tgz",true);}}
        print_status(c,"VERIFIED");campaign_free(c);return 0;
    }
    usage();return 1;
}
