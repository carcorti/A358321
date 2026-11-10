# A358321: polygonal indices with a prescribed number of distinct prime factors

Carlo Corti — Independent researcher — carlo.corti@outlook.com

Release v1.0.1: publication metadata and manuscript/PDF finalization, prepared
10 November 2026. Scientific source, data, coverage and certificates are
unchanged from v1.0. GitHub and the initial Zenodo deposit are public; the
series DOI links their release history. This is not an OEIS edit.

For n >= 3 and k >= 1, let `P_n(k) = k*((n-2)*k-(n-4))/2` and let
`a(n) = min {k >= 1 : omega(P_n(k)) = n}`, when the set is nonempty.
Here omega counts DISTINCT prime factors; capital Omega counts multiplicity
and defines a different problem. The source baseline covers n=3..15.
The canonical `data/b358321.txt` has 17 consecutive `n a(n)` decimal rows,
n=3..19, no header, and exactly one empty final line (LF LF).

| n | Locally validated a(n) | Derived P_n(a(n)) |
|---:|---:|---:|
|16|119535945060|100021895128994153154840|
|17|1113316946280|9296059671549446483637180|
|18|4278672701330|146456320680822524361241890|
|19|153290693815740|199733312889341920908906236550|

The last column gives the same-index consequences for A358862 by strict
monotonicity and exact inversion, not a second autonomous enumeration. There
is no term20 or later indexed target term in this package. No canonical
OEIS a-file was produced in this project; no new attachment is inferred here.

## Evidence and its limits

The C producer enumerates increasing distinct prime bases and all positive
powers, with exact tail bounds, residue filters, exact polygonal inversion
and streaming minima. Daniel Suteu's published A358862 PARI method is the
constructive prior art; this is a fresh C implementation. See the monolithic
`paper/A358321.tex` for definitions, proofs, chronology and bibliography.

The computational minima are conditional on correct producer execution and
the recorded coverage. The earlier schema1 producer accounts for nine windows;
the later schema4 producer accounts for three. Native run2 remains 576/577
complete, with pending prefix 0; run3 remains 588/590, with pending prefixes
0 and 110. They are incomplete and unsealed. Exact valuation arguments for
p=3 or 5 exclude those entire unfinished subtrees: if p divides P_19(k),
then p squared divides it, so a fixed exponent-one prefix cannot match.
Only pending units add analytic coverage; overlapping whole-map classes are
not counted again as native completion. The lemma was applied after the
search, not used for early C subtree pruning.

The separate final index interval `(166539042068893,170000000000000]` has no
matching order19 index under those assumptions. The producer records minima,
not every hit: this does not prove the entire interval above a(19) empty.
The first unresolved index is20. Numerical C support n=13..24 is capacity,
not completed computation, operational feasibility or a search authorization.

Python trial-factor and separate PARI/GP certificates verify the four positive
witnesses, exact inverses and support sizes. The generic auditors verify
journal hashes/semantics, unit binding and joins. Exact-set diagnostics use
a distinct-factor-count sieve for small cases n=4..7 and separate C fixtures;
cursor, interruption, malformed-record and recovery checks have bounded scopes.
None constitutes a second independently implemented exhaustive negative search
for the new production ranges. Hashes prove file integrity, not mathematical
coverage or authentication of an artifact's owner.

## Payload

| Path | Purpose |
|---|---|
|src/a358321.c, src/Makefile|Unchanged scientific source and public build/test entry point.|
|src/readme.md|Short source-neighbor pointer to this guide and the original build identity.|
|data/b358321.txt|Latest canonical contiguous target data, byte-identical to the admitted table.|
|paper/A358321.tex, paper/A358321.pdf|Monolithic English manuscript and matching PDF; inline bibliography, no external scientific input files.|
|check/verify.py|Package-relative integrity, safe restoration and bounded verification driver.|
|check/check_*.py|Five unchanged original implementation validators; the driver restores their original layout before invoking them.|
|cert/a16..a19/|Unchanged Python and GP positive certificate programs.|
|cert/arith/, cert/limit/|Modular GP certificates and original exact prefix-map/control programs.|
|ref/|Three attributed OEIS entry exports, export timestamp and the original published-method replay GP inputs.|
|proof/run.tgz, proof/map.json|Losslessly compressed original records, metadata, outputs, historical producer/binaries and indispensable checker inputs, with a deduplicated restore index.|
|proof/build.diff|Exact publication-only Makefile test-routing change.|
|LICENSE, CITATION.cff, .gitignore, files.sha|Existing author license, release citation metadata and exact payload checksum inventory.|

Original record/proof/certificate paths are in `proof/map.json`, with role,
SHA256, byte count, permissions and either a public file or a compact archive
member. Archive members have short opaque names; these names do not change
record schemas or rewrite historical paths. Restoration reconstructs original
layouts only outside the publication payload. Identical original bytes are
stored once even when several historical paths need them. There are 112
restored paths, 79 compressed objects (1,633,157 object bytes), and 2,056,991
restored file bytes including shared public originals. The gzip archive is
608,069 bytes; its exact identity and sizes are also in the index.

Private manuscript/code-review conversations, old drafts, superseded candidates,
instrumented binaries, large synthetic development journals and redundant nested
admission archives are excluded. Original bounded-suite outputs, original source
and hardware context, source-method replay outputs and proof/admission inputs
are included. This is selected claim/dependency coverage, not a workspace dump.
Full third-party articles/manuals are linked in the paper rather than copied.

## Bounded verification

Run from the repository root, on a trusted local machine. Default mode requires
Python >=3.10, standard library only, without Python -O (the original scientific
validators use assertions). It verifies every payload file before execution,
rejects missing/changed/unexpected files, safely restores the indexed originals
to temporary storage, checks their hashes, reruns retained portable auditors,
positive certificates and exact arithmetic controls, and regenerates the b-file
from the historical source values plus admitted results for byte comparison.
No original campaign is resumed or modified.

```sh
python3 -I -B check/verify.py
```

Expected final line: `PACKAGE CHECK PASS; records/arithmetic, not independent exhaustive negative enumeration`.
The driver uses a new external temporary directory and deletes it on completion;
the frozen checkout remains unchanged. Add --verbose to display original command
outputs. Errors, missing optional dependencies and timeouts are failures, never
mathematical MISS results.

Full local bounded checks, including a fresh public build, the five original
diagnostic validators, six arithmetic GP inputs and two draftmode compilations:

```sh
python3 -I -B check/verify.py --build --pari --tex
```

This requires Linux x86-64, GCC13 (tested gcc-13 13.3.0), make, OpenMP, libm,
GNU tar/gzip, PARI/GP2.15.4 and TeX Live2023 with the packages named in the TeX.
The C arithmetic uses GCC/Clang unsigned __int128. The original local Python
version was3.12.3. Diagnostic helpers may compile C fixtures and create synthetic
or known-domain jobs only in scratch storage; they do not run the n16..19
campaign again. Their large transient quota/compaction fixtures are not stored
in this repository. Optional --cc selects the compiler for the public build.
GP mode requires empty stderr and byte-identical output to the six original
logs; a presentation difference on another GP version requires inspection.
The --tex check uses -draftmode and leaves the delivered PDF unchanged. The
release PDF was separately compiled and visually inspected. To rebuild it in a
new external directory (substitute any new path for the example):

```sh
mkdir /tmp/a358321-pdf
pdflatex -interaction=nonstopmode -halt-on-error -output-directory=/tmp/a358321-pdf paper/A358321.tex
pdflatex -interaction=nonstopmode -halt-on-error -output-directory=/tmp/a358321-pdf paper/A358321.tex
```

The rebuilt PDF is /tmp/a358321-pdf/A358321.pdf. Creation timestamps can change
its bytes; files.sha authenticates the delivered PDF. No TeX auxiliaries belong
in the payload, and .gitignore deliberately keeps PDF files eligible for tracking.

The build uses the original compile/link options unchanged. Only the public
Makefile test recipes route to the package driver, because the old private
layout is restored on demand. `proof/build.diff` records this change. The
original Makefile, both historical binaries and each cfg identity remain in
the archive; a fresh public build is never substituted for a historical binary.
To build directly, `make -C src test` uses the same bounded test route and its
explicit generated-binary exception; `make -C src clean` removes that binary
before running the default frozen-tree checker again. No other unexpected
checkout file is ignored. A root .git metadata DIRECTORY is the only clone
metadata exclusion; arbitrary dotfiles remain payload.

Native read-only verification of historical jobs is an explicit optional mode:

```sh
python3 -I -B check/verify.py --native
```

The frozen executables were built with -march=native on an AMD Ryzen9 7940HS
under Linux Mint22.3 (kernel6.17.0-42-generic); a different CPU may produce SIGILL.
That is an environment limitation. Use the default portable record audit rather
than rebuilding or rebinding an old job to a different executable. The final
production jobs used eight workers. The supplement's stored native search wall
time is about9900 seconds across three calls; it is not CPU time, booking time,
a whole-project benchmark or a runtime forecast.

For manual inspection or original-layout reproduction, choose a NEW external
directory (the command refuses an existing destination):

```sh
python3 -I -B check/verify.py --restore /tmp/a358321-proof
```

This stops after a hash-checked restore. For example the original same-method
Suteu replay can then be invoked as follows; it covers known n=3..15 only and
is not independent negative evidence for new terms:

```sh
gp -q -f -s 256M /tmp/a358321-proof/outputs/meta/prefix.gp
gp -q -f -s 256M /tmp/a358321-proof/outputs/meta/replay.gp
```

The recorded earlier replay elapsed about46 seconds for n13..15 on the local
machine; hardware-dependent timings in those logs are not acceptance values.
Output values are checked against the source pairs. Historical metadata may
refer to private preflight/admission paths or then-current endpoints; these
are historical fields, not new instructions or claims that all development
files are distributed. The restore index defines the selected dependency set.

## Source provenance, license and citation

The original MIT LICENSE supplied by Carlo Corti is preserved unchanged for
his software and associated original documentation. OEIS entry exports and
the reproduced Suteu PARI routine retain their separate CC-BY-SA-4.0 terms;
the MIT file does not relicense those materials. Credit the
[On-Line Encyclopedia of Integer Sequences](https://oeis.org/), OEIS Foundation
Inc., the original entry contributors and the original entry links:
[A358321](https://oeis.org/A358321), [A358862](https://oeis.org/A358862),
[A359014](https://oeis.org/A359014).
The [official OEIS export repository](https://github.com/oeis/oeisdata) and
[CC-BY-SA-4.0 license](https://creativecommons.org/licenses/by-sa/4.0/) describe
the source terms. Export text and the copied method are unchanged; the replay
drivers add fixed known-term invocations and timing/print commands.

Ilya Gutkovskiy submitted A358321/A359014 on12 December2022 and A358862
on3 December2022. A358862 credits Daniel Suteu's terms12..15 and PARI programs
of4 December2022, and Harvey P. Dale's first-eight-term Mathematica program
of9 September2023. The included entries have revisions67,17,7 dated
16 February2025. `ref/time.txt` records the9 November2026 export; entry text
was checked again on10 November and matched. Direct live b-file/editorial
history retrieval was unavailable in the documented environment. Therefore
this is a locally validated extension of the stated baseline, with no claim
of worldwide priority or present OEIS incorporation.

Use CITATION.cff for the software and preferred manuscript citation.
Repository: https://github.com/carcorti/A358321 . Zenodo series (concept) DOI:
https://doi.org/10.5281/zenodo.24103849 . The series DOI spans releases; consult
its version history for an immutable deposited version. The initial deposit
is v1.0; this package supplies the finalized manuscript/PDF and metadata for
v1.0.1. A DOI for that new individual deposit is not guessed in advance.

Local preflight and distribution-shape checks concern the prepared payload.
Actual provider downloads require separate checks after synchronization; one
provider's successful validation does not establish the other's contents.
