# A358321 source and build

Copyright (c) 2026 Carlo Corti. The canonical a358321.c is byte-identical to
the reviewed schema4 producer. See ../README.md and ../paper/A358321.tex
for the current scientific endpoint, proof, bounded commands and dependencies.

The public Makefile retains the original compiler/link options and changes
only test routing to ../check/verify.py. Its exact diff is ../proof/build.diff;
the original Makefile and executed binary are indexed in ../proof/map.json.
The driver restores original validator layouts in external temporary storage.
The original native jobs remain incomplete/unsealed with mixed mathematical
closure; building a fresh binary does not change their historical identity.
