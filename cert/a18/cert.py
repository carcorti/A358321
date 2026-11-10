#!/usr/bin/env python3
"""Carlo Corti: exact independent positive n18 certificate, no negative search.

Factor the two linear factors by trial division, compare their product with the polygonal value,
and compare with the supplied prime support. No producer or DFS is invoked.
"""
import argparse
import json
import math
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def factor_trial(value):
    if value < 1:
        raise ValueError('positive integer required')
    result = {}
    divisor = 2
    while divisor <= value // divisor:
        while value % divisor == 0:
            result[divisor] = result.get(divisor, 0) + 1
            value //= divisor
        divisor += 1 if divisor == 2 else 2
    if value > 1:
        result[value] = result.get(value, 0) + 1
    return result


def certify(k, value, pairs):
    if k < 1 or len(pairs) != 18 or len({p for p, e in pairs}) != 18:
        raise ValueError('wrong index/support cardinality')
    if any(p < 2 or e < 1 or e > 127 or factor_trial(p) != {p: 1} for p, e in pairs):
        raise ValueError('invalid prime/exponent')
    if [p for p, e in pairs] != sorted(p for p, e in pairs):
        raise ValueError('unordered support')
    a = factor_trial(k)
    b = factor_trial(8 * k - 7)
    combined = a.copy()
    for p, e in b.items():
        combined[p] = combined.get(p, 0) + e
    numerator = k * (16 * k - 14)
    if numerator % 2 or value != numerator // 2 or value != k * (8 * k - 7):
        raise ValueError('polygon mismatch')
    if value != math.prod(p ** e for p, e in pairs) or dict(pairs) != combined:
        raise ValueError('factor product/support mismatch')
    discriminant = 196 + 128 * value
    t = math.isqrt(discriminant)
    if t * t != discriminant or (t + 14) % 32 or (t + 14) // 32 != k:
        raise ValueError('exact inverse mismatch')
    return {'n': 18, 'k': k, 'value': str(value),
            'distinct_primes': len(combined), 'factor_k': a,
            'factor_8k_minus_7': b, 'factor_value': combined,
            'exact_root': str(t), 'exact_division_by_two': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    lines = (args.directory / 'hits.tsv').read_text().splitlines()
    if not lines or lines[0] != 'n\tk\tv\tfactors':
        raise ValueError('wrong hit-table framing')
    rows = [x.split('\t') for x in lines[1:]]
    rows = [x for x in rows if x[0] == '18' and x[1] != '0']
    if len(rows) != 1 or len(rows[0]) != 4:
        raise ValueError('expected one closed positive n18 row')
    n, k, value, text = rows[0]
    k, value = int(k), int(value)
    pairs = [tuple(map(int, x.split('^'))) for x in text.split(',')]
    result = certify(k, value, pairs)
    old_rows = [tuple(map(int, x.split())) for x in
                (ROOT / 'outputs/a18/b-prev.txt').read_text().splitlines() if x]
    if [n for n, index in old_rows] != list(range(3, 18)):
        raise ValueError('wrong admitted predecessor domain')
    provider = (ROOT / 'reference/a358862.seq').read_text()
    if '%O A358862 3,1' not in provider:
        raise ValueError('provider offset differs')
    data = ''.join(re.findall(r'^%[STU] A358862 (.+)$', provider, re.M))
    values = [int(x) for x in data.split(',') if x]
    if len(values) != 13:
        raise ValueError('provider domain differs')
    for (n, index), v in zip(old_rows[:13], values):
        if index * ((n - 2) * index - (n - 4)) // 2 != v:
            raise ValueError('known semantic mapping mismatch')
    local16 = json.loads((ROOT / 'outputs/a16/result.json').read_text())
    index16 = old_rows[-2][1]
    if old_rows[-2] != (16, local16['k']) or index16 * (7 * index16 - 6) != int(local16['P16']):
        raise ValueError('local n16 transform mismatch')
    previous = json.loads((ROOT / 'outputs/a17/result.json').read_text())
    if old_rows[-1] != (17, previous['k']):
        raise ValueError('local admitted n17 mismatch')
    index = old_rows[-1][1]
    if index * (15 * index - 13) // 2 != int(previous['P17']):
        raise ValueError('local n17 transform mismatch')
    bad_cases = [(k + 1, value, pairs), (k, value + 1, pairs),
                 (k, value, [(p, e + 1 if i == 0 else e)
                             for i, (p, e) in enumerate(pairs)]),
                 (k, value, [(4, e) if i == 0 else (p, e)
                             for i, (p, e) in enumerate(pairs)]),
                 (k, value, pairs[:-1])]
    rejected = 0
    for case in bad_cases:
        try:
            certify(*case)
        except ValueError:
            rejected += 1
        else:
            raise ValueError('negative control accepted')
    result.update(author='Carlo Corti', status='INDEPENDENT_POSITIVE_CERTIFICATE_PASS',
                  known_semantic_replay='all13 source rows n3..15 plus admitted local n16,n17',
                  negative_controls_rejected=rejected,
                  independent_negative_census=False,
                  scope='Positive exact certificate only; minimum also requires audited complete producer coverage.')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
