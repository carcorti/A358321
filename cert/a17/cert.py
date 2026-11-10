#!/usr/bin/env python3
"""Carlo Corti: exact independent positive n17 certificate, no negative search.

Factor the two linear factors by trial division, divide their product by two,
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
    if k < 1 or len(pairs) != 17 or len({p for p, e in pairs}) != 17:
        raise ValueError('wrong index/support cardinality')
    if any(p < 2 or e < 1 or e > 127 or factor_trial(p) != {p: 1} for p, e in pairs):
        raise ValueError('invalid prime/exponent')
    if [p for p, e in pairs] != sorted(p for p, e in pairs):
        raise ValueError('unordered support')
    a = factor_trial(k)
    b = factor_trial(15 * k - 13)
    combined = a.copy()
    for p, e in b.items():
        combined[p] = combined.get(p, 0) + e
    if combined.get(2, 0) < 1:
        raise ValueError('product not divisible by two')
    combined[2] -= 1
    if combined[2] == 0:
        del combined[2]
    numerator = k * (15 * k - 13)
    if numerator % 2 or value != numerator // 2:
        raise ValueError('polygon mismatch')
    if value != math.prod(p ** e for p, e in pairs) or dict(pairs) != combined:
        raise ValueError('factor product/support mismatch')
    discriminant = 169 + 120 * value
    t = math.isqrt(discriminant)
    if t * t != discriminant or (t + 13) % 30 or (t + 13) // 30 != k:
        raise ValueError('exact inverse mismatch')
    return {'n': 17, 'k': k, 'value': str(value),
            'distinct_primes': len(combined), 'factor_k': a,
            'factor_15k_minus_13': b, 'factor_value': combined,
            'exact_root': str(t), 'exact_division_by_two': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    lines = (args.directory / 'hits.tsv').read_text().splitlines()
    if not lines or lines[0] != 'n\tk\tv\tfactors':
        raise ValueError('wrong hit-table framing')
    rows = [x.split('\t') for x in lines[1:]]
    rows = [x for x in rows if x[0] == '17' and x[1] != '0']
    if len(rows) != 1 or len(rows[0]) != 4:
        raise ValueError('expected one closed positive n17 row')
    n, k, value, text = rows[0]
    k, value = int(k), int(value)
    pairs = [tuple(map(int, x.split('^'))) for x in text.split(',')]
    result = certify(k, value, pairs)
    old_rows = [tuple(map(int, x.split())) for x in
                (ROOT / 'outputs/a17/b-prev.txt').read_text().splitlines() if x]
    if [n for n, index in old_rows] != list(range(3, 17)):
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
    previous = json.loads((ROOT / 'outputs/a16/result.json').read_text())
    if old_rows[-1] != (16, previous['k']):
        raise ValueError('local admitted n16 mismatch')
    index = old_rows[-1][1]
    if index * (7 * index - 6) != int(previous['P16']):
        raise ValueError('local n16 transform mismatch')
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
                  known_semantic_replay='all13 source rows n3..15 plus admitted local n16',
                  negative_controls_rejected=rejected,
                  independent_negative_census=False,
                  scope='Positive exact certificate only; minimum also requires audited complete producer coverage.')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
