#!/usr/bin/env python3
"""Carlo Corti: independent positive certificate and known-row semantic replay.

No producer executable, no prime-support generation, no negative census.
Factor k and 7*k-6 by elementary trial division for the n16 certificate.
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
    if k < 1 or len(pairs) != 16 or len({p for p, e in pairs}) != 16:
        raise ValueError('wrong index/support cardinality')
    if any(p < 2 or e < 1 or e > 127 or factor_trial(p) != {p: 1} for p, e in pairs):
        raise ValueError('invalid prime/exponent')
    if [p for p, e in pairs] != sorted(p for p, e in pairs):
        raise ValueError('unordered support')
    a = factor_trial(k)
    b = factor_trial(7 * k - 6)
    combined = a.copy()
    for p, e in b.items():
        combined[p] = combined.get(p, 0) + e
    product = math.prod(p ** e for p, e in pairs)
    generic = k * (14 * k - 12) // 2
    if value != k * (7 * k - 6) or value != generic or value != product or dict(pairs) != combined:
        raise ValueError('polynomial/factor product mismatch')
    d = 7 * value + 9
    t = math.isqrt(d)
    if t * t != d or (t + 3) % 7 or (t + 3) // 7 != k:
        raise ValueError('exact inverse mismatch')
    return {'n': 16, 'k': k, 'value': str(value), 'distinct_primes': len(combined),
            'factor_k': a, 'factor_7k_minus_6': b,
            'factor_value': dict(pairs), 'exact_reduced_root': str(t)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    lines = (args.directory / 'hits.tsv').read_text().splitlines()
    if not lines or lines[0] != 'n\tk\tv\tfactors':
        raise ValueError('wrong hit-table framing')
    rows = [x.split('\t') for x in lines[1:]]
    rows = [x for x in rows if x[0] == '16' and x[1] != '0']
    if len(rows) != 1 or len(rows[0]) != 4:
        raise ValueError('expected one closed positive n16 row')
    n, k, value, text = rows[0]
    pairs = [tuple(map(int, x.split('^'))) for x in text.split(',')]
    result = certify(int(k), int(value), pairs)

    # Replay the complete retained provider DATA against the exact n-keyed baseline.
    old_rows = [tuple(map(int, x.split())) for x in (ROOT / 'outputs/a16/b-prev.txt').read_text().splitlines() if x]
    provider = (ROOT / 'reference/a358862.seq').read_text()
    if '%O A358862 3,1' not in provider:
        raise ValueError('provider offset/convention changed')
    data = ''.join(re.findall(r'^%[STU] A358862 (.+)$', provider, re.M))
    values = [int(x) for x in data.split(',') if x]
    expected = {n: k for n, k in old_rows}
    if sorted(expected) != list(range(3, 16)) or len(values) != 13:
        raise ValueError('known-provider replay domain differs')
    for n, v in zip(range(3, 16), values):
        index = expected[n]
        if index * ((n - 2) * index - (n - 4)) // 2 != v:
            raise ValueError('known semantic mapping mismatch at n=' + str(n))

    negative_controls = 0
    bad_cases = [(int(k) + 1, int(value), pairs), (int(k), int(value) + 1, pairs),
                 (int(k), int(value), [(p, e + 1 if i == 0 else e) for i, (p, e) in enumerate(pairs)]),
                 (int(k), int(value), [(4, e) if i == 0 else (p, e) for i, (p, e) in enumerate(pairs)])]
    for case in bad_cases:
        try:
            certify(*case)
        except ValueError:
            negative_controls += 1
        else:
            raise ValueError('negative control was accepted')
    result.update(status='INDEPENDENT_POSITIVE_CERTIFICATE_PASS',
                  known_semantic_replay='all13 n-keyed rows n3..15',
                  negative_controls_rejected=negative_controls,
                  independent_negative_census=False,
                  scope='Exact witness/factor/inverse validation only; minimum additionally requires audited complete producer coverage.')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
