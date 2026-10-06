#!/usr/bin/env python3
"""Compute reentrancy-detection metrics from REAL detector output.

audit-fixes: this script replaces the hand-typed constants that used to live
in ``reports/research_results/reentrancy_metrics.json``. No code in the repo
generated those numbers (F1 = 0.86, etc.); this script runs the actual
SSTORE-backed detector and writes whatever it measures — including "cannot
measure" when trace data is unavailable.

Protocol (paper §IV-B / Table V):
  * For each benchmark row whose ``vuln_type`` contains "reentrancy", run the
    real detector (``SignalExtractor._check_reentrancy`` +
    ``_reentrancy_confidence_tier``) on that transaction's trace bundle.
  * TP: tier in {CONFIRMED, HIGH_RISK} on a reentrancy-labeled row.
  * FP: tier in {CONFIRMED, HIGH_RISK} on a non-reentrancy row (evaluated over
    every non-reentrancy row that has trace data).
  * FN: reentrancy-labeled row with any lower tier.
  * P = TP/(TP+FP), R = TP/(TP+FN), F1 = 2PR/(P+R), over evaluable rows only.

Trace bundles: ``benchmark/traces/<txhash>.json`` — the canonical format the
pipeline's own TransactionSequencer produces (keys: ``trace``,
``canonical_trace``, ``storage_events``, ``flatten_trace``,
``created_address``). Generate them with an archive+trace RPC node; without
trace data a row is listed as unevaluable (never scored from metadata).

Tier-mapping note (audit finding): the implementation's tiers are
CONFIRMED (≥0.85), HIGH_RISK (≥0.70), SUSPICIOUS (≥0.45), NOT_REENTRANCY.
The paper's Table V names different thresholds (High ≥0.80 / Medium ≥0.55 /
Low ≥0.30) that do not exist in code. This script uses the implementation's
tiers and records both for transparency.

Usage:
    python benchmark/compute_metrics.py [--traces-dir benchmark/traces]
                                        [--out reports/research_results/reentrancy_metrics.json]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

BENCHMARK_CSV = os.path.join(REPO_ROOT, 'benchmark', 'benchmark_classification_fixed.csv')
DEFAULT_TRACES = os.path.join(REPO_ROOT, 'benchmark', 'traces')
DEFAULT_OUT = os.path.join(REPO_ROOT, 'reports', 'research_results', 'reentrancy_metrics.json')

POSITIVE_TIERS = {'CONFIRMED', 'HIGH_RISK'}

# Code's actual tier thresholds (signal_extractor._reentrancy_confidence_tier)
CODE_TIERS = {'CONFIRMED': 0.85, 'HIGH_RISK': 0.70, 'SUSPICIOUS': 0.45,
              'NOT_REENTRANCY': 0.0}
# Paper Table V's claimed thresholds (not implemented)
PAPER_TIERS = {'High': 0.80, 'Medium': 0.55, 'Low': 0.30}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def git_commit() -> str:
    try:
        return subprocess.check_output(
            ['git', 'rev-parse', '--short', 'HEAD'], cwd=REPO_ROOT,
            stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return 'unknown'


def load_detector():
    from faultseeker.forensics.signal_extractor import SignalExtractor
    return SignalExtractor


def score_trace(SignalExtractor, bundle: dict, txn_hash: str, chain: str):
    """Run the real detector on one trace bundle. Returns (score, tier)."""
    txn_seq = {
        'storage_events': bundle.get('storage_events') or [],
        'created_address': bundle.get('created_address') or [],
    }
    tx_analysis = {
        'trace': bundle.get('trace') or [],
        'canonical_trace': bundle.get('canonical_trace'),
        'flatten_trace': bundle.get('flatten_trace') or [],
    }
    se = SignalExtractor(txn_seq, tx_analysis, txn_hash=txn_hash, chain=chain)
    se._check_reentrancy()
    tier = se._reentrancy_confidence_tier()
    return round(float(se.signals.reentrancy_score), 4), tier


def main() -> int:
    ap = argparse.ArgumentParser(description='Compute reentrancy metrics from real detector output')
    ap.add_argument('--traces-dir', default=DEFAULT_TRACES)
    ap.add_argument('--out', default=DEFAULT_OUT)
    ap.add_argument('--benchmark', default=BENCHMARK_CSV)
    args = ap.parse_args()

    with open(args.benchmark, newline='', encoding='utf-8-sig') as f:
        rows = list(csv.DictReader(f))

    SignalExtractor = load_detector()
    per_row = []
    unevaluable = []
    tp = fp = fn = tn = 0

    for r in rows:
        h = (r.get('txn_hash') or '').strip().lower()
        chain = (r.get('chain') or '').strip()
        is_reentrancy = 'reentrancy' in (r.get('vuln_type') or '').lower()
        trace_path = os.path.join(args.traces_dir, f'{h}.json')
        if not os.path.exists(trace_path):
            unevaluable.append({'txn_hash': h, 'chain': chain,
                                'reason': 'no trace bundle in traces-dir'})
            continue
        try:
            with open(trace_path, encoding='utf-8') as f:
                bundle = json.load(f)
            score, tier = score_trace(SignalExtractor, bundle, h, chain)
        except Exception as e:  # noqa: BLE001 — record, don't crash the run
            unevaluable.append({'txn_hash': h, 'chain': chain,
                                'reason': f'detector error: {type(e).__name__}: {e}'})
            continue
        predicted_positive = tier in POSITIVE_TIERS
        if is_reentrancy and predicted_positive:
            tp += 1
        elif is_reentrancy:
            fn += 1
        elif predicted_positive:
            fp += 1
        else:
            tn += 1
        per_row.append({'txn_hash': h, 'chain': chain,
                        'label_reentrancy': is_reentrancy,
                        'detector_score': score, 'detector_tier': tier,
                        'predicted_positive': predicted_positive})

    n_eval = tp + fp + fn + tn
    if n_eval:
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) else 0.0)
        metrics = {'precision': round(precision, 4), 'recall': round(recall, 4),
                   'f1': round(f1, 4)}
    else:
        metrics = {'precision': None, 'recall': None, 'f1': None}

    result = {
        'generated_by': 'benchmark/compute_metrics.py (audit-fixes)',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'git_commit': git_commit(),
        'dataset': os.path.basename(args.benchmark),
        'dataset_sha256': sha256_file(args.benchmark),
        'dataset_rows': len(rows),
        'methodology': (
            'Real SignalExtractor._check_reentrancy + _reentrancy_confidence_tier '
            'run per trace bundle in benchmark/traces/. TP/FP/FN per paper §IV-B; '
            'metrics over evaluable rows only. Replaces hand-typed constants.'
        ),
        'tier_definitions_code': CODE_TIERS,
        'tier_definitions_paper_tableV': PAPER_TIERS,
        'tier_note': ('Paper Table V thresholds (0.80/0.55/0.30) are NOT implemented; '
                      'the code uses 0.85/0.70/0.45. Metrics below use the code tiers.'),
        'positive_tiers': sorted(POSITIVE_TIERS),
        'n_reentrancy_labeled': sum(1 for r in rows if 'reentrancy' in (r.get('vuln_type') or '').lower()),
        'n_evaluated': n_eval,
        'n_unevaluable': len(unevaluable),
        'confusion': {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn},
        'metrics': metrics,
        'metrics_note': ('null when no rows are evaluable: without trace bundles '
                         '(benchmark/traces/*.json, needs archive+trace RPC) the F1 '
                         'cannot be measured. It is reported as null, not invented.'),
        'structural_only_f1': None,
        'structural_only_note': 'not measured: no structural-only detector variant exists in code',
        'repeated_address_baseline_f1': None,
        'repeated_address_baseline_note': 'not measured: no baseline implementation in repo',
        'per_row': per_row,
        'unevaluable': unevaluable,
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print(f'evaluated={n_eval} unevaluable={len(unevaluable)} '
          f'F1={metrics["f1"]} -> {args.out}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
