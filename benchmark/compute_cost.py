#!/usr/bin/env python3
"""Recompute the cost analysis from CostTracker pricing data.

audit-fixes: the old ``reports/research_results/runtime_cost.json`` asserted
``cost_reduction_pct: 58`` with no generating code. The 58% figure is the
*Tier-2-only* per-query saving ($0.05 vs $0.12 cloud); applied to the paper's
own 5:3:2 tier mix the overall LLM-spend saving is 35%, because Tier 1 is
deterministic (zero LLM cost) in both modes and must not inflate the
denominator.

This script recomputes the arithmetic from the paper's stated inputs and the
CostTracker pricing table, and writes ``runtime_cost.json`` with explicit
provenance. It is a MODEL — no production query log exists in the repo, and
no measured run backs the latency figures, so those are removed rather than
re-asserted. A real measured run (``CostTracker`` over production traffic
with API keys) would replace the modeled section.

Usage:
    python benchmark/compute_cost.py [--out reports/research_results/runtime_cost.json]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

DEFAULT_OUT = os.path.join(REPO_ROOT, 'reports', 'research_results', 'runtime_cost.json')

# ── Inputs (paper §6.7 claims; labeled as inputs, not measurements) ───────────
TIER_FRACTIONS = {'tier1': 0.50, 'tier2': 0.30, 'tier3': 0.20}
# Per-query USD cost inputs quoted by the paper (embed assumed token counts;
# not derivable from the pricing table alone without a measured run).
TIER2_HYBRID_COST = 0.05   # paper's blended Tier-2 cost (local-first)
TIER2_CLOUD_COST = 0.12    # paper's Tier-2 cost when routed to cloud
TIER3_COST = 0.12          # Tier 3 is always cloud


def git_commit() -> str:
    try:
        return subprocess.check_output(
            ['git', 'rev-parse', '--short', 'HEAD'], cwd=REPO_ROOT,
            stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return 'unknown'


def main() -> int:
    ap = argparse.ArgumentParser(description='Recompute cost analysis honestly')
    ap.add_argument('--out', default=DEFAULT_OUT)
    args = ap.parse_args()

    from faultseeker.research.cost_tracker import DEFAULT_PRICING
    local_price = DEFAULT_PRICING['local']

    f1, f2, f3 = (TIER_FRACTIONS['tier1'], TIER_FRACTIONS['tier2'],
                  TIER_FRACTIONS['tier3'])

    # Tier 1 is deterministic (rule classifier): $0 LLM cost in BOTH modes.
    # Cloud-only baseline: every LLM query (tiers 2+3) goes to cloud.
    hybrid_per_query = f1 * 0.0 + f2 * TIER2_HYBRID_COST + f3 * TIER3_COST
    cloud_per_query = f1 * 0.0 + f2 * TIER2_CLOUD_COST + f3 * TIER3_COST
    reduction = ((cloud_per_query - hybrid_per_query) / cloud_per_query
                 if cloud_per_query else 0.0)

    # What the old 58% actually was: Tier-2-only saving, mislabeled as overall.
    tier2_only_saving = ((TIER2_CLOUD_COST - TIER2_HYBRID_COST) / TIER2_CLOUD_COST
                         if TIER2_CLOUD_COST else 0.0)

    result = {
        'generated_by': 'benchmark/compute_cost.py (audit-fixes)',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'git_commit': git_commit(),
        'methodology': (
            'Modeled from the paper §6.7 inputs and CostTracker.DEFAULT_PRICING '
            '(local tier = $0). NOT a measured run: no production query log exists '
            'in the repo. Replaces the hand-typed runtime_cost.json.'
        ),
        'pricing_source': 'faultseeker/research/cost_tracker.py: DEFAULT_PRICING',
        'local_tier_pricing_usd_per_1m_tokens': local_price,
        'inputs': {
            'tier_fractions': TIER_FRACTIONS,
            'tier2_hybrid_cost_per_query_usd': TIER2_HYBRID_COST,
            'tier2_cloud_cost_per_query_usd': TIER2_CLOUD_COST,
            'tier3_cost_per_query_usd': TIER3_COST,
            'inputs_note': ('per-query costs embed assumed token counts; they are '
                            'paper inputs, not measurements'),
        },
        'computed': {
            'hybrid_cost_per_query_usd': round(hybrid_per_query, 4),
            'cloud_only_cost_per_query_usd': round(cloud_per_query, 4),
            'cost_reduction_pct': round(reduction * 100, 1),
        },
        'correction': {
            'old_claim_pct': 58,
            'old_claim_status': 'REMOVED — was Tier-2-only saving, mislabeled as overall',
            'tier2_only_saving_pct': round(tier2_only_saving * 100, 1),
            'tier2_only_note': ('(0.12-0.05)/0.12 = 58.3%: the old headline number. '
                                'It ignores Tier 1 (deterministic, $0 in both modes) '
                                'and Tier 3 (cloud in both modes).'),
        },
        'latency': None,
        'latency_note': ('REMOVED — the old stage1/stage23 latency figures (2.3s, '
                         '8.1s, 3.4s) had no measurement behind them. Measure with '
                         'CostTracker stage timings on a real run.'),
        'benign_prefilter': {
            'status': 'mechanism implemented (audit-fixes), rate unmeasured',
            'note': ('RuleClassifier Rule 0 now emits BENIGN and the pipeline '
                     'skips Stage 2. The old "40% of Stage 2 calls avoided" was '
                     'never measured; no rate is claimed here.'),
        },
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print(f"cost_reduction_pct={result['computed']['cost_reduction_pct']} "
          f"(old claim 58 removed) -> {args.out}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
