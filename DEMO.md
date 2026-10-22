# Demo console integration

This branch makes the repo directly drivable by the FaultSeeker forensic
console (web UI), without changing any pipeline behavior.

## What changed vs main

Only `faultseeker/main.py`:

- New `offline` and `no_llm` parameters on `main()` (and `--offline` /
  `--no-llm` CLI flags):
  - `--offline`: strict local-only deterministic Stage 1. Uses a local
    forensics cache (`data/cache/forensics/<txn_hash>.json`) when present;
    otherwise returns an explicit UNCERTAIN demo-triage result. No RPC,
    explorer, model, or provider is contacted.
  - `--no-llm`: real deterministic Stage 1 through free/public acquisition
    only. No LLM is constructed or called; Stage 2 is skipped.
- Interactive model selection imports are now lazy, so `main()` can be
  imported and called programmatically with explicit models.

Nothing else in the repo was touched. Full pipeline behavior with explicit
models is unchanged.

## Console contract

The console backend imports and calls:

```python
from faultseeker.main import main
# deterministic, free RPC:
main(txn_hash="0x...", chain="eth", no_llm=True, output_path="out.json")
# full pipeline, per-request keys via env (OPENAI_API_KEY etc.):
main(txn_hash="0x...", chain="eth", forensics_model="gpt-4o-mini",
     function_analysis_model="gpt-4o-mini", track_cost=True, output_path="out.json")
```

Both return the Stage-1+ result dict the console renders (verdict, rule
confidence, signals, ranked functions, reentrancy, balance changes).

## Seeding the offline replay cache

Copy a saved Stage-1 report to `data/cache/forensics/<txn_hash>.json` (the
report must contain `transaction.hash` / `transaction.chain` matching the
request). Then `--offline` replays it with zero network access.
