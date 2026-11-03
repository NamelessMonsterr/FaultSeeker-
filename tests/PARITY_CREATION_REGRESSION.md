# Parity creation normalization regression

Base: `NamelessMonsterr/FaultSeeker-` main,
`fca6b998fa0a01f3832be6a0f1aa1d768306da8f`.

The direct Parity normalizer used `action.init` (creation bytecode) as the
callee and discarded it as input. The flat-array tree builder did the same,
then dropped original type/result/error fields, so subsequent normalization
reported CREATE as CALL and could lose a reverted call's failure status.

The fix reads creation callee from `result.address` and input from `action.init`.
When no usable creation result is present, callee stays empty instead of being
invented from bytecode. Tree reconstruction retains the provider's action,
result, type and failure metadata for the subsequent normalizer. The caller's
input trace is not mutated. Ordinary CALL destination/input behavior is retained.

The first pre-fix run reproduced 10 failures and 1 pass using synthetic
provider-schema inputs. Final coverage adds CREATE2 variants, direct/tree
normalization, malformed/missing failed-creation results, CALL preservation,
and the real `TransactionReplayer._rpc_structured_trace` Parity fallback with
controlled RPC replies and a nested creation. No on-chain fixture is invented.

Executed on Windows / Python 3.11.9:

```powershell
python -B tests/run_offline_parity.py tests/test_parity_creation_normalization.py tests/test_reentrancy_state_signals.py tests/test_pipeline_parse.py
git diff --check
```

Result: **48 executed, 48 passed, 0 failed, 0 skipped**, 5.19 seconds, including
13 new regression cases and 35 existing tests. Diff check passed. Network was
blocked and inherited keys removed; no installs or model/RPC service calls.
Installed pyreadline3 emitted an ignored Windows-handle error at interpreter
shutdown; the test command exited zero. Kluster tools were unavailable, so no
Kluster verification is claimed.

Coverage ends at the structured trace boundary for this new Parity regression.
It does not establish live provider behavior, whole forensic/function/model
analysis, verdict correctness or deployment. The Docker pin and other worktrees
were not modified; no push, merge or deployment was performed by this change.
