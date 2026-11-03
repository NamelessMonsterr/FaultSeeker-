# Trace-depth processing regression

Branch: fix/deep-trace-processing, based on pipeline main
fca6b998fa0a01f3832be6a0f1aa1d768306da8f. Synthetic inputs only; no on-chain
fixture, verdict ground truth or paper metric is created or changed.

At Python's default recursion limit1000, depth1024 reproduced failures in
normalization (three provider variants), TraceNode conversions, canonical
conversion, graph/text traversal and flattening. The old flattening path also
deepcopied every descendant subtree at every frame before deleting children.

Trace-specific traversals are now iterative, retaining order, identities, frame
metadata and all1024 nodes. Flattening copies only each retained frame and keeps
repeated-pattern collection in its original postorder. Active-path cycle checks
reject cyclic local objects while allowing repeated sibling references.
Shallow normalization expectations were captured from the original base code;
tests do not require Git history in a shallow CI checkout.

The integrated application test initially still failed at standard JSON/deepcopy.
`main()` now explicitly establishes a process-wide minimum recursion allowance
of20000 before processing, matching the older Docker pin's function-analyzer
import side effect. It never lowers an existing higher allowance or temporarily
resets it while production threads run. Trace traversal itself does not depend
on that allowance. This is compatibility for the tested1024-frame boundary,
not a security/resource guarantee for arbitrarily deep provider JSON.

Commands, Windows Python3.11.9, installed dependencies only:

```powershell
python -B tests/run_offline_depth.py tests/test_deep_application_path.py tests/test_deep_rpc_normalization.py tests/test_deep_trace_objects.py tests/test_deep_trace_flattening.py tests/test_reentrancy_state_signals.py tests/test_pipeline_parse.py
python -B tests/run_offline_depth.py tests
git diff --check
```

Focused result:66 executed/passed,0failed/skipped,12.56s.
Full available pipeline suite:232 executed/passed,0failed/skipped,15.20s.
Diff check passed. Network sockets blocked; inherited keys removed; temporary
working/output storage. Installed pyreadline3 emitted an ignored Windows-handle
error on interpreter shutdown; full command exit0. Kluster was unavailable.
Independent read-only review found no confirmed regression in changed paths.

The integrated test runs real normalization, cache JSON write/reload, deepcopy,
sequencer, graph construction, flattening and application report JSON, retaining
1024 frames/deepest identity. `analyze_transaction` is controlled around this
trace-processing path: no full forensic/function/model reasoning is verified.
Direct library callers bypassing `main()` do not receive its JSON/deepcopy
allowance. No live RPC/model call, deployment, container build or arbitrary-depth
claim. The separate queued Parity correctness patch is not included here; merge
resolution must preserve both fixes. Docker pin and other worktrees unchanged.
