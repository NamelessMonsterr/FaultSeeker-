# Offline target-binding regression checks

Use this branch plus companion console PR3 (d03fcea1d1903e6dcac6d005802cf254de2312b6).
To test both console fixes together, use a local-only branch that combines PR3
with the preflight PR2 branch. Do not change the production Docker pin for tests.

With both repos' dependencies installed:

    CONSOLE_REPO_PATH=/absolute/path/to/console python -m pytest tests/test_canonical_target_binding.py tests/test_rejected_findings_pipeline_e2e.py -q

The model and blockchain stages are stubbed. The candidate filter, finalizer,
pipeline result assembly, confidence scorer, evidence cards, and console
annotation are real. Sockets are blocked. This is an offline integration test,
not a live-provider or blockchain analysis and not proof that the model will
echo the correct id on future transactions.

The console annotation cases use its checked-in hedgey_verified_trace.json.
Both rejected-only and mixed valid/rejected outputs must remain partial and
INCONCLUSIVE. Removing pipeline.py's rejected_findings forwarding must fail
these tests. Other cases cover raw malformed output and junk lists.

The console's seven opt-in integration tests can separately run against an
exact deployed-fork checkout at bc98bfd8cc6903363955da72792db112757172c0:

    FAULTSEEKER_TEST_PIPELINE_REPO=/absolute/path/to/deployed-fork python -m pytest tests/ -q

Those tests exercise transport hooks, retry budgets, key rotation, canonical
trace conversion, ranking, and cache identity. They do not call live services.
