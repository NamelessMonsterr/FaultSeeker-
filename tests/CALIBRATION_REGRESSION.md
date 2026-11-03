# Calibration reporting regression

Base: NamelessMonsterr/FaultSeeker- main at
`fca6b998fa0a01f3832be6a0f1aa1d768306da8f`.

The reporting path replaced `confidence.overall` after logistic calibration but
retained the heuristic level and explanation. A failure on a later function also
left earlier functions calibrated while claiming a heuristic fallback.

Two pre-fix regressions reproduced these behaviors through
`FaultSeekerPipeline.analyze_transaction`, with controlled upstream stages and
calibrator outputs. The fix preserves the original heuristic separately, derives
the reported level and explanation from the stored calibrated probability, and
publishes calibration only after every function succeeds. Invalid probabilities
fall back without partially modifying results. Component scores remain heuristic
inputs; they are not described as calibrated feature contributions.

Verification on Windows, Python 3.11.9:

```powershell
python -B tests/run_offline_calibration.py
git diff --check
```

Result: 47 executed, 47 passed, 0 failed, 0 skipped (11.75 seconds); diff check
passed. This includes 23 new regression cases and 24 existing confidence tests.
Network sockets were blocked and inherited provider keys removed by the runner.
Installed pyreadline3 emitted an ignored Windows handle error during interpreter
shutdown; the test command exited zero.

Coverage ends at controlled stage boundaries: no live RPC/model call, trace
ground truth, trained-model accuracy, Docker build or deployment is verified.
No calibration weights, paper metrics or historical reports were modified.
