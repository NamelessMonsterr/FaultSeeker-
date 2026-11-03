# Public RPC application identification

Base: `NamelessMonsterr/FaultSeeker-` main,
`fca6b998fa0a01f3832be6a0f1aa1d768306da8f`.

The parent investigation observed HTTP 403 for a public standard transaction RPC
request using Python urllib's default user agent, and success for the same
request with an explicit honest FaultSeeker validation user agent. That is
endpoint-specific evidence, not proof that every 403 is header-related.

`_http_post` now sets the explicit application name `FaultSeeker`. It does not
impersonate a browser, invent a release version, change the endpoint or auth,
introduce retries, or alter error classification. This worktree did not repeat
the live comparison; acceptance of this exact product-only header remains to be
verified by a bounded live request.

Pre-fix mocked request-contract result: **1 failed, 8 passed**; the expected
application header was missing. The final command was:

```powershell
python -B tests/run_offline_rpc.py tests/test_rpc_user_agent.py tests/test_reentrancy_state_signals.py tests/test_pipeline_parse.py
git diff --check
```

Result: **44 executed, 44 passed, 0 failed, 0 skipped**, 5.67 seconds (9 new
HTTP contract cases plus 35 existing tests). The tests inspect the actual
urllib Request, preserving POST body, JSON content type and timeout; cover
401/403, 429, 500/502 and unchanged 404 handling; and check timeout/invalid JSON
remain errors with no added retry. Diff check passed.

The runner blocks network sockets and removes inherited provider keys. No
downloads, installs, RPC/model service calls, endpoint switches, deployments or
other-worktree changes were performed. Kluster tools were unavailable; no
Kluster verification is claimed. Installed pyreadline3 emitted an ignored
Windows-handle error during interpreter shutdown; the test command exited zero.

These are transport contract tests, not an on-chain trace, full forensic flow,
provider availability or correctness pass. Docker pin remains unchanged.
