import os
import re
import json
import subprocess
from faultseeker.utils.rpc_provider import get_rpc, get_all_rpcs, retry_with_backoff, rpc_call, probe_trace_support


# Chain RPC maps now live in faultseeker/utils/rpc_provider.py
# txn_replayer delegates all RPC resolution there.


class TransactionReplayer:

    def __init__(self, cache_path='./data/cache/replay', structured_cache_path='./data/cache/replay_structured'):
        """Initialize TransactionReplayer with cache directory."""
        self.cache_path = cache_path
        self.structured_cache_path = structured_cache_path
        os.makedirs(cache_path, exist_ok=True)
        os.makedirs(structured_cache_path, exist_ok=True)

    @staticmethod
    def _resolve_rpc(chain: str) -> str:
        """Resolve chain short name to best available RPC URL."""
        if chain.startswith('http'):
            return chain
        return get_rpc(chain)

    @staticmethod
    def _run_cast(txn_hash, rpc_url):
        """Run cast run with a given RPC URL. Returns clean stdout or None."""
        command = ["cast", "run", "--quick", txn_hash, '--rpc-url', rpc_url]
        print(' '.join(command))
        try:
            result = subprocess.run(command, capture_output=True, timeout=7200)
            ansi_escape = re.compile(rb'\x1b\[[0-9;]*[a-zA-Z]')
            clean_bytes = ansi_escape.sub(b'', result.stdout)
            clean = clean_bytes.decode('utf-8', errors='ignore')
            if not clean.strip():
                err = ansi_escape.sub(b'', result.stderr).decode('utf-8', errors='ignore').strip()
                if err:
                    print(f"      ✗ cast stderr: {err}")
                return None
            return clean
        except FileNotFoundError:
            # cast (Foundry) not installed — caller will use RPC fallback
            raise
        except Exception:
            import traceback
            traceback.print_exc()
            return None

    @staticmethod
    def _rpc_trace_fallback(txn_hash: str, chain: str) -> str | None:
        """
        Fetch a call trace via JSON-RPC. Uses rpc_call() which internally
        cycles ALL scored providers with per-call failover.
        Tries debug_traceTransaction first, then trace_replayTransaction.
        """
        from faultseeker.utils.rpc_provider import normalize_trace_node, build_parity_tree

        def _fmt_canonical(node, depth=0):
            """Format a canonical (already normalized) trace node."""
            indent = '  ' * depth
            to  = node.get('callee') or node.get('to', '?')
            sig = node.get('function_selector') or node.get('input', '0x')[:10]
            typ = node.get('call_type', 'CALL')
            lines = [f'{indent}{to}::{sig} [{typ}]']
            for child in node.get('children', []):
                lines.extend(_fmt_canonical(child, depth + 1))
            return lines

        # Method 1: debug_traceTransaction (best — gives full call tree)
        print(f'      Trying debug_traceTransaction (all providers)...')
        try:
            result = rpc_call(chain, 'debug_traceTransaction',
                              [txn_hash, {'tracer': 'callTracer'}], timeout=60)
            if result:
                norm = normalize_trace_node(result)
                return '\n'.join(_fmt_canonical(norm))
        except Exception as e:
            print(f'      debug_traceTransaction failed across all providers: {e}')

        # Method 2: trace_replayTransaction (Erigon/Parity flat list format)
        print(f'      Trying trace_replayTransaction (all providers)...')
        try:
            result = rpc_call(chain, 'trace_replayTransaction',
                              [txn_hash, ['trace']], timeout=60)
            if result:
                trace_list = result.get('trace', []) if isinstance(result, dict) else []
                if trace_list:
                    # Build proper nested tree from flat traceAddress list
                    root = build_parity_tree(trace_list)
                    if root:
                        return '\n'.join(_fmt_canonical(normalize_trace_node(root)))
        except Exception as e:
            print(f'      trace_replayTransaction failed across all providers: {e}')

        print('      No supported trace method available on any provider.')
        return None

    def get_structured_cache(self, txn_hash: str) -> dict | None:
        """Check if a structured trace exists in cache."""
        cache_file = os.path.join(self.structured_cache_path, txn_hash.lower() + '.json')
        if not os.path.exists(cache_file):
            return None
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None

    def cache_structured_trace(self, txn_hash: str, structured_trace: dict) -> None:
        """Persist structured trace/state metadata to disk."""
        cache_file = os.path.join(self.structured_cache_path, txn_hash.lower() + '.json')
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(structured_trace, f, indent=2)

    @staticmethod
    def _rpc_structured_trace(txn_hash: str, chain: str) -> dict | None:
        """
        Fetch a canonical call graph plus best-effort SSTORE events.

        Canonical node schema:
          {
            call_id, depth, caller, callee, function_selector, input,
            value, gas, call_type, success, return_data, children
          }
        """
        from faultseeker.utils.rpc_provider import (
            build_parity_tree,
            extract_storage_writes_from_struct_logs,
            extract_storage_writes_from_prestate_diff,
            normalize_trace_node,
        )

        canonical_trace = None
        state_diff = {}
        storage_events = []

        try:
            trace_result = rpc_call(
                chain,
                'debug_traceTransaction',
                [txn_hash, {'tracer': 'callTracer', 'timeout': '60s'}],
                timeout=60,
            )
            if trace_result:
                canonical_trace = normalize_trace_node(trace_result)
        except Exception as e:
            print(f'      structured debug_traceTransaction failed: {e}')

        if canonical_trace is None:
            try:
                replay_result = rpc_call(
                    chain,
                    'trace_replayTransaction',
                    [txn_hash, ['trace', 'stateDiff']],
                    timeout=60,
                )
                if replay_result:
                    trace_list = replay_result.get('trace', []) if isinstance(replay_result, dict) else []
                    if trace_list:
                        root = build_parity_tree(trace_list)
                        if root:
                            canonical_trace = normalize_trace_node(root)
                    if isinstance(replay_result, dict):
                        state_diff = replay_result.get('stateDiff', {}) or {}
            except Exception as e:
                print(f'      structured trace_replayTransaction failed: {e}')

        if canonical_trace is None:
            return None

        try:
            opcode_trace = rpc_call(
                chain,
                'debug_traceTransaction',
                [txn_hash, {
                    'disableMemory': True,
                    'disableStack': False,
                    'disableStorage': False,
                    'timeout': '60s',
                }],
                timeout=60,
            )
            if isinstance(opcode_trace, dict):
                storage_events = extract_storage_writes_from_struct_logs(
                    opcode_trace.get('structLogs', []) or [],
                    canonical_trace,
                )
        except Exception as e:
            print(f'      structured opcode trace failed: {e}')

        if not storage_events:
            # Fallback for providers that reject the raw structLogger (dRPC
            # 400s on it) but support prestateTracer with diffMode: derive
            # the same storage-write events from the pre/post state diff.
            try:
                prestate = rpc_call(
                    chain,
                    'debug_traceTransaction',
                    [txn_hash, {
                        'tracer': 'prestateTracer',
                        'tracerConfig': {'diffMode': True},
                        'timeout': '60s',
                    }],
                    timeout=60,
                )
                if isinstance(prestate, dict):
                    storage_events = extract_storage_writes_from_prestate_diff(
                        prestate,
                        canonical_trace,
                    )
            except Exception as e:
                print(f'      prestate diff trace failed: {e}')

        if not state_diff:
            try:
                replay_result = rpc_call(
                    chain,
                    'trace_replayTransaction',
                    [txn_hash, ['trace', 'stateDiff']],
                    timeout=60,
                )
                if isinstance(replay_result, dict):
                    state_diff = replay_result.get('stateDiff', {}) or {}
            except Exception as e:
                print(f'      structured stateDiff replay failed: {e}')

        return {
            'schema_version': 1,
            'transaction_hash': txn_hash,
            'chain': chain,
            'trace': canonical_trace,
            'storage_events': storage_events,
            'state_diff': state_diff,
        }

    def get_structured_trace(self, txn_hash: str, chain: str) -> dict | None:
        """Fetch canonical trace/state data with cache."""
        structured = self.get_structured_cache(txn_hash)
        if structured:
            return structured

        structured = self._rpc_structured_trace(txn_hash, chain)
        if structured:
            self.cache_structured_trace(txn_hash, structured)
        return structured

    @staticmethod
    def _record_trace_failure(txn_hash: str, reason: str):
        """Persist trace failures to disk so eval harness can report them cleanly."""
        path = os.path.join('data', 'cache', 'trace_failures.json')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            failures = json.load(open(path)) if os.path.exists(path) else {}
        except Exception:
            failures = {}
        failures[txn_hash.lower()] = reason
        with open(path, 'w') as f:
            json.dump(failures, f, indent=2)

    @staticmethod
    def transaction_replay(txn_hash, chain):
        """Execute transaction replay. Tries cast CLI first, then scored RPC failover."""
        primary_rpc = TransactionReplayer._resolve_rpc(chain)

        # Try cast first (fastest when Foundry is installed)
        cast_missing = False
        try:
            result = TransactionReplayer._run_cast(txn_hash, primary_rpc)
            if result:
                return result
        except FileNotFoundError:
            cast_missing = True
            print('      cast (Foundry) not installed -- using RPC trace fallback')

        # Probe trace capability ONCE before committing to 60s timeout cycles
        trace_rpc = probe_trace_support(chain)
        if not trace_rpc:
            msg = f'No provider on {chain} supports debug_traceTransaction'
            print(f'      [TRACE FAIL] {txn_hash[:16]}... -- {msg}')
            TransactionReplayer._record_trace_failure(txn_hash, msg)
            return None

        if cast_missing:
            return TransactionReplayer._rpc_trace_fallback(txn_hash, chain)
        else:
            # cast exists but primary RPC failed -- try other RPCs with cast
            for rpc_url in get_all_rpcs(chain)[1:]:
                print(f'      Trying cast with: {rpc_url[:45]}')
                try:
                    result = TransactionReplayer._run_cast(txn_hash, rpc_url)
                    if result:
                        return result
                except FileNotFoundError:
                    break
            # If cast still got nothing, fall back to RPC
            return TransactionReplayer._rpc_trace_fallback(txn_hash, chain)

        return None


    def get_replay_cache(self, txn_hash):
        """Check if replay result exists in cache."""
        cache_file = os.path.join(self.cache_path, txn_hash.lower() + '.txt')
        if os.path.exists(cache_file):
            return open(cache_file, 'r', encoding='utf-8', errors='ignore').read()
        return None

    def cache_replay(self, txn_hash, invocation_flow):
        """Cache replay result to disk."""
        with open(os.path.join(self.cache_path, txn_hash.lower() + '.txt'), 'w', encoding='utf-8') as f:
            f.write(invocation_flow)

    def run(self, txn_hash: str, chain: str) -> str:
        """
        Run transaction replay for given transaction hash and chain.

        Args:
            txn_hash: Transaction hash
            chain: Chain identifier (eth, bsc, poly, etc.)

        Returns:
            Transaction replay trace text
        """
        # Check cache first
        invocation_flow = self.get_replay_cache(txn_hash)
        if invocation_flow:
            # Reject previously cached rate-limit / Cloudflare error pages
            if '<html' in invocation_flow.lower() or 'cloudflare' in invocation_flow.lower():
                print(f"      ⚠ Stale/invalid cache detected for {txn_hash[:10]}... — clearing")
                import os
                bad = os.path.join(self.cache_path, txn_hash.lower() + '.txt')
                try:
                    os.remove(bad)
                except OSError:
                    pass
                invocation_flow = None
            else:
                return invocation_flow

        # Run replay and cache only valid results
        invocation_flow = self.transaction_replay(txn_hash, chain)
        if invocation_flow:
            # Guard: do not cache error pages from rate-limited / blocked RPCs
            if '<html' in invocation_flow.lower() or 'cloudflare' in invocation_flow.lower():
                print("      ✗ RPC returned an error page (rate-limited?). Not caching.")
                return None
            self.cache_replay(txn_hash, invocation_flow)

        return invocation_flow



