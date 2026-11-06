"""
explorer_provider.py — Adaptive, scored explorer API client for FaultSeeker.

Applies the same engineering principles as rpc_provider.py to block explorer
HTTP APIs (Etherscan, BscScan, etc.):
  - Multiple endpoints per chain (primary + fallback explorers)
  - EMA latency tracking + dynamic weight sorting
  - Circuit breaker with gradual half-open recovery
  - Differentiated penalties: auth -40 | rate-limit -10 | server -15
  - API keys loaded from .env automatically

Supported chains (15+):
  ETH, BSC, Polygon, Arbitrum, Optimism, Avalanche, Base, Fantom,
  zkSync Era, Linea, Scroll, Gnosis, Celo, Cronos, Moonbeam, Aurora

Usage:
    from faultseeker.utils.explorer_provider import explorer_call, print_explorer_stats

    # Fetch source code (retries across explorer endpoints automatically):
    data = explorer_call('bsc', {
        'module': 'contract',
        'action': 'getsourcecode',
        'address': '0xAddr',
    })
    if data and data.get('status') == '1':
        ...
"""

import os
import json
import random
import time
import logging
import threading
import urllib.request
import urllib.parse
import urllib.error
from typing import Any
from dotenv import load_dotenv

load_dotenv(override=True)
log = logging.getLogger('faultseeker.explorer')


# ── Per-endpoint metrics (EMA latency) ────────────────────────────────────────

class _Metrics:
    EMA_ALPHA = 0.2

    def __init__(self):
        self.success = 0
        self.fail    = 0
        self.ema_ms  = 800.0   # start slightly pessimistic
        self._lock   = threading.Lock()

    def record(self, ms: float, ok: bool):
        with self._lock:
            if ok:
                self.success += 1
            else:
                self.fail += 1
            self.ema_ms = self.EMA_ALPHA * ms + (1 - self.EMA_ALPHA) * self.ema_ms

    @property
    def success_rate(self) -> float:
        t = self.success + self.fail
        return self.success / t if t else 0.0

    @property
    def total(self) -> int:
        return self.success + self.fail


# ── Scored explorer endpoint ───────────────────────────────────────────────────

class _ExplorerEndpoint:
    """Single explorer API base URL with health score and circuit breaker."""

    SCORE_MIN    =   0
    SCORE_MAX    = 100
    REWARD_MAX   =   8
    REWARD_FLOOR =  -4
    LATENCY_SCALE = 150    # ms per score point (generous — explorer APIs are slower)
    PENALTY_429  =  10
    PENALTY_5XX  =  15
    PENALTY_TIMEOUT = 20
    PENALTY_AUTH =  40
    SCORE_BLEED  = 0.92    # gentler than RPC (explorer limits are less volatile)
    BLEED_INTERVAL = 600

    CB_THRESHOLD = 4
    CB_PAUSE_SECS = 90     # explorers throttle for longer, so pause longer
    CB_PROBES    = 2

    def __init__(self, base_url: str, api_key_env: str = '', initial_score: int = 80):
        self.base_url     = base_url
        self.api_key_env  = api_key_env
        self.score        = float(max(0, min(100, initial_score + random.randint(-4, 4))))
        self.metrics      = _Metrics()
        self._lock        = threading.Lock()
        self._consec_fail = 0
        self._cb_until    = 0.0
        self._half_probes = 0
        self._last_bleed  = time.time()

    @property
    def api_key(self) -> str:
        if self.api_key_env:
            return os.getenv(self.api_key_env, '').strip() or 'YourApiKeyToken'
        return 'YourApiKeyToken'

    @property
    def is_circuit_open(self) -> bool:
        if self._cb_until == 0:
            return False
        return time.time() < self._cb_until

    @property
    def _is_half_open(self) -> bool:
        return self._cb_until > 0 and time.time() >= self._cb_until and self._half_probes < self.CB_PROBES

    @property
    def dynamic_weight(self) -> float:
        score_norm = self.score / self.SCORE_MAX
        sr         = self.metrics.success_rate
        lat_factor = max(0.0, 1.0 - self.metrics.ema_ms / 5000.0)   # 5s ceiling
        return 0.50 * score_norm + 0.30 * sr + 0.20 * lat_factor

    def _apply_bleed(self):
        now   = time.time()
        ticks = int((now - self._last_bleed) / self.BLEED_INTERVAL)
        if ticks > 0:
            with self._lock:
                self.score       = max(self.score * (self.SCORE_BLEED ** ticks), self.SCORE_MIN)
                self._last_bleed = now

    def reward(self, ms: float):
        self._apply_bleed()
        raw = self.REWARD_MAX - (ms / self.LATENCY_SCALE)
        pts = max(self.REWARD_FLOOR, min(self.REWARD_MAX, raw))
        with self._lock:
            self.score        = min(max(self.score + pts, self.SCORE_MIN), self.SCORE_MAX)
            self._consec_fail = 0
            if self._cb_until > 0:
                self._half_probes += 1
                if self._half_probes >= self.CB_PROBES:
                    self._cb_until    = 0
                    self._half_probes = 0
                    log.info(f'[explorer circuit CLOSED] {self.base_url[:50]}')
        self.metrics.record(ms, ok=True)

    def penalize(self, ms: float, penalty: int):
        self._apply_bleed()
        with self._lock:
            self.score        = max(self.score - penalty, self.SCORE_MIN)
            self._consec_fail += 1
            self._half_probes  = 0
            if self._consec_fail >= self.CB_THRESHOLD:
                self._cb_until = time.time() + self.CB_PAUSE_SECS
                log.warning(f'[explorer circuit TRIPPED] {self.base_url[:50]} — {self.CB_PAUSE_SECS}s')
        self.metrics.record(ms, ok=False)

    def build_url(self, params: dict) -> str:
        p = dict(params)
        p.setdefault('apikey', self.api_key)
        return f'{self.base_url}?{urllib.parse.urlencode(p)}'

    def __repr__(self):
        state = 'OPEN' if self.is_circuit_open else ('HALF' if self._is_half_open else 'OK')
        return f'<Explorer {self.base_url[:45]} score={self.score:.0f} w={self.dynamic_weight:.2f} [{state}]>'


# ── Chain → endpoints registry ─────────────────────────────────────────────────
#
# Each chain entry is a list of (base_url, api_key_env, initial_score).
# The first entry is the primary explorer; subsequent entries are fallbacks.
# Chains with multiple live explorers (e.g. zkSync has two verified explorers)
# benefit most from this — they'll auto-failover when one rate-limits.

_CHAIN_EXPLORERS: dict[str, list[tuple[str, str, int]]] = {
    # ── Ethereum ──────────────────────────────────────────────────────────────
    'eth': [
        ('https://api.etherscan.io/api',            'ETHERSCAN_API_KEY',          90),
        ('https://api.etherscan.io/api',            'ETHERSCAN_API_KEY_2',         70),  # second key
        ('https://eth.blockscout.com/api',          '',                            65),  # keyless fallback
    ],
    # ── BNB Smart Chain ───────────────────────────────────────────────────────
    'bsc': [
        ('https://api.bscscan.com/api',             'BSCSCAN_API_KEY',            90),
        ('https://api.bscscan.com/api',             'BSCSCAN_API_KEY_2',           70),
    ],
    # ── Polygon ───────────────────────────────────────────────────────────────
    'polygon': [
        ('https://api.polygonscan.com/api',         'POLYGONSCAN_API_KEY',         90),
        ('https://polygon.blockscout.com/api',      '',                            65),  # no key needed
    ],
    # ── Arbitrum One ──────────────────────────────────────────────────────────
    'arbitrum': [
        ('https://api.arbiscan.io/api',             'ARBISCAN_API_KEY',            90),
        ('https://arbitrum.blockscout.com/api',     '',                            65),
    ],
    # ── Optimism ──────────────────────────────────────────────────────────────
    'optimism': [
        ('https://api-optimistic.etherscan.io/api', 'OPTIMISM_ETHERSCAN_API_KEY',  90),
        ('https://optimism.blockscout.com/api',     '',                            65),
    ],
    # ── Avalanche C-Chain ─────────────────────────────────────────────────────
    'avalanche': [
        ('https://api.snowtrace.io/api',            'SNOWTRACE_API_KEY',           90),
        ('https://glacier-api.avax.network/v1',     '',                            60),
    ],
    # ── Base ──────────────────────────────────────────────────────────────────
    'base': [
        ('https://api.basescan.org/api',            'BASESCAN_API_KEY',            90),
        ('https://base.blockscout.com/api',         '',                            65),
    ],
    # ── Fantom ────────────────────────────────────────────────────────────────
    'fantom': [
        ('https://api.ftmscan.com/api',             'FTMSCAN_API_KEY',             90),
        ('https://ftm.blockscout.com/api',          '',                            60),
    ],
    # ── zkSync Era ────────────────────────────────────────────────────────────
    'zksync': [
        ('https://block-explorer-api.mainnet.zksync.io/api', '',                   80),
        ('https://zksync.blockscout.com/api',       '',                            70),
    ],
    # ── Linea ─────────────────────────────────────────────────────────────────
    'linea': [
        ('https://api.lineascan.build/api',         'LINEASCAN_API_KEY',           85),
        ('https://explorer.linea.build/api',        '',                            65),
    ],
    # ── Scroll ────────────────────────────────────────────────────────────────
    'scroll': [
        ('https://api.scrollscan.com/api',          'SCROLLSCAN_API_KEY',          85),
        ('https://scroll.blockscout.com/api',       '',                            65),
    ],
    # ── Gnosis (xDai) ─────────────────────────────────────────────────────────
    'gnosis': [
        ('https://api.gnosisscan.io/api',           'GNOSISSCAN_API_KEY',          85),
        ('https://gnosis.blockscout.com/api',       '',                            65),
    ],
    # ── Celo ──────────────────────────────────────────────────────────────────
    'celo': [
        ('https://api.celoscan.io/api',             'CELOSCAN_API_KEY',            85),
        ('https://celo.blockscout.com/api',         '',                            65),
    ],
    # ── Cronos ────────────────────────────────────────────────────────────────
    'cronos': [
        ('https://api.cronoscan.com/api',           'CRONOSCAN_API_KEY',           85),
        ('https://cronos.org/explorer/api',         '',                            60),
    ],
    # ── Moonbeam ──────────────────────────────────────────────────────────────
    'moonbeam': [
        ('https://api-moonbeam.moonscan.io/api',    'MOONSCAN_API_KEY',            85),
        ('https://moonbeam.moonscan.io/api',        '',                            65),
    ],
    # ── Aurora (NEAR EVM) ─────────────────────────────────────────────────────
    'aurora': [
        ('https://explorer.mainnet.aurora.dev/api', '',                            75),
    ],
}

# Aliases → canonical
_ALIASES: dict[str, str] = {
    'ethereum': 'eth', 'bnb': 'bsc',
    'poly': 'polygon', 'arb': 'arbitrum',
    'op': 'optimism', 'avax': 'avalanche',
    'ftm': 'fantom', 'zkevm': 'polygon',
    'xdai': 'gnosis',
}


def _canonical(chain: str) -> str:
    return _ALIASES.get(chain.lower(), chain.lower())


class _ExplorerRegistry:
    def __init__(self):
        self._chains: dict[str, list[_ExplorerEndpoint]] = {}
        self._lock   = threading.Lock()

    def _endpoints(self, chain: str) -> list[_ExplorerEndpoint]:
        with self._lock:
            if chain not in self._chains:
                specs = _CHAIN_EXPLORERS.get(chain, [])
                self._chains[chain] = [
                    _ExplorerEndpoint(url, env, score)
                    for url, env, score in specs
                ]
            return self._chains[chain]

    def sorted_endpoints(self, chain: str) -> list[_ExplorerEndpoint]:
        endpoints = self._endpoints(chain)
        return sorted(endpoints,
                      key=lambda e: (-1e9 if e.is_circuit_open else e.dynamic_weight),
                      reverse=True)


_registry = _ExplorerRegistry()


# ── Error classification ───────────────────────────────────────────────────────

class _AuthError(Exception):
    pass

class _RateLimitError(Exception):
    pass

class _ServerError(Exception):
    pass


def _classify_http(code: int) -> type:
    if code in (401, 403):
        return _AuthError
    if code == 429:
        return _RateLimitError
    if code >= 500:
        return _ServerError
    return RuntimeError


def _penalty_for(exc: Exception) -> int:
    if isinstance(exc, _AuthError):
        return _ExplorerEndpoint.PENALTY_AUTH
    if isinstance(exc, _RateLimitError):
        return _ExplorerEndpoint.PENALTY_429
    if isinstance(exc, _ServerError):
        return _ExplorerEndpoint.PENALTY_5XX
    if isinstance(exc, TimeoutError):
        return _ExplorerEndpoint.PENALTY_TIMEOUT
    return _ExplorerEndpoint.PENALTY_5XX


# ── Core: scored, circuit-broken explorer call ─────────────────────────────────

def explorer_call(chain: str, params: dict, timeout: int = 20) -> dict | None:
    """
    Make an authenticated explorer API call across endpoints for the chain,
    sorted by dynamic weight. Handles failover, scoring, and circuit breaking.

    Returns the parsed JSON dict, or None if ALL endpoints failed.
    """
    canonical = _canonical(chain)
    endpoints = _registry.sorted_endpoints(canonical)

    if not endpoints:
        log.warning(f'No explorer endpoints configured for chain: {chain}')
        return None

    soft_failure = None  # first API-level non-success response (endpoint alive)

    for ep in endpoints:
        if ep.is_circuit_open:
            log.debug(f'[explorer circuit SKIP] {ep.base_url[:50]}')
            continue

        url = ep.build_url(params)
        t0  = time.time()
        try:
            req  = urllib.request.Request(url, headers={'User-Agent': 'FaultSeeker/1.0'})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode('utf-8', errors='ignore'))
            ms = (time.time() - t0) * 1000

            # Application-level error classification. Etherscan-style APIs put
            # 'NOTOK' in message and the real reason in result, so both fields
            # must be examined - otherwise an auth/rate-limit failure counts as
            # success and failover never happens.
            msg = f"{data.get('message', '')} {data.get('result', '')}".lower()
            if any(w in msg for w in ('invalid api key', 'invalid apikey', 'unauthorized', 'missing apikey', 'missing api key', 'missing/invalid api key')):
                raise _AuthError(msg)
            if 'rate limit' in msg or 'max rate' in msg:
                raise _RateLimitError(msg)

            # Validate status + payload, not just HTTP 200: a status != '1'
            # response (deprecated endpoint, contract not verified, empty
            # result) must not look like success. Try the next endpoint and
            # preserve the primary's answer if every endpoint answers the same.
            if str(data.get('status', '')) != '1' or not data.get('result'):
                log.debug(f'[explorer SOFT-FAIL] {ep.base_url[:42]} {params.get("action","")}: {msg[:80]}')
                ep.reward(ms)
                if soft_failure is None:
                    soft_failure = data
                continue

            log.debug(f'[explorer OK] {ep.base_url[:42]} {params.get("action","")} {ms:.0f}ms')
            ep.reward(ms)
            return data

        except urllib.error.HTTPError as e:
            ms  = (time.time() - t0) * 1000
            exc = _classify_http(e.code)(f'HTTP {e.code}')
            ep.penalize(ms, _penalty_for(exc))
            log.warning(f'[explorer FAIL] {ep.base_url[:42]}: HTTP {e.code} ({ms:.0f}ms)')

        except (_AuthError, _RateLimitError, _ServerError) as exc:
            ms = (time.time() - t0) * 1000
            ep.penalize(ms, _penalty_for(exc))
            log.warning(f'[explorer FAIL] {ep.base_url[:42]}: {exc} ({ms:.0f}ms)')

        except Exception as exc:
            ms = (time.time() - t0) * 1000
            ep.penalize(ms, _ExplorerEndpoint.PENALTY_5XX)
            log.warning(f'[explorer FAIL] {ep.base_url[:42]}: {exc} ({ms:.0f}ms)')

    if soft_failure is not None:
        log.warning(f'All explorer endpoints returned no result for {chain}:{params.get("action","")}')
        return soft_failure
    log.error(f'All explorer endpoints failed for {chain}:{params.get("action","")}')
    return None


# ── Convenience: get API key for a chain ──────────────────────────────────────

def get_explorer_api_key(chain: str) -> str:
    """Get the best available API key for the given chain."""
    canonical  = _canonical(chain)
    endpoints  = _registry.sorted_endpoints(canonical)
    active     = [e for e in endpoints if not e.is_circuit_open]
    best       = (active or endpoints)
    return best[0].api_key if best else 'YourApiKeyToken'


# ── Stats / observability ──────────────────────────────────────────────────────

def print_explorer_stats(chain: str):
    """Print explorer endpoint scoreboard for a chain."""
    endpoints = _registry.sorted_endpoints(_canonical(chain))
    print(f'\n  🔍 Explorer stats — {chain.upper()}')
    print(f'  {"URL":<50} {"Score":>5}  {"Weight":>6}  {"OK":>4}  {"Fail":>4}  {"EMA ms":>7}  {"Rate":>5}  State')
    print(f'  {"-" * 100}')
    for e in endpoints:
        m     = e.metrics
        rate  = f'{m.success_rate*100:.0f}%' if m.total else 'N/A'
        state = '⛔ OPEN' if e.is_circuit_open else ('🟡 HALF' if e._is_half_open else '✅ OK')
        print(f'  {e.base_url[:50]:<50} {e.score:>5.0f}  {e.dynamic_weight:>6.3f}  '
              f'{m.success:>4}  {m.fail:>4}  {m.ema_ms:>7.0f}  {rate:>5}  {state}')
