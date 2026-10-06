"""
rpc_provider.py — Elite-grade, self-correcting RPC orchestration layer.

Design principles:
  - Adaptive: learns from every call via latency EMA + composite dynamic weight
  - Fair: periodic score rebalancing prevents winner-takes-all lock-in
  - Resilient: circuit breaker with 3-probe gradual recovery
  - Precise: 429/5xx/timeout/auth treated with differentiated penalties
  - Efficient: JSON-RPC batching with per-call fallback on chunk failure

Usage:
    from faultseeker.utils.rpc_provider import rpc_call, rpc_batch, get_rpc, print_provider_stats

    # Single call — scored failover across all providers:
    block = rpc_call('eth', 'eth_blockNumber', [])

    # Batch — one HTTP round-trip, chunked at MAX_BATCH_SIZE, per-call fallback:
    results = rpc_batch('bsc', [
        ('eth_blockNumber', []),
        ('eth_getBalance', ['0xAddr', 'latest']),
    ])

    # Scoreboard (auto-printed after every pipeline run):
    print_provider_stats('bsc')
"""

import os
import json
import math
import random
import time
import logging
import threading
from typing import Any
import urllib.request
import urllib.error
from dotenv import load_dotenv

load_dotenv(override=True)
log = logging.getLogger('faultseeker.rpc')

# ── LRU + TTL Cache (thread-safe) ─────────────────────────────────────────────

class _LRUCache:
    def __init__(self, max_size: int = 512, ttl_secs: int = 600):
        self._store: dict[str, tuple[Any, float]] = {}
        self._order: list[str] = []
        self._max   = max_size
        self._ttl   = ttl_secs
        self._lock  = threading.Lock()

    def get(self, key: str) -> tuple[bool, Any]:
        with self._lock:
            if key not in self._store:
                return False, None
            val, exp = self._store[key]
            if time.time() > exp:
                del self._store[key]
                self._order.remove(key)
                return False, None
            self._order.remove(key)
            self._order.append(key)
            return True, val

    def set(self, key: str, value: Any):
        with self._lock:
            if key in self._store:
                self._order.remove(key)
            elif len(self._store) >= self._max:
                evict = self._order.pop(0)
                del self._store[evict]
            self._store[key] = (value, time.time() + self._ttl)
            self._order.append(key)


_cache = _LRUCache(max_size=512, ttl_secs=600)

# ── EMA Latency tracker + metrics ─────────────────────────────────────────────

class _Metrics:
    """
    Per-provider metrics.
    Latency uses EMA (alpha=0.2) for smooth signal — more stable than rolling window P95.
    """
    EMA_ALPHA = 0.2   # weight for each new observation; ~5 observations to converge

    def __init__(self):
        self.success   = 0
        self.fail      = 0
        self.ema_ms    = 500.0   # start pessimistic so new providers aren't over-trusted
        self._lock     = threading.Lock()

    def record(self, latency_ms: float, ok: bool):
        with self._lock:
            if ok:
                self.success += 1
            else:
                self.fail += 1
            # EMA update — driven by all calls (success and fail get latency context)
            self.ema_ms = self.EMA_ALPHA * latency_ms + (1 - self.EMA_ALPHA) * self.ema_ms

    @property
    def success_rate(self) -> float:
        total = self.success + self.fail
        return self.success / total if total else 0.0

    @property
    def total(self) -> int:
        return self.success + self.fail


# ── Scored, adaptive provider ──────────────────────────────────────────────────

class _RPCProvider:
    """
    A single RPC endpoint with:
      - Negative scoring zone for slow providers (>1000ms actively loses score)
      - Circuit breaker with 3-probe gradual half-open recovery
      - Differentiated penalties: auth -40 | timeout -25 | 5xx -15 | 429 -10
      - Periodic score rebalancing (10-min bleed prevents permanent lock-in)
      - Adaptive per-provider timeout based on EMA latency
      - Cold-start jitter to prevent ordering bias at startup
    """
    # Scoring
    SCORE_MIN     =   0
    SCORE_MAX     = 100
    REWARD_MAX    =  10
    REWARD_FLOOR  =  -5
    LATENCY_SCALE = 100    # ms per reward point; +10 at 0ms, 0 at 1000ms, -5 floor
    PENALTY_429   =  10    # rate limit — temporary, recovers naturally
    PENALTY_5XX   =  15    # server error
    PENALTY_TIMEOUT =  25  # timed out — expensive waste
    PENALTY_AUTH  =  40    # permanent until key is fixed
    SCORE_BLEED   = 0.90   # periodic multiplier (10% reduction every 10 min)
    BLEED_INTERVAL = 600   # seconds between rebalancing ticks

    # Circuit breaker
    CB_THRESHOLD  =   4    # consecutive failures before tripping
    CB_PAUSE_SECS =  60    # pause duration
    CB_PROBES     =   3    # clean probes needed to fully close

    # Adaptive timeout bounds (seconds)
    TIMEOUT_MIN   =   2
    TIMEOUT_MAX   =  10
    TIMEOUT_EMA_K =  4     # multiplier: timeout = k * ema_latency_secs

    def __init__(self, url: str, initial_score: int = 80):
        # Cold-start jitter: ±5 pts so providers with same nominal score explore fairly
        self.url          = url
        self.score        = float(max(0, min(100, initial_score + random.randint(-5, 5))))
        self.metrics      = _Metrics()
        self._lock        = threading.Lock()
        self._consec_fail = 0
        self._cb_until    = 0.0   # epoch; 0 = circuit closed
        self._half_probes = 0     # successful probes in half-open state
        self._last_bleed  = time.time()

    # ── circuit state ──────────────────────────────────────────────────────────

    @property
    def is_circuit_open(self) -> bool:
        if self._cb_until == 0:
            return False
        if time.time() >= self._cb_until:
            return False   # half-open: allow probes through
        return True

    @property
    def _is_half_open(self) -> bool:
        return (self._cb_until > 0 and
                time.time() >= self._cb_until and
                self._half_probes < self.CB_PROBES)

    # ── adaptive timeout ───────────────────────────────────────────────────────

    @property
    def adaptive_timeout(self) -> int:
        """Timeout in seconds based on EMA latency. Fast nodes get tighter timeouts."""
        ema_secs = self.metrics.ema_ms / 1000.0
        t = self.TIMEOUT_EMA_K * ema_secs
        return int(max(self.TIMEOUT_MIN, min(self.TIMEOUT_MAX, t)))

    # ── dynamic composite weight ───────────────────────────────────────────────

    @property
    def dynamic_weight(self) -> float:
        """
        Composite weight used for sorting providers:
          50% normalised score + 30% success rate + 20% latency factor
        """
        score_norm   = self.score / self.SCORE_MAX
        sr           = self.metrics.success_rate
        # latency factor: 1.0 at 0ms, 0.0 at 2000ms
        lat_factor   = max(0.0, 1.0 - self.metrics.ema_ms / 2000.0)
        return 0.50 * score_norm + 0.30 * sr + 0.20 * lat_factor

    # ── score mechanics ────────────────────────────────────────────────────────

    def _apply_bleed(self):
        """Periodic rebalancing: multiply score by SCORE_BLEED every BLEED_INTERVAL.
        Prevents any provider from saturating at 100 and starving out competitors."""
        now   = time.time()
        ticks = int((now - self._last_bleed) / self.BLEED_INTERVAL)
        if ticks > 0:
            with self._lock:
                self.score       = max(self.score * (self.SCORE_BLEED ** ticks), self.SCORE_MIN)
                self._last_bleed = now

    def reward(self, latency_ms: float):
        """Latency-aware reward. Fast = +pts, slow (>1000ms) = negative pts."""
        self._apply_bleed()
        raw = self.REWARD_MAX - (latency_ms / self.LATENCY_SCALE)
        pts = max(self.REWARD_FLOOR, min(self.REWARD_MAX, raw))
        with self._lock:
            self.score        = min(max(self.score + pts, self.SCORE_MIN), self.SCORE_MAX)
            self._consec_fail = 0
            if self._cb_until > 0:
                # Gradual half-open: only fully close after CB_PROBES clean calls
                self._half_probes += 1
                if self._half_probes >= self.CB_PROBES:
                    self._cb_until    = 0
                    self._half_probes = 0
                    log.info(f'[circuit CLOSED] {self.url[:50]}')
        self.metrics.record(latency_ms, ok=True)

    def penalize(self, latency_ms: float, penalty: int):
        """Apply a specific penalty and trip circuit after CB_THRESHOLD failures."""
        self._apply_bleed()
        with self._lock:
            self.score        = max(self.score - penalty, self.SCORE_MIN)
            self._consec_fail += 1
            self._half_probes  = 0   # reset half-open progress on any fail
            if self._consec_fail >= self.CB_THRESHOLD:
                self._cb_until = time.time() + self.CB_PAUSE_SECS
                log.warning(f'[circuit TRIPPED] {self.url[:50]} — paused {self.CB_PAUSE_SECS}s')
        self.metrics.record(latency_ms, ok=False)

    def __repr__(self):
        state = 'OPEN' if self.is_circuit_open else ('HALF' if self._is_half_open else 'OK')
        return (f'<RPC {self.url[:42]} score={self.score:.0f} '
                f'w={self.dynamic_weight:.2f} ok={self.metrics.success} '
                f'fail={self.metrics.fail} ema={self.metrics.ema_ms:.0f}ms [{state}]>')


# ── Provider registry ──────────────────────────────────────────────────────────

class _ChainRegistry:
    def __init__(self):
        self._chains: dict[str, list[_RPCProvider]] = {}
        self._lock   = threading.Lock()

    def _providers(self, chain: str) -> list[_RPCProvider]:
        with self._lock:
            if chain not in self._chains:
                self._chains[chain] = _build_providers(chain)
            return self._chains[chain]

    def sorted_providers(self, chain: str) -> list[_RPCProvider]:
        """Sort by dynamic_weight descending; circuit-open providers are pushed last."""
        providers = self._providers(chain)
        return sorted(providers,
                      key=lambda p: (-1e9 if p.is_circuit_open else p.dynamic_weight),
                      reverse=True)

    def log_state(self, chain: str):
        for p in self._providers(chain):
            log.debug(f'  {p}')


_registry = _ChainRegistry()

# ── Public fallback endpoints ──────────────────────────────────────────────────

# ── Private endpoints from environment (audit-fixes) ─────────────────────────
# SECURITY: a live QuickNode BSC API token was previously hardcoded in the
# 'bsc' list below. Private endpoints now come from the environment only —
# never commit tokens to source.
load_dotenv()
_BSC_QUICKNODE_URL = (os.environ.get('BSC_QUICKNODE_URL') or '').strip()

_PUBLIC: dict[str, list[tuple[str, int]]] = {
    # ── Ethereum ───────────────────────────────────────────────────────────────
    # NOTE: debug_traceTransaction requires an archive+trace node.
    # Free options that support it:
    #   - Alchemy free tier:  https://eth-mainnet.g.alchemy.com/v2/<key>
    #   - Ankr with API key:  https://rpc.ankr.com/eth/<key>
    # Public nodes below handle eth_getTransactionReceipt & basic calls,
    # but will fail on debug_traceTransaction. Set ETH_RPC_URL in .env for traces.
    'eth': [
        ('https://eth.llamarpc.com',                  80),  # standard calls only
        ('https://rpc.ankr.com/eth',                  75),  # trace: needs API key
        ('https://ethereum.publicnode.com',            70),  # standard calls only
        ('https://cloudflare-eth.com',                65),  # standard calls only
    ],
    # ── BNB Smart Chain ────────────────────────────────────────────────────────
    # BSC public nodes do NOT support debug_traceTransaction.
    # For BSC tracing, set BSC_RPC_URL in .env to:
    #   - Alchemy BSC: https://bnb-mainnet.g.alchemy.com/v2/<key>
    #   - Ankr with key: https://rpc.ankr.com/bsc/<key>
    'bsc': [
        # Private QuickNode endpoint (trace-capable). Set BSC_QUICKNODE_URL
        # in .env — see .env.example. Omitted when unset.
        *([(_BSC_QUICKNODE_URL, 85)] if _BSC_QUICKNODE_URL else []),
        ('https://bsc-dataseed1.binance.org',         68),
        ('https://bsc-dataseed2.binance.org',         65),
        ('https://bsc-dataseed1.defibit.io',          62),
        ('https://rpc.ankr.com/bsc',                  58),  # trace: needs API key
    ],
    # ── Polygon PoS ────────────────────────────────────────────────────────────
    'polygon': [
        ('https://polygon-rpc.com',                   75),
        ('https://rpc.ankr.com/polygon',              70),
        ('https://polygon.llamarpc.com',              65),
        ('https://polygon-bor-rpc.publicnode.com',    60),
    ],
    # ── Arbitrum One ───────────────────────────────────────────────────────────
    'arbitrum': [
        ('https://arb1.arbitrum.io/rpc',              80),
        ('https://rpc.ankr.com/arbitrum',             70),
        ('https://arbitrum.llamarpc.com',             65),
    ],
    # ── Optimism ───────────────────────────────────────────────────────────────
    'optimism': [
        ('https://mainnet.optimism.io',               80),
        ('https://rpc.ankr.com/optimism',             70),
        ('https://optimism.llamarpc.com',             65),
    ],
    # ── Avalanche C-Chain ──────────────────────────────────────────────────────
    'avalanche': [
        ('https://api.avax.network/ext/bc/C/rpc',     80),
        ('https://rpc.ankr.com/avalanche',            70),
        ('https://avalanche.public-rpc.com',          60),
    ],
    # ── Base ───────────────────────────────────────────────────────────────────
    'base': [
        ('https://mainnet.base.org',                  80),
        ('https://rpc.ankr.com/base',                 70),
        ('https://base.llamarpc.com',                 65),
    ],
    # ── Fantom ─────────────────────────────────────────────────────────────────
    'fantom': [
        ('https://rpc.ftm.tools',                     75),
        ('https://rpc.ankr.com/fantom',               70),
        ('https://fantom.public-rpc.com',             60),
    ],
    # ── zkSync Era ─────────────────────────────────────────────────────────────
    'zksync': [
        ('https://mainnet.era.zksync.io',             80),
        ('https://rpc.ankr.com/zksync_era',           70),
        ('https://zksync.meowrpc.com',                60),
    ],
    # ── Linea ──────────────────────────────────────────────────────────────────
    'linea': [
        ('https://rpc.linea.build',                   80),
        ('https://linea.blockpi.network/v1/rpc/public', 65),
        ('https://linea.decubate.com',                60),
    ],
    # ── Scroll ─────────────────────────────────────────────────────────────────
    'scroll': [
        ('https://rpc.scroll.io',                     80),
        ('https://rpc.ankr.com/scroll',               70),
        ('https://scroll-mainnet.public.blastapi.io', 60),
    ],
    # ── Gnosis (xDai) ──────────────────────────────────────────────────────────
    'gnosis': [
        ('https://rpc.gnosischain.com',               80),
        ('https://rpc.ankr.com/gnosis',               70),
        ('https://gnosis.llamarpc.com',               65),
    ],
    # ── Celo ───────────────────────────────────────────────────────────────────
    'celo': [
        ('https://forno.celo.org',                    80),
        ('https://rpc.ankr.com/celo',                 70),
    ],
    # ── Cronos ─────────────────────────────────────────────────────────────────
    'cronos': [
        ('https://evm.cronos.org',                    80),
        ('https://cronos-evm-rpc.publicnode.com',     65),
    ],
    # ── Moonbeam ───────────────────────────────────────────────────────────────
    'moonbeam': [
        ('https://rpc.api.moonbeam.network',          80),
        ('https://moonbeam.public.blastapi.io',       65),
    ],
    # ── Aurora (NEAR EVM) ──────────────────────────────────────────────────────
    'aurora': [
        ('https://mainnet.aurora.dev',                80),
    ],
}

_ALIASES = {
    'ethereum': 'eth',  'bnb': 'bsc',
    'poly': 'polygon',  'arb': 'arbitrum',
    'op': 'optimism',   'avax': 'avalanche',
    'ftm': 'fantom',    'xdai': 'gnosis',
    'zkevm': 'polygon', 'era': 'zksync',
}


def _canonical(chain: str) -> str:
    return _ALIASES.get(chain.lower(), chain.lower())


def _build_providers(chain: str) -> list[_RPCProvider]:
    providers = []
    key = chain.upper().replace('-', '_')
    for suffix in ['_RPC_URL', '_RPC_URL_2', '_RPC_URL_3', '_RPC_URL_4']:
        url = os.getenv(f'{key}{suffix}', '').strip()
        if url:
            providers.append(_RPCProvider(url, initial_score=95))

    # Tenderly — free tier supports debug_traceTransaction
    # Set TENDERLY_RPC_URL in .env (Dashboard -> Web3 Gateway -> Mainnet -> Copy URL)
    if chain == 'eth':
        tenderly_url = os.getenv('TENDERLY_RPC_URL', '').strip()
        if tenderly_url:
            if not any(p.url == tenderly_url for p in providers):
                providers.append(_RPCProvider(tenderly_url, initial_score=97))  # highest: trace-capable
                log.debug(f'[tenderly] Registered trace-capable provider for eth')

    for url, score in _PUBLIC.get(chain, []):
        if not any(p.url == url for p in providers):
            providers.append(_RPCProvider(url, initial_score=score))
    return providers

# ── HTTP error classification ──────────────────────────────────────────────────

class _AuthError(Exception):
    pass

class _RateLimitError(Exception):
    pass

class _ServerError(Exception):
    pass


def _http_post(url: str, body: bytes, timeout: int = 5) -> Any:
    """Raw HTTP POST. Raises typed errors for 429, 5xx, 401/403."""
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise _RateLimitError(f'HTTP 429 rate limit')
        if e.code in (401, 403):
            raise _AuthError(f'HTTP {e.code} auth error')
        if e.code >= 500:
            raise _ServerError(f'HTTP {e.code} server error')
        raise


def _check_rpc_error(data: dict) -> Any:
    """Extract result or raise typed error for RPC-level errors."""
    if 'error' in data:
        msg = data['error'].get('message', str(data['error']))
        if any(w in msg.lower() for w in ('unauthorized', 'api key', 'authenticate', 'forbidden')):
            raise _AuthError(msg)
        if 'rate' in msg.lower() or '429' in msg:
            raise _RateLimitError(msg)
        raise RuntimeError(f'RPC error: {msg}')
    return data.get('result')


def _penalty_for(exc: Exception) -> int:
    """Map exception type to penalty points."""
    if isinstance(exc, _AuthError):
        return _RPCProvider.PENALTY_AUTH
    if isinstance(exc, _RateLimitError):
        return _RPCProvider.PENALTY_429
    if isinstance(exc, (_ServerError,)):
        return _RPCProvider.PENALTY_5XX
    if isinstance(exc, TimeoutError):
        return _RPCProvider.PENALTY_TIMEOUT
    return _RPCProvider.PENALTY_5XX   # catch-all

# ── Core: per-call failover with adaptive timeout ──────────────────────────────

MAX_BATCH_SIZE = 20

def rpc_call(chain: str, method: str, params: list,
             cacheable: bool = False,
             timeout: int | None = None) -> Any:
    """
    Execute a JSON-RPC call across providers sorted by dynamic_weight.
    Each provider uses its own adaptive_timeout unless overridden.
    """
    canonical = _canonical(chain)
    cache_key = f'{canonical}:{method}:{json.dumps(params, sort_keys=True)}'

    if cacheable:
        hit, val = _cache.get(cache_key)
        if hit:
            log.debug(f'[cache HIT] {cache_key[:80]}')
            return val

    providers = _registry.sorted_providers(canonical)
    if not providers:
        raise RuntimeError(f'No RPC providers for chain: {chain}')

    last_err = None
    for provider in providers:
        if provider.is_circuit_open:
            log.debug(f'[circuit SKIP] {provider.url[:50]}')
            continue

        t_out = timeout or provider.adaptive_timeout
        t0    = time.time()
        try:
            body   = json.dumps({'jsonrpc': '2.0', 'method': method,
                                  'params': params, 'id': 1}).encode()
            data   = _http_post(provider.url, body, timeout=t_out)
            result = _check_rpc_error(data)
            ms     = (time.time() - t0) * 1000
            log.debug(f'[rpc OK] {provider.url[:42]} {method} {ms:.0f}ms')
            provider.reward(ms)
            if cacheable:
                _cache.set(cache_key, result)
            return result

        except Exception as exc:
            ms      = (time.time() - t0) * 1000
            penalty = _penalty_for(exc)
            log.warning(f'[rpc FAIL +{penalty}] {provider.url[:42]} {method}: {exc} ({ms:.0f}ms)')
            provider.penalize(ms, penalty)
            last_err = exc

    _registry.log_state(canonical)
    raise RuntimeError(f'All providers failed for {chain}:{method}. Last: {last_err}')


# ── Batch with per-call fallback on chunk failure ──────────────────────────────

def rpc_batch(chain: str,
              calls: list[tuple[str, list]],
              cacheable: bool = False,
              timeout: int = 30) -> list[Any]:
    """
    Batch JSON-RPC call. Chunked at MAX_BATCH_SIZE.
    If a chunk fails on all providers, falls back to individual rpc_call() per item.
    """
    canonical = _canonical(chain)
    results   = [None] * len(calls)
    uncached: list[tuple[int, str, list]] = []

    for i, (method, params) in enumerate(calls):
        if cacheable:
            key = f'{canonical}:{method}:{json.dumps(params, sort_keys=True)}'
            hit, val = _cache.get(key)
            if hit:
                results[i] = val
                continue
        uncached.append((i, method, params))

    if not uncached:
        return results

    chunks = [uncached[i:i + MAX_BATCH_SIZE]
              for i in range(0, len(uncached), MAX_BATCH_SIZE)]

    for chunk in chunks:
        payload  = json.dumps([
            {'jsonrpc': '2.0', 'method': m, 'params': p, 'id': orig_i}
            for orig_i, m, p in chunk
        ]).encode()
        sent = False

        for provider in _registry.sorted_providers(canonical):
            if provider.is_circuit_open:
                continue
            t_out = timeout
            t0    = time.time()
            try:
                data = _http_post(provider.url, payload, timeout=t_out)
                ms   = (time.time() - t0) * 1000
                if not isinstance(data, list):
                    raise RuntimeError(f'Expected list, got {type(data)}')
                id_map = {item['id']: item for item in data}
                for orig_i, method, params in chunk:
                    item   = id_map.get(orig_i, {})
                    result = _check_rpc_error(item)
                    results[orig_i] = result
                    if cacheable:
                        key = f'{canonical}:{method}:{json.dumps(params, sort_keys=True)}'
                        _cache.set(key, result)
                log.debug(f'[batch OK] {provider.url[:42]} chunk={len(chunk)} {ms:.0f}ms')
                provider.reward(ms)
                sent = True
                break
            except Exception as exc:
                ms      = (time.time() - t0) * 1000
                penalty = _penalty_for(exc)
                provider.penalize(ms, penalty)
                log.warning(f'[batch FAIL] {provider.url[:42]}: {exc} ({ms:.0f}ms)')

        if not sent:
            # ── Per-call fallback — batch failed, retry each call individually ──
            log.warning(f'[batch FALLBACK] chunk of {len(chunk)} failing on all providers — retrying individually')
            for orig_i, method, params in chunk:
                try:
                    results[orig_i] = rpc_call(chain, method, params,
                                                cacheable=cacheable)
                except Exception as exc:
                    log.warning(f'[fallback FAIL] {method}: {exc}')
                    results[orig_i] = None

    return results

# ── Trace capability probe ────────────────────────────────────────────────────

# Multiple known mainnet txs with internal calls — probe tries each in order
# so a pruned or rate-limited tx doesn't falsely report no support.
_PROBE_TXS: dict[str, list[str]] = {
    'eth': [
        '0x90b468608fbcc7faef46502b198471311baca3baab49242a4a85b73d4924379b',  # Arbitrary External Call, depth 4
        '0x23fcf9d4517f7cc39815b09b0a80c023ab2c8196c826c93b4100f2e26b701286',  # Arbitrary External Call, 6 calls
        '0xd4fafa1261f6e4f9c8543228a67caf9d02811e4ad3058a2714323964a8db61f6',  # Reentrancy pattern
    ],
    'bsc': [
        '0xbea605b238c85aabe5edc636219155d8c4879d6b05c48091cf1f7286bd4702ba',  # Access Control
        '0x0237855c63eb85c5f437fba5267cc869a08c58a49501e3e5ebec9990bdd97565',  # Inflation Attack
    ],
}

# Provider capability cache — stored on disk so we don't probe every startup
_PROBE_CACHE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    'data', 'cache', 'trace_provider.json'
)
_PROBE_CACHE_TTL = 86_400  # 24 hours


def _load_probe_cache(chain: str) -> str | None:
    """Return cached working provider URL if fresh, else None."""
    try:
        if not os.path.exists(_PROBE_CACHE_PATH):
            return None
        data = json.load(open(_PROBE_CACHE_PATH))
        entry = data.get(chain, {})
        if time.time() - entry.get('ts', 0) < _PROBE_CACHE_TTL:
            url = entry.get('url')
            if url:
                log.debug(f'[probe cache HIT] {chain} → {url[:50]}')
                return url
    except Exception:
        pass
    return None


def _save_probe_cache(chain: str, url: str):
    """Persist working provider URL to disk."""
    try:
        os.makedirs(os.path.dirname(_PROBE_CACHE_PATH), exist_ok=True)
        data = json.load(open(_PROBE_CACHE_PATH)) if os.path.exists(_PROBE_CACHE_PATH) else {}
        data[chain] = {'url': url, 'ts': time.time()}
        with open(_PROBE_CACHE_PATH, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        log.debug(f'[probe cache WRITE FAIL] {e}')


def build_parity_tree(trace_list: list) -> dict:
    """
    Reconstruct a nested call tree from Erigon's flat parity trace format.

    Erigon's trace_replayTransaction returns a flat list like:
        [{traceAddress: [],    type: 'call', action: {...}},  # root
         {traceAddress: [0],  type: 'call', action: {...}},  # child of root
         {traceAddress: [0,0],type: 'call', action: {...}},  # grandchild
         {traceAddress: [1],  type: 'call', action: {...}}]  # sibling of [0]

    The 'subtraces' field is an INTEGER count, not a list of children.
    Correct nesting requires traceAddress-based tree reconstruction.
    """
    if not trace_list:
        return {}

    # Index nodes by their traceAddress tuple
    nodes: dict[tuple, dict] = {}
    roots: list[dict] = []
    
    for item in trace_list:
        addr = tuple(item.get('traceAddress', []))
        action = item.get('action', {})
        node = {
            'call_type': item.get('type', 'call').upper(),
            'to':        action.get('to', action.get('init', '')),
            'from':      action.get('from', ''),
            'input':     action.get('input', '0x'),
            'children':  [],
            '_addr':     addr,
        }
        
        if len(addr) == 0:
            roots.append(node)
            nodes[addr] = node  # Map () to last seen root for children attachment
        else:
            nodes[addr] = node

    # Attach each node to its parent
    for addr, node in sorted(nodes.items(), key=lambda x: len(x[0])):
        if len(addr) == 0:
            continue
            
        parent_addr = addr[:-1]
        parent = nodes.get(parent_addr)
        if parent is not None:
            parent['children'].append(node)

    if not roots:
        return {}
    if len(roots) == 1:
        return roots[0]
        
    # Return synthetic root if multiple top-level actions exist (suicides, multi-calls)
    return {
        'call_type': 'CALL',
        'to': roots[0].get('to', ''),
        'from': roots[0].get('from', ''),
        'input': '0x',
        'children': roots
    }


def _normalize_word_hex(value: Any) -> str | None:
    """Normalize a stack/storage word to 32-byte lowercase hex."""
    if value is None:
        return None
    raw = str(value).strip().lower()
    if not raw:
        return None
    if raw.startswith('0x'):
        raw = raw[2:]
    if not raw:
        raw = '0'
    try:
        int(raw, 16)
    except ValueError:
        return None
    return '0x' + raw[-64:].zfill(64)


def _normalize_address_hex(value: Any) -> str | None:
    """Normalize a stack word / raw address to a 20-byte lowercase address."""
    word = _normalize_word_hex(value)
    if not word:
        return None
    return '0x' + word[-40:]


def _trace_success(node: dict) -> bool:
    """Best-effort success bit across geth / Tenderly / parity variants."""
    if node.get('error'):
        return False
    if node.get('reverted') is True:
        return False
    if node.get('failed') is True:
        return False
    result = node.get('result')
    if isinstance(result, dict) and result.get('error'):
        return False
    return True


def normalize_trace_node(node: dict, depth: int = 0, call_id: str = '0') -> dict:
    """
    Normalize a callTracer JSON node to a canonical schema regardless of provider.

    Handles three known variants:
      - geth/debug:   type, from, to, calls[]              (standard)
      - Tenderly:     callType, caller, callee, children[]  (sometimes)
      - Erigon parity single node: action{}, subtraces INT  (per-item from trace list)

    For the full Erigon flat array format, call build_parity_tree(trace_list) first.

    Returns a dict with canonical fields:
      - call_type: str (always uppercase, e.g. 'CALL', 'DELEGATECALL')
      - to:        str
      - children:  list[dict] (recursively normalized)
    """
    if not node or not isinstance(node, dict):
        return {}

    # Erigon parity single-node format (action dict present, no calls/children)
    # subtraces here is an INTEGER count — children come from the flat list
    # caller should use build_parity_tree() for the full list; this path
    # handles a single pre-extracted node with already-attached children.
    if 'action' in node:
        action   = node.get('action', {})
        raw_type = node.get('type', 'call')
        # 'children' may already be attached if this came from build_parity_tree
        children = [
            normalize_trace_node(child, depth + 1, f'{call_id}.{idx}')
            for idx, child in enumerate(node.get('children', []))
        ]
        input_data = action.get('input', '0x') or '0x'
        callee = action.get('to', action.get('init', ''))
        caller = action.get('from', '')
        return_data = (
            node.get('output')
            or (node.get('result') or {}).get('output')
            or '0x'
        )
        return {
            'call_id':   call_id,
            'depth':     depth,
            'caller':    caller,
            'callee':    callee,
            'function_selector': input_data[:10] if len(input_data) >= 10 else '0x',
            'input':     input_data,
            'value':     action.get('value', '0x0'),
            'gas':       action.get('gas', node.get('gas')),
            'call_type': raw_type.upper(),
            'success':   _trace_success(node),
            'return_data': return_data,
            'storage_writes': [],
            'children':  children,
            # Compatibility aliases for legacy downstream code.
            'to':        callee,
            'from':      caller,
        }

    # Tenderly / children variant (also used by internal TraceNode.to_dict())
    if 'children' in node and 'calls' not in node:
        raw_type = (node.get('callType') or node.get('type') or 'call')
        children = [
            normalize_trace_node(child, depth + 1, f'{call_id}.{idx}')
            for idx, child in enumerate(node.get('children', []))
        ]
        input_data = node.get('input', '0x') or '0x'
        callee = node.get('callee') or node.get('to', '')
        caller = node.get('caller') or node.get('from', '')
        return {
            'call_id':   call_id,
            'depth':     depth,
            'caller':    caller,
            'callee':    callee,
            'function_selector': input_data[:10] if len(input_data) >= 10 else '0x',
            'input':     input_data,
            'value':     node.get('value', '0x0'),
            'gas':       node.get('gas'),
            'call_type': raw_type.upper(),
            'success':   _trace_success(node),
            'return_data': node.get('output', '0x'),
            'storage_writes': [],
            'children':  children,
            'to':        callee,
            'from':      caller,
        }

    # Standard geth callTracer (most common)
    raw_type = (node.get('type') or node.get('callType') or 'CALL')
    children = [
        normalize_trace_node(child, depth + 1, f'{call_id}.{idx}')
        for idx, child in enumerate(node.get('calls', []))
    ]
    input_data = node.get('input', '0x') or '0x'
    callee = node.get('to', '')
    caller = node.get('from', '')
    return {
        'call_id':   call_id,
        'depth':     depth,
        'caller':    caller,
        'callee':    callee,
        'function_selector': input_data[:10] if len(input_data) >= 10 else '0x',
        'input':     input_data,
        'value':     node.get('value', '0x0'),
        'gas':       node.get('gas'),
        'call_type': raw_type.upper(),
        'success':   _trace_success(node),
        'return_data': node.get('output', '0x'),
        'storage_writes': [],
        'children':  children,
        'to':        callee,
        'from':      caller,
    }


def extract_storage_writes_from_struct_logs(struct_logs: list[dict], root_trace: dict | None = None) -> list[dict]:
    """
    Build canonical SSTORE events from opcode logs.

    Output shape:
      {
        address, slot, value_before, value_after, pc, depth,
        event_index, after_external_call
      }
    """
    if not struct_logs:
        return []

    root_addr = ''
    if isinstance(root_trace, dict):
        root_addr = (
            root_trace.get('callee')
            or root_trace.get('to')
            or root_trace.get('address')
            or ''
        ).lower()
    if not root_addr:
        return []

    call_ops = {'CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'}
    mutating_call_ops = {'CALL', 'CALLCODE', 'DELEGATECALL'}

    address_stack: list[str] = [root_addr]
    call_id_stack: list[str] = ['0']
    child_counters: list[int] = [0]
    after_external_stack: list[bool] = [False]
    events: list[dict] = []

    for idx, entry in enumerate(struct_logs):
        op = (entry.get('op') or '').upper()
        try:
            depth = max(int(entry.get('depth', 1)), 1)
        except (TypeError, ValueError):
            depth = max(len(address_stack), 1)

        while len(address_stack) > depth:
            address_stack.pop()
            call_id_stack.pop()
            child_counters.pop()
            after_external_stack.pop()
        while len(address_stack) < depth:
            address_stack.append(address_stack[-1])
            call_id_stack.append(call_id_stack[-1])
            child_counters.append(0)
            after_external_stack.append(False)

        current_address = address_stack[-1]
        current_call_id = call_id_stack[-1]
        stack = entry.get('stack') or []

        if op == 'SSTORE':
            slot = _normalize_word_hex(stack[-1] if len(stack) >= 1 else None)
            value_after = _normalize_word_hex(stack[-2] if len(stack) >= 2 else None)

            storage_map = entry.get('storage') or {}
            value_before = None
            if slot and isinstance(storage_map, dict):
                value_before = (
                    storage_map.get(slot)
                    or storage_map.get(slot[2:])
                    or storage_map.get(slot.lower())
                    or storage_map.get(slot[2:].lower())
                )
                value_before = _normalize_word_hex(value_before)

            if slot:
                events.append({
                    'op': 'SSTORE',
                    'address': current_address,
                    'slot': slot,
                    'value_before': value_before,
                    'value_after': value_after,
                    'pc': entry.get('pc'),
                    'depth': depth,
                    'call_id': current_call_id,
                    'event_index': idx,
                    'after_external_call': bool(after_external_stack[-1]),
                })

        # SLOAD extraction (audit-fixes): the replay stage advertises
        # "SSTORE/SLOAD events" — previously only SSTORE was captured.
        # SLOADs carry no value_after; consumers that need writes must
        # filter on op == 'SSTORE'.
        if op == 'SLOAD':
            slot = _normalize_word_hex(stack[-1] if len(stack) >= 1 else None)
            if slot:
                events.append({
                    'op': 'SLOAD',
                    'address': current_address,
                    'slot': slot,
                    'value_before': None,
                    'value_after': None,
                    'pc': entry.get('pc'),
                    'depth': depth,
                    'call_id': current_call_id,
                    'event_index': idx,
                    'after_external_call': bool(after_external_stack[-1]),
                })

        next_depth = depth
        if idx + 1 < len(struct_logs):
            try:
                next_depth = max(int(struct_logs[idx + 1].get('depth', depth)), 1)
            except (TypeError, ValueError):
                next_depth = depth

        if op in call_ops and next_depth > depth:
            target_addr = current_address
            if op not in {'DELEGATECALL', 'CALLCODE'}:
                target_addr = _normalize_address_hex(stack[-2] if len(stack) >= 2 else None) or current_address

            is_external_boundary = op in {'DELEGATECALL', 'CALLCODE'} or target_addr.lower() != current_address.lower()
            if op in mutating_call_ops and is_external_boundary:
                after_external_stack[-1] = True

            parent_call_id = call_id_stack[-1]
            child_index = child_counters[-1]
            child_counters[-1] += 1
            address_stack.append(target_addr.lower())
            call_id_stack.append(f'{parent_call_id}.{child_index}')
            child_counters.append(0)
            after_external_stack.append(False)

    return events


def _sanity_check_trace(result: dict) -> tuple[bool, int, int, set]:
    """
    Validate a callTracer trace is non-trivial after normalization.
    Returns (ok, max_depth, call_count, call_types).

    Fails on:
    - empty / non-dict result
    - depth == 0 and call_count == 1 (root-only, no internal calls)
    - depth >= call_count (flat / incorrectly reconstructed tree)
    """
    if not result or not isinstance(result, dict):
        return False, 0, 0, set()

    normalized = normalize_trace_node(result)

    def _walk(node, depth=0):
        children = node.get('children', [])
        ct       = node.get('call_type', 'CALL')
        max_d    = depth
        count    = 1
        types    = {ct}
        for child in children:
            _, cd, cc, ct_set = _walk(child, depth + 1)
            max_d  = max(max_d, cd)
            count += cc
            types |= ct_set
        return True, max_d, count, types

    ok, max_depth, call_count, call_types = _walk(normalized)
    sane = ok and (max_depth > 0 or call_count > 1)

    # Bad nesting guard: flat traces have depth ≈ call_count (each call is a root)
    if sane and max_depth >= call_count and call_count > 3:
        log.warning(f'[sanity] depth={max_depth} >= calls={call_count} — likely flat/incorrectly nested trace')
        sane = False

    return sane, max_depth, call_count, call_types


def probe_trace_support(chain: str, force: bool = False) -> str | None:
    """
    Probe providers for debug_traceTransaction support.
    Returns the first URL that responds with a SANE trace, or None.

    Features:
    - Multi-tx fallback: tries several known txs so a pruned hash doesn't break probe
    - Sanity check: validates call depth > 0 and nested calls exist (not empty response)
    - Scoring: rewards working providers, penalizes failures
    - 24h disk cache: avoids re-probing on every run

    Args:
        chain: Chain identifier (eth, bsc, etc.)
        force: If True, skip the cache and re-probe all providers
    """
    canonical = _canonical(chain)

    if not force:
        cached = _load_probe_cache(canonical)
        if cached:
            return cached

    probe_txs = _PROBE_TXS.get(canonical, [])
    if not probe_txs:
        return None

    tracer_config = {'tracer': 'callTracer', 'timeout': '8s'}

    for provider in _registry.sorted_providers(canonical):
        if provider.is_circuit_open:
            continue

        for test_tx in probe_txs:
            body = json.dumps({
                'jsonrpc': '2.0',
                'method':  'debug_traceTransaction',
                'params':  [test_tx, tracer_config],
                'id': 1,
            }).encode()

            t0 = time.time()
            try:
                data   = _http_post(provider.url, body, timeout=8)
                result = _check_rpc_error(data)
                ms     = (time.time() - t0) * 1000

                sane, max_depth, call_count, call_types = _sanity_check_trace(result)
                if not sane:
                    log.warning(f'[probe EMPTY] {provider.url[:50]} returned empty/trivial trace for {test_tx[:16]}')
                    provider.penalize(ms, 15)  # empty trace = worse than error
                    continue

                # Valid trace confirmed — reward and cache
                provider.reward(ms)
                log.info(f'[probe OK] {provider.url[:50]} depth={max_depth} calls={call_count} types={call_types}')
                print(f'      [trace probe] OK — {provider.url[:50]}')
                print(f'      [trace probe] calls={call_count}  depth={max_depth}  types={sorted(call_types)}')
                _save_probe_cache(canonical, provider.url)
                return provider.url

            except Exception as e:
                ms = (time.time() - t0) * 1000
                provider.penalize(ms, _penalty_for(e))
                log.debug(f'[probe FAIL] {provider.url[:50]} tx={test_tx[:16]}: {e}')
                break  # this provider failed — try next provider, not next tx

    print(f'      [trace probe] FAIL — no provider on {chain} supports debug_traceTransaction')
    return None



# ── Convenience helpers ────────────────────────────────────────────────────────

def get_rpc(chain: str) -> str:
    """Best available RPC URL (highest dynamic_weight, circuit closed)."""
    if chain.startswith('http'):
        return chain
    providers = _registry.sorted_providers(_canonical(chain))
    active = [p for p in providers if not p.is_circuit_open]
    return (active or providers)[0].url if (active or providers) else (_ for _ in ()).throw(RuntimeError(f'No RPC for {chain}'))


def get_all_rpcs(chain: str) -> list[str]:
    if chain.startswith('http'):
        return [chain]
    return [p.url for p in _registry.sorted_providers(_canonical(chain))]


def print_provider_stats(chain: str):
    providers = _registry.sorted_providers(_canonical(chain))
    print(f'\n  📊 RPC Provider stats — {chain.upper()}')
    print(f'  {"URL":<46} {"Score":>5}  {"Weight":>6}  {"OK":>4}  {"Fail":>4}  {"EMA ms":>7}  {"Rate":>5}  State')
    print(f'  {"-" * 96}')
    for p in providers:
        m     = p.metrics
        rate  = f'{m.success_rate*100:.0f}%' if m.total else 'N/A'
        state = '⛔ OPEN' if p.is_circuit_open else ('🟡 HALF' if p._is_half_open else '✅ OK')
        print(f'  {p.url[:46]:<46} {p.score:>5.0f}  {p.dynamic_weight:>6.3f}  '
              f'{m.success:>4}  {m.fail:>4}  {m.ema_ms:>7.0f}  {rate:>5}  {state}')


# ── retry_with_backoff (for non-RPC HTTP, e.g. explorer APIs) ─────────────────

def retry_with_backoff(fn, retries: int = 3, delay: float = 1.5, label: str = ''):
    last_exc = None
    for attempt in range(retries):
        try:
            return fn()
        except Exception as e:
            last_exc = e
            wait = delay * (2 ** attempt)
            tag  = f'[{label}] ' if label else ''
            print(f'      ↻ {tag}Retry {attempt+1}/{retries} failed ({e}), waiting {wait:.1f}s...')
            time.sleep(wait)
    raise last_exc


def cache_get(key: str):
    return _cache.get(key)


def cache_set(key: str, value: Any):
    _cache.set(key, value)
