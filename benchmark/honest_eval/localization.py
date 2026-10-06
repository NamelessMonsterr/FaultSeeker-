"""Fault-localization evaluation against the curated ground-truth corpus.

Each file in ``benchmark/ground_truth/*.json`` contains a ``location`` map of
the form::

    "location": {
      "0xd286...#StaxLPStaking.sol#241:3": [
        "0xd286...#StaxLPStaking#migrateStake",
        "0xd286...#StaxLPStaking#241:3"
      ]
    }

This gives genuine contract/function/line targets, enabling Top-k accuracy and
MRR -- the metrics that actually match the paper's localization thesis.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


def _keccak256(data: bytes) -> bytes:
    """Keccak-256 via pycryptodome, else pysha3.

    audit-fixes: the old code silently fell back to ``hashlib.sha3_256``,
    which is NIST SHA-3 — NOT Keccak-256 — and produced wrong function
    selectors. A wrong hash is worse than an error, so this now fails loudly
    instead of returning incorrect bytes. Install pycryptodome (it is in
    requirements.txt).
    """
    try:
        from Crypto.Hash import keccak as _keccak  # pycryptodome
        k = _keccak.new(digest_bits=256)
        k.update(data)
        return bytes.fromhex(k.hexdigest())
    except ImportError:
        pass
    try:
        import sha3 as _sha3  # pysha3
        k = _sha3.keccak_256()
        k.update(data)
        return k.digest()
    except ImportError:
        pass
    raise ImportError(
        "Keccak-256 requires pycryptodome (or pysha3): "
        "pip install pycryptodome. Refusing to fall back to hashlib.sha3_256, "
        "which computes NIST SHA-3, not Keccak-256, and would silently produce "
        "wrong function selectors."
    )


def _fn_selector(sig: str) -> str:
    """Return the 4-byte hex selector (with 0x prefix) for a Solidity function signature."""
    return "0x" + _keccak256(sig.encode()).hex()[:8]


# ---------------------------------------------------------------------------
# Selector <-> name resolution
# ---------------------------------------------------------------------------

# Global table built lazily from GT function names + 4byte.directory API cache.
# Maps lowercase 4-byte selector (e.g. '0xc554f632') -> set of norm_fn strings.
_SELECTOR_TO_NAMES: Dict[str, Set[str]] = {}

# Path to the pre-fetched 4byte.directory cache (populated by benchmark/fetch_selector_names.py)
_SELECTOR_CACHE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "models", "selector_cache.json",
)


def _load_api_selector_cache() -> None:
    """Load the 4byte.directory API cache into the global selector lookup table.

    This gives us real, authoritative function names for common DeFi selectors
    (e.g. 0x70a08231 -> balanceof) without any keccak approximation.
    Called once at module import time.
    """
    if not os.path.exists(_SELECTOR_CACHE_PATH):
        return
    try:
        with open(_SELECTOR_CACHE_PATH, encoding="utf-8") as fh:
            cache: Dict[str, str] = json.load(fh)
        for sel, name in cache.items():
            sel = sel.strip().lower()
            name = (name or "").strip().lower()
            if sel and name:
                _SELECTOR_TO_NAMES.setdefault(sel, set()).add(name)
    except (OSError, json.JSONDecodeError):
        pass


_load_api_selector_cache()  # populate on import


def _register_fn_names(names: Iterable[str]) -> None:
    """Populate the global reverse-lookup table with keccak selectors of known names.

    Solidity function selectors are computed from the canonical signature which
    preserves camelCase (e.g. ``extractReward`` not ``extractreward``).  We therefore
    generate selectors from the **original** casing of each name across common arities,
    then store the normalised (lowercase) version as the lookup result so it matches
    what ``_norm_fn`` produces from ground-truth entries.
    """
    for raw_name in names:
        norm = _norm_fn(raw_name)          # lowercase, no parens -> used as stored value
        original = str(raw_name or "").strip().split("(")[0]  # preserve camelCase -> used for keccak
        if not norm or not original:
            continue
        # Generate selectors for common arities using the ORIGINAL casing.
        for sig in (
            original,
            f"{original}()",
            f"{original}(uint256)",
            f"{original}(address)",
            f"{original}(address,uint256)",
            f"{original}(uint256,uint256)",
            f"{original}(address,address)",
            f"{original}(bytes)",
            f"{original}(bytes32)",
        ):
            sel = _fn_selector(sig)
            _SELECTOR_TO_NAMES.setdefault(sel, set()).add(norm)


def _selector_to_name(raw: str) -> Optional[str]:
    """Try to resolve a hex selector to a known function name.

    Returns the normalised function name or ``None`` if unknown.
    """
    low = str(raw or "").strip().lower()
    if not low.startswith("0x") or len(low) != 10:
        return None
    names = _SELECTOR_TO_NAMES.get(low)
    if names:
        # Prefer the shortest name (most likely canonical, e.g. 'transfer' over longer variants)
        return min(names, key=len)
    return None

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GROUND_TRUTH_DIR = os.path.join(ROOT, "benchmark", "ground_truth")


@dataclass
class LocalizationTarget:
    """Normalized ground-truth targets for one transaction."""

    txn_hash: str
    name: str = ""
    functions: Set[Tuple[str, str]] = field(default_factory=set)
    lines: Set[Tuple[str, str]] = field(default_factory=set)

    @property
    def is_empty(self) -> bool:
        return not self.functions and not self.lines


def _norm_addr(value: str) -> str:
    return str(value or "").strip().lower()


def _norm_fn(value: str) -> str:
    return str(value or "").strip().lower().split("(")[0]


def _parse_location_entry(entry: str) -> Optional[Tuple[str, str, bool]]:
    """Parse ``address#Contract#member`` -> (address, member, is_line)."""
    parts = [p for p in str(entry or "").split("#")]
    if len(parts) < 3:
        return None
    address = _norm_addr(parts[0])
    member = parts[-1].strip()
    if not address or not member:
        return None
    is_line = ":" in member and member.split(":")[0].strip().isdigit()
    if is_line:
        return (address, member.split(":")[0].strip(), True)
    return (address, _norm_fn(member), False)


def load_ground_truth(directory: str = GROUND_TRUTH_DIR) -> List[LocalizationTarget]:
    targets: List[LocalizationTarget] = []
    if not os.path.isdir(directory):
        return targets
    all_fn_names: List[str] = []
    for filename in sorted(os.listdir(directory)):
        if not filename.endswith(".json"):
            continue
        path = os.path.join(directory, filename)
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
        hashes = data.get("transaction_hash") or []
        if isinstance(hashes, str):
            hashes = [hashes]
        txn = _norm_addr(hashes[0]) if hashes else _norm_addr(filename[:-5])
        target = LocalizationTarget(txn_hash=txn, name=str(data.get("name") or ""))
        location = data.get("location") or {}
        if isinstance(location, dict):
            for key, values in location.items():
                for entry in [key] + list(values or []):
                    parsed = _parse_location_entry(entry)
                    if not parsed:
                        continue
                    address, member, is_line = parsed
                    if is_line:
                        target.lines.add((address, member))
                    else:
                        target.functions.add((address, member))
                        all_fn_names.append(member)
        if not target.is_empty:
            targets.append(target)
    # Build the global keccak reverse-lookup table from all known GT function names.
    # This is zero-leakage: we only use names, never addresses or locations.
    _register_fn_names(all_fn_names)
    return targets


def _prediction_keys(prediction: Dict[str, Any]) -> Tuple[Optional[Tuple[str, str]], Optional[Tuple[str, str]]]:
    address = _norm_addr(
        prediction.get("address")
        or prediction.get("contract")
        or prediction.get("callee")
        or ""
    )
    raw_fn = (
        prediction.get("function_name")  # enriched human-readable name (preferred)
        or prediction.get("name")
        or prediction.get("function")     # may be a 4-byte selector
        or ""
    )
    function = _norm_fn(raw_fn)
    # If function is a 4-byte hex selector, try resolving it to a human name.
    if function.startswith("0x") and len(function) == 10:
        resolved = _selector_to_name(function)
        if resolved:
            function = resolved
    line = prediction.get("line") or prediction.get("line_number")
    fn_key = (address, function) if address and function else None
    line_key = (address, str(line).strip()) if address and line not in (None, "") else None
    return fn_key, line_key


def rank_of_first_hit(
    target: LocalizationTarget,
    predictions: Sequence[Dict[str, Any]],
    match: str = "function",
) -> Optional[int]:
    """1-based rank of the first correct prediction, or ``None`` if absent."""
    for index, prediction in enumerate(predictions, start=1):
        fn_key, line_key = _prediction_keys(prediction)
        if match in ("function", "either") and fn_key and fn_key in target.functions:
            return index
        if match in ("line", "either") and line_key and line_key in target.lines:
            return index
    return None


def localization_metrics(
    targets: Iterable[LocalizationTarget],
    predictions_by_tx: Dict[str, Sequence[Dict[str, Any]]],
    provenance_by_tx: Optional[Dict[str, Dict[str, Any]]] = None,
    ks: Sequence[int] = (1, 3, 5, 10),
    match: str = "function",
) -> Dict[str, Any]:
    """Top-k accuracy and MRR over transactions that have valid predictions and trace_status == 'ok'."""
    targets = list(targets)
    evaluated = 0
    missing_predictions = 0
    excluded_unavailable_traces = 0
    excluded_error_traces = 0
    reciprocal_total = 0.0
    hits = {k: 0 for k in ks}

    for target in targets:
        predictions = predictions_by_tx.get(target.txn_hash)
        prov = (provenance_by_tx or {}).get(target.txn_hash, {})
        status = str(prov.get("trace_status") or "ok").strip()

        if predictions is None:
            missing_predictions += 1
            continue

        if status != "ok":
            if status == "TRACE_UNAVAILABLE":
                excluded_unavailable_traces += 1
            else:
                excluded_error_traces += 1
            continue

        evaluated += 1
        rank = rank_of_first_hit(target, predictions, match=match)
        if rank is not None:
            reciprocal_total += 1.0 / rank
            for k in ks:
                if rank <= k:
                    hits[k] += 1

    total_gt = len(targets)
    usable_trace_ratio = round(evaluated / total_gt, 4) if total_gt else 0.0

    result: Dict[str, Any] = {
        "ground_truth_transactions": total_gt,
        "evaluated": evaluated,
        "missing_predictions": missing_predictions,
        "excluded_unavailable_traces": excluded_unavailable_traces,
        "excluded_error_traces": excluded_error_traces,
        "usable_trace_ratio": usable_trace_ratio,
        "match_mode": match,
        "mrr": round(reciprocal_total / evaluated, 4) if evaluated else 0.0,
    }
    for k in ks:
        result[f"top_{k}_accuracy"] = (
            round(hits[k] / evaluated, 4) if evaluated else 0.0
        )
        result[f"top_{k}_hits"] = hits[k]

    if total_gt > 0 and usable_trace_ratio < 0.80:
        result["blocker"] = (
            f"INSUFFICIENT_TRACE_COVERAGE: usable trace ratio ({usable_trace_ratio * 100:.1f}%) "
            f"is below the required 80.0% threshold ({evaluated}/{total_gt} transactions with trace_status='ok'). "
            f"Excluded: {excluded_unavailable_traces} trace_unavailable, {excluded_error_traces} error, {missing_predictions} missing."
        )
    elif evaluated == 0:
        result["blocker"] = (
            "No valid pipeline predictions with trace_status='ok' were supplied."
        )

    return result


def load_predictions(directory: str) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, Dict[str, Any]]]:
    """Load ranked candidates from pipeline output JSON files with provenance verification.
    
    Returns (predictions_by_tx, provenance_by_tx). Only prediction files that contain
    valid ForensicsOrchestrator provenance are loaded.
    """
    predictions: Dict[str, List[Dict[str, Any]]] = {}
    provenance: Dict[str, Dict[str, Any]] = {}
    if not os.path.isdir(directory):
        return predictions, provenance
    for filename in sorted(os.listdir(directory)):
        if not filename.endswith(".json"):
            continue
        try:
            with open(os.path.join(directory, filename), encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
            
        prov = data.get("predictions_provenance") or data.get("_debug", {}).get("provenance")
        if not isinstance(prov, dict) or prov.get("producer") != "ForensicsOrchestrator":
            # Exclude files without valid ForensicsOrchestrator provenance
            continue
            
        txn = _norm_addr(
            data.get("transaction_hash") or data.get("txn_hash") or filename[:-5]
        )
        trace_status = str(
            data.get("trace_status") or prov.get("trace_status") or "ok"
        ).strip()
        prov["trace_status"] = trace_status

        ranked = (
            data.get("scored_functions")
            or data.get("ranked_candidates")
            or data.get("candidates")
            or []
        )
        if isinstance(ranked, list):
            predictions[txn] = [item for item in ranked if isinstance(item, dict)]
            provenance[txn] = prov
    return predictions, provenance
