import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List


ALGORITHM_NAME = "FAEGL"
ALGORITHM_VERSION = "1.0"


@dataclass
class FailureAwareDecision:
    algorithm: str = ALGORITHM_NAME
    version: str = ALGORITHM_VERSION
    activated: bool = False
    trigger: str = ""
    failure_severity: float = 0.0
    features: Dict[str, float] = field(default_factory=dict)
    fallback_utilities: Dict[str, float] = field(default_factory=dict)
    selected_modes: List[str] = field(default_factory=list)
    candidate_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "version": self.version,
            "activated": self.activated,
            "trigger": self.trigger,
            "failure_severity": self.failure_severity,
            "features": self.features,
            "fallback_utilities": self.fallback_utilities,
            "selected_modes": self.selected_modes,
            "candidate_count": self.candidate_count,
        }


class FailureAwareExploitGraphLocalizer:
    """
    Failure-Aware Exploit Graph Localization (FAEGL).

    FAEGL is a deterministic localization algorithm for transactions where the
    first-pass function selector pipeline fails or produces weak evidence. It
    estimates a failure severity score, computes graph/state/entropy features,
    chooses fallback modes by utility, and ranks trace-derived candidates.
    """

    MODE_THRESHOLD = 0.35

    def decide(
        self,
        functions_to_inspect: Dict[str, List[Dict[str, Any]]],
        tx_analysis: Dict[str, Any],
        token_filter_result: Dict[str, Any] | None = None,
        graph_metrics: Dict[str, Any] | None = None,
    ) -> FailureAwareDecision:
        before_count = self._count(functions_to_inspect)
        features = self.extract_features(tx_analysis, token_filter_result or {}, graph_metrics or {})
        failure_severity = self.failure_severity(before_count, features)
        utilities = self.fallback_utilities(failure_severity, features)
        if before_count == 0:
            utilities["graph_expansion"] = max(utilities.get("graph_expansion", 0.0), self.MODE_THRESHOLD)
        selected_modes = [mode for mode, utility in utilities.items() if utility >= self.MODE_THRESHOLD]
        activated = before_count == 0 and bool(selected_modes)
        return FailureAwareDecision(
            activated=activated,
            trigger="functions_to_inspect_count == 0" if before_count == 0 else "",
            failure_severity=failure_severity,
            features=features,
            fallback_utilities=utilities,
            selected_modes=selected_modes,
            candidate_count=before_count,
        )

    def rank_candidates(
        self,
        candidates: Iterable[Dict[str, Any]],
        features: Dict[str, float],
        address_scores: Dict[str, int] | None = None,
    ) -> List[Dict[str, Any]]:
        ranked = []
        address_scores = address_scores or {}
        for candidate in candidates:
            row = dict(candidate)
            address = str(row.get("address") or row.get("callee") or "").lower()
            call_type = str(row.get("call_type") or row.get("type") or "").lower()
            depth = self._to_float(row.get("depth", 0))
            address_prior = min(1.0, address_scores.get(address, 0) / 2.0)
            proxy_signal = 1.0 if call_type == "delegatecall" or row.get("proxy_unwrapped") else 0.0
            value_signal = 1.0 if row.get("value") not in (None, "", "0", "0x0", 0) else 0.0
            score = (
                0.24 * features.get("graph_anomaly", 0.0)
                + 0.18 * features.get("trace_entropy", 0.0)
                + 0.16 * features.get("state_delta", 0.0)
                + 0.14 * min(1.0, depth / 12.0)
                + 0.12 * features.get("token_flow_anomaly", 0.0)
                + 0.10 * proxy_signal
                + 0.04 * value_signal
                + 0.02 * address_prior
            )
            row["_faegl_score"] = round(min(1.0, score), 6)
            row["_adaptive_priority"] = row["_faegl_score"]
            row["_adaptive_fallback"] = True
            row["_adaptive_algorithm"] = f"{ALGORITHM_NAME}-v{ALGORITHM_VERSION}"
            ranked.append(row)
        return sorted(ranked, key=lambda item: (item.get("_faegl_score", 0.0), item.get("depth", 0)), reverse=True)

    def extract_features(
        self,
        tx_analysis: Dict[str, Any],
        token_filter_result: Dict[str, Any],
        graph_metrics: Dict[str, Any],
    ) -> Dict[str, float]:
        nodes = list(self._iter_trace_nodes(tx_analysis.get("trace", {})))
        nodes.extend(node for node in (tx_analysis.get("flatten_trace", []) or []) if isinstance(node, dict))
        storage_events = tx_analysis.get("storage_events") or []
        # Round2: storage events now carry op tags ('SSTORE' / 'SLOAD'; missing
        # ⇒ legacy SSTORE). state_delta measures WRITES — counting SLOAD reads
        # inflates it. Filter to SSTORE (backward compatible with op-less).
        write_events = [e for e in storage_events
                        if isinstance(e, dict) and str(e.get("op") or "SSTORE").upper() == "SSTORE"]
        token_edges = self._token_edges(tx_analysis, token_filter_result)
        max_depth = max([int(self._to_float(node.get("depth", 0))) for node in nodes] or [0])
        delegatecalls = sum(1 for node in nodes if str(node.get("call_type") or node.get("type") or "").lower() == "delegatecall")
        return {
            "trace_entropy": self._trace_entropy(nodes),
            "call_depth": round(min(1.0, max_depth / 16.0), 6),
            "state_delta": round(min(1.0, len(write_events) / 12.0), 6),
            "token_flow_anomaly": round(min(1.0, len(token_edges) / 10.0), 6),
            "delegatecall_density": round(min(1.0, delegatecalls / max(1, len(nodes))), 6),
            "graph_anomaly": round(float(graph_metrics.get("anomaly_score", 0.0) or 0.0), 6),
            "graph_cycles": round(min(1.0, float(graph_metrics.get("cycle_count", 0) or 0) / 4.0), 6),
        }

    @staticmethod
    def failure_severity(before_count: int, features: Dict[str, float]) -> float:
        zero_candidate = 1.0 if before_count == 0 else 0.0
        weak_graph = max(features.get("graph_anomaly", 0.0), features.get("trace_entropy", 0.0))
        state_or_flow = max(features.get("state_delta", 0.0), features.get("token_flow_anomaly", 0.0))
        severity = 0.58 * zero_candidate + 0.24 * weak_graph + 0.18 * state_or_flow
        return round(min(1.0, severity), 6)

    @staticmethod
    def fallback_utilities(failure_severity: float, features: Dict[str, float]) -> Dict[str, float]:
        utilities = {
            "entropy_trace_analysis": failure_severity * (0.45 + 0.55 * features.get("trace_entropy", 0.0)),
            "state_delta_reasoning": failure_severity * (0.35 + 0.65 * features.get("state_delta", 0.0)),
            "graph_expansion": failure_severity * (0.40 + 0.60 * features.get("graph_anomaly", 0.0)),
            "aggressive_call_depth_inspection": failure_severity * (0.35 + 0.65 * features.get("call_depth", 0.0)),
            "proxy_unwrapping": failure_severity * (0.35 + 0.65 * features.get("delegatecall_density", 0.0)),
        }
        return {key: round(min(1.0, value), 6) for key, value in utilities.items()}

    def _trace_entropy(self, nodes: List[Dict[str, Any]]) -> float:
        tokens = [
            str(node.get("function") or node.get("call_type") or node.get("type") or "unknown").lower()
            for node in nodes
            if isinstance(node, dict)
        ]
        if len(tokens) <= 1:
            return 0.0
        counts = Counter(tokens)
        entropy = -sum((count / len(tokens)) * math.log2(count / len(tokens)) for count in counts.values())
        max_entropy = math.log2(len(counts)) if len(counts) > 1 else 1.0
        return round(min(1.0, entropy / max_entropy), 6)

    def _iter_trace_nodes(self, node: Any, depth: int = 0) -> Iterable[Dict[str, Any]]:
        if isinstance(node, list):
            for child in node:
                yield from self._iter_trace_nodes(child, depth)
            return
        if not isinstance(node, dict):
            return
        current = dict(node)
        current.setdefault("depth", depth)
        yield current
        for child in node.get("children", []) or []:
            yield from self._iter_trace_nodes(child, depth + 1)

    @staticmethod
    def _token_edges(tx_analysis: Dict[str, Any], token_filter_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        for source in (tx_analysis, token_filter_result):
            token_transfer = source.get("token_transfer", {}) if isinstance(source, dict) else {}
            if isinstance(token_transfer, dict) and isinstance(token_transfer.get("edges"), list):
                return token_transfer["edges"]
        return []

    @staticmethod
    def _count(functions_to_inspect: Dict[str, List[Dict[str, Any]]]) -> int:
        return sum(len(value or []) for value in functions_to_inspect.values())

    @staticmethod
    def _to_float(value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0
