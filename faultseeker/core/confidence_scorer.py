"""
Confidence Scoring Engine for FaultSeeker++
Research Gap 4: No Confidence Scoring Mechanism

Computes composite confidence scores for fault localization predictions
using a multi-factor weighted formula:
    C(f) = 0.30 * PMS + 0.25 * CES + 0.25 * TCS + 0.20 * LCS

Factors:
    PMS - Pattern Match Score: similarity to known attack patterns
    CES - Code Evidence Score: source code availability and confirmation
    TCS - Transaction Consistency Score: consistency with fund flow anomalies
    LCS - LLM Confidence Score: normalized self-reported LLM confidence
"""

import logging
import copy
import math
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional


@dataclass
class ConfidenceScore:
    """Structured confidence score with component breakdown."""
    overall: float = 0.0
    level: str = "unknown"  # very_high, high, moderate, low, very_low

    # Component scores (0-1)
    pattern_match: float = 0.0
    code_evidence: float = 0.0
    txn_consistency: float = 0.0
    llm_confidence: float = 0.0

    # Explanation
    explanation: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'overall': round(self.overall, 4),
            'level': self.level,
            'components': {
                'pattern_match': round(self.pattern_match, 4),
                'code_evidence': round(self.code_evidence, 4),
                'txn_consistency': round(self.txn_consistency, 4),
                'llm_confidence': round(self.llm_confidence, 4),
            },
            'explanation': self.explanation,
        }


# Confidence level thresholds
CONFIDENCE_LEVELS = [
    (0.9, "very_high", "Immediate remediation recommended"),
    (0.7, "high", "Priority investigation warranted"),
    (0.5, "moderate", "Further analysis recommended"),
    (0.3, "low", "Review for false positive"),
    (0.0, "very_low", "Likely false positive"),
]

# Default weights (must sum to 1.0)
DEFAULT_WEIGHTS = {
    'pattern_match': 0.30,
    'code_evidence': 0.25,
    'txn_consistency': 0.25,
    'llm_confidence': 0.20,
}

# Known attack pattern keywords (expanded from 6 → 15 categories using DeFiHackLabs terminology)
ATTACK_PATTERNS = {
    'reentrancy': ['reentrancy', 'reenter', 'recursive', 'callback', 'nested call', 'fallback'],
    'flash_loan': ['flash loan', 'flashloan', 'borrow', 'atomic', 'flash borrow', 'uncollateralized'],
    'price_manipulation': ['price', 'oracle', 'manipulat', 'sandwich', 'slippage', 'twap', 'spot price'],
    'access_control': ['access', 'permission', 'onlyowner', 'auth', 'privilege', 'unauthorized', 'missing check'],
    'integer_overflow': ['overflow', 'underflow', 'arithmetic', 'unsafe math', 'unchecked', 'wrap around'],
    'logic_error': ['logic', 'business logic', 'state', 'validation', 'incorrect calculation', 'wrong assumption'],
    'governance_attack': ['governance', 'proposal', 'vote', 'quorum', 'timelock', 'delegate', 'snapshot'],
    'bridge_exploit': ['bridge', 'cross chain', 'crosschain', 'relay', 'message passing', 'mint without burn'],
    'donation_attack': ['donation', 'donate', 'direct transfer', 'force send', 'selfdestruct deposit'],
    'sandwich_attack': ['sandwich', 'front run', 'frontrun', 'back run', 'mev', 'mempool', 'slippage exploit'],
    'rugpull': ['rugpull', 'rug pull', 'drain', 'owner withdraw', 'admin key', 'mint unlimited', 'backdoor'],
    'signature_replay': ['signature', 'replay', 'ecrecover', 'permit', 'eip712', 'nonce', 'deadline'],
    'token_inflation': ['inflation', 'total supply', 'mint', 'rebase', 'elastic', 'share price manipulation'],
    'precision_loss': ['precision', 'truncation', 'rounding', 'division', 'decimal', 'dust'],
    'cross_contract': ['cross contract', 'delegate call', 'proxy', 'storage collision', 'implementation', 'upgrade'],
}


class ConfidenceScorer:
    """
    Multi-factor confidence scoring engine.

    Adapts designs from the Kimi Agent confidence engine and the user's
    research proposals, mapped to actual FaultSeeker data sources.
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.logger = logging.getLogger(__name__)
        self.weights = weights or DEFAULT_WEIGHTS.copy()

        # Validate weights sum to ~1.0
        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.01:
            self.logger.warning(f"Weights sum to {total}, normalizing")
            self.weights = {k: v / total for k, v in self.weights.items()}

    def score_function(
        self,
        func_data: Dict[str, Any],
        forensics_result: Dict[str, Any],
        contract_info: Optional[Dict[str, Any]] = None,
    ) -> ConfidenceScore:
        """
        Compute confidence score for a single vulnerable function candidate.

        Args:
            func_data: Function data dict with 'evidence', 'confidence_score',
                       'function', 'address' keys (from function_analyzer)
            forensics_result: Stage 1 forensics result dict with
                              'repeated_patterns', 'balance_change', etc.
            contract_info: Optional contract source code info

        Returns:
            ConfidenceScore with overall score and component breakdown
        """
        score = ConfidenceScore()

        # 1. Pattern Match Score (PMS)
        score.pattern_match = self._compute_pattern_match(
            func_data, forensics_result
        )

        # 2. Code Evidence Score (CES)
        score.code_evidence = self._compute_code_evidence(
            func_data, contract_info
        )

        # 3. Transaction Consistency Score (TCS)
        score.txn_consistency = self._compute_txn_consistency(
            func_data, forensics_result
        )

        # 4. LLM Confidence Score (LCS) — from preserved confidence_score
        score.llm_confidence = self._compute_llm_confidence(func_data)

        # Weighted overall
        score.overall = (
            self.weights['pattern_match'] * score.pattern_match +
            self.weights['code_evidence'] * score.code_evidence +
            self.weights['txn_consistency'] * score.txn_consistency +
            self.weights['llm_confidence'] * score.llm_confidence
        )
        score.overall = max(0.0, min(1.0, score.overall))

        # Classify confidence level
        score.level = self._classify(score.overall)

        # Build explanation
        score.explanation = self._build_explanation(score)

        return score

    def score_all(
        self,
        finalized_functions: List[Dict[str, Any]],
        forensics_result: Dict[str, Any],
        contract_info: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Score all finalized vulnerable functions and return enriched results.

        Returns list of dicts, each containing the original function data
        plus a 'confidence' key with the ConfidenceScore.
        """
        results = []
        for func in finalized_functions:
            score = self.score_function(func, forensics_result, contract_info)
            enriched = dict(func)
            enriched['confidence'] = score.to_dict()
            results.append(enriched)

        # Sort by confidence descending
        results.sort(key=lambda x: x['confidence']['overall'], reverse=True)
        return results

    # ─── Component Scoring Methods ────────────────────────────────────

    def _compute_pattern_match(
        self,
        func_data: Dict[str, Any],
        forensics_result: Dict[str, Any],
    ) -> float:
        """PMS: How well does this finding match known attack patterns?"""
        score = 0.0
        evidence_text = ' '.join(
            str(e) for e in func_data.get('evidence', [])
        ).lower()

        # Check evidence against known patterns
        matched_categories = 0
        for category, keywords in ATTACK_PATTERNS.items():
            for keyword in keywords:
                if keyword in evidence_text:
                    matched_categories += 1
                    break

        if matched_categories > 0:
            score += min(0.5, matched_categories * 0.2)

        # Check forensics repeated patterns
        repeated_patterns = forensics_result.get('repeated_patterns', [])
        if repeated_patterns:
            score += 0.3
            # Extra boost if function name appears in repeated patterns
            func_name = func_data.get('function', '').lower()
            for pattern in repeated_patterns:
                if func_name and func_name in str(pattern).lower():
                    score += 0.2
                    break

        return max(0.0, min(1.0, score))

    def _compute_code_evidence(
        self,
        func_data: Dict[str, Any],
        contract_info: Optional[Dict[str, Any]],
    ) -> float:
        """CES: Is source code available and does it confirm the vuln?"""
        score = 0.3  # Base score

        address = func_data.get('address', '')

        # Check if source code was available for this contract
        if contract_info and address:
            if address in contract_info:
                score += 0.3  # Source code available
                # Check if contract info has actual source
                info = contract_info[address]
                if isinstance(info, dict) and info.get('source_code'):
                    score += 0.2  # Has actual source code content
            else:
                score -= 0.1  # Source not available

        # Check evidence for code-level indicators
        evidence_text = ' '.join(
            str(e) for e in func_data.get('evidence', [])
        ).lower()
        code_indicators = ['source code', 'modifier', 'require', 'guard',
                           'function', 'contract', 'solidity']
        code_matches = sum(1 for ind in code_indicators if ind in evidence_text)
        score += min(0.2, code_matches * 0.05)

        return max(0.0, min(1.0, score))

    def _compute_txn_consistency(
        self,
        func_data: Dict[str, Any],
        forensics_result: Dict[str, Any],
    ) -> float:
        """TCS: Is the finding consistent with fund flow anomalies?"""
        score = 0.4  # Neutral baseline

        # Check if balance changes exist (indicating fund flow anomaly)
        balance_change = forensics_result.get('balance_change', {})
        if balance_change:
            score += 0.2

        # Check if address appears in attacker/victim lists
        address = func_data.get('address', '').lower()
        potential_attacker = forensics_result.get('potential_attacker', [])
        potential_victim = forensics_result.get('potential_victim', [])

        if address:
            # If the function's contract is in the attacker list
            for addr in potential_attacker:
                if isinstance(addr, str) and address == addr.lower():
                    score += 0.2
                    break
            # If it's in the victim list (also relevant)
            for addr in potential_victim:
                if isinstance(addr, str) and address == addr.lower():
                    score += 0.1
                    break

        # Check depth (deeper calls often more suspicious)
        depth = func_data.get('depth', 0)
        if depth and isinstance(depth, (int, float)):
            score += min(0.1, depth * 0.02)

        return max(0.0, min(1.0, score))

    def _compute_llm_confidence(self, func_data: Dict[str, Any]) -> float:
        """LCS: Normalized average of LLM self-reported confidence scores."""
        confidence_scores = func_data.get('confidence_score', [])

        if not confidence_scores:
            return 0.5  # Neutral if no scores

        # Try to normalize confidence scores
        normalized = []
        for cs in confidence_scores:
            if isinstance(cs, (int, float)):
                # Already numeric (0-1 or 0-100)
                val = float(cs)
                if val > 1.0:
                    val = val / 100.0
                normalized.append(max(0.0, min(1.0, val)))
            elif isinstance(cs, str):
                # Try to extract numeric value or interpret text
                cs_lower = cs.strip().lower()
                if cs_lower in ('high', 'very high'):
                    normalized.append(0.85)
                elif cs_lower in ('medium', 'moderate'):
                    normalized.append(0.6)
                elif cs_lower in ('low', 'very low'):
                    normalized.append(0.3)
                else:
                    # Try to parse as number
                    try:
                        val = float(cs.strip().rstrip('%'))
                        if val > 1.0:
                            val = val / 100.0
                        normalized.append(max(0.0, min(1.0, val)))
                    except ValueError:
                        pass

        if not normalized:
            return 0.5

        return sum(normalized) / len(normalized)

    # ─── Helpers ──────────────────────────────────────────────────────

    def _classify(self, score: float) -> str:
        """Classify score into confidence level."""
        for threshold, level, _ in CONFIDENCE_LEVELS:
            if score >= threshold:
                return level
        return "very_low"

    def _build_explanation(self, score: ConfidenceScore) -> List[str]:
        """Build human-readable explanation of the confidence score."""
        explanation = []

        # Find level description
        level_desc = ""
        for _, level, desc in CONFIDENCE_LEVELS:
            if level == score.level:
                level_desc = desc
                break

        explanation.append(
            f"Overall confidence: {score.overall:.1%} ({score.level}) — {level_desc}"
        )

        components = [
            ('Pattern match', score.pattern_match),
            ('Code evidence', score.code_evidence),
            ('Txn consistency', score.txn_consistency),
            ('LLM confidence', score.llm_confidence),
        ]

        for name, value in components:
            strength = 'strong' if value > 0.7 else 'moderate' if value > 0.4 else 'weak'
            explanation.append(f"  {name}: {value:.1%} ({strength})")

        return explanation


def calibrated_confidence(confidence: Any, probability: float, model_path: str) -> Dict[str, Any]:
    """Report calibration coherently while preserving the original heuristic.

    Component scores are heuristic inputs, not calibrated feature attributions.
    The original score, level and explanation remain available without being
    presented as the explanation of the calibrated probability.
    """
    if isinstance(probability, bool):
        raise ValueError("Calibration must return a finite probability between zero and one")
    probability = float(probability)
    if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
        raise ValueError("Calibration must return a finite probability between zero and one")
    probability = round(probability, 4)
    level = next(level for threshold, level, _ in CONFIDENCE_LEVELS if probability >= threshold)
    original = copy.deepcopy(confidence) if isinstance(confidence, dict) else None
    result = copy.deepcopy(original) if original is not None else {}
    result.update(overall=probability, level=level, calibrated=True,
                  calibration_model=model_path, heuristic_confidence=original,
                  explanation=[
                      f"Calibrated confidence: {probability:.1%} ({level}).",
                      "Component scores are heuristic inputs, not calibrated feature contributions. "
                      "The original heuristic explanation is retained in heuristic_confidence.",
                  ])
    return result


def generate_evidence_card(
    func_data: Dict[str, Any],
    confidence: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Generate a structured evidence card for a vulnerable function.

    Research Gap 3: Enhanced Explainability
    Produces a JSON-serializable evidence card with function signature,
    confidence breakdown, evidence list, and reasoning chain.
    """
    card = {
        'function_signature': {
            'address': func_data.get('address', 'unknown'),
            'function': func_data.get('function', 'unknown'),
            'call_depth': func_data.get('depth', 0),
        },
        'confidence': confidence,
        'evidence': func_data.get('evidence', []),
        'analyst_notes': '',  # Placeholder for HITL (Gap 2)
    }

    return card
