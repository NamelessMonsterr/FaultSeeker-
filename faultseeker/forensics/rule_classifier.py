"""
RuleClassifier — Threshold-based hard verdict before any LLM call.

Input:  SignalBundle  (from SignalExtractor)
Output: (verdict, confidence, matched_rule, vuln_type_hint)

  verdict      → "EXPLOIT" | "BENIGN" | "UNCERTAIN"
  confidence   → float 0.0–1.0
  matched_rule → string label of the rule that fired
  vuln_type    → best-guess vulnerability category (matches benchmark CSV)

Design goals:
  - BENIGN → skip LLM entirely (no contract code executed; skip rate unmeasured)
  - EXPLOIT with confidence ≥ 0.85 → LLM only explains, doesn't re-classify
  - UNCERTAIN → full LLM reasoning pipeline (existing behaviour)
"""

from __future__ import annotations
from faultseeker.forensics.signal_extractor import SignalBundle


# ── Benchmark CSV vuln_type labels (normalised) ────────────────────────────
# Used to map our internal rule names to the ground-truth labels in the CSV.
VULN_TYPE_MAP = {
    'reentrancy_with_profit':           'Reentrancy',
    'reentrancy_pattern':               'Reentrancy',
    'flash_loan_profit':                'Flash Loan Attack',
    'flash_loan_price_manipulation':    'Price Manipulation',
    'price_manipulation':               'Price Manipulation',
    'compoundv2_inflation':             'Compoundv2 Inflation Attack',
    'closed_source_access_control':     'Improper Access Control Of Close-Source Contract',
    'access_control_bypass':            'Access Control',
    'delegatecall_created_contract':    'Arbitrary External Call',
    'privileged_call_with_creation':    'Access Control',
    'no_signals':                       'Benign',
    'ambiguous':                        'Unknown',
}


def classify(signals: SignalBundle) -> tuple[str, float, str, str]:
    """
    Returns (verdict, confidence, matched_rule, vuln_type_hint).

    Rule priority (highest confidence first):
     0. No contract execution → BENIGN (skip Stage 2)
     1. Reentrancy + profit
     2. Flash Loan + profit
     3. Flash Loan + price manipulation
     4. Closed-source access control (hex selectors OR delegatecall)
     4b. Compoundv2 inflation attack
     5. Price manipulation alone
     6. Privileged call using created-contract address
     7. Generic delegatecall into tx-created contract
     8. Generic access control bypass
     9. Reentrancy pattern alone
    10. Weak flash-loan signal
    11. No signals → UNCERTAIN
    12. Ambiguous → UNCERTAIN
    """

    # ── Rule 0: No contract code executed → BENIGN ──────────────────────────
    # Positive benign evidence (set by SignalExtractor._check_no_contract_execution):
    # pure native-currency transfer(s); a contract exploit is impossible.
    if signals.no_contract_execution:
        return ('BENIGN', 0.90, 'no_contract_execution',
                VULN_TYPE_MAP['no_signals'])

    # ── Rule 1: Reentrancy + confirmed profit ─────────────────────────────────
    if signals.reentrancy_score >= 0.85 and signals.profit_extraction_eth > 0.5:
        return ('EXPLOIT', 0.92, 'reentrancy_with_profit',
                VULN_TYPE_MAP['reentrancy_with_profit'])

    # ── Rule 2: Flash loan + extracted profit ─────────────────────────────────
    if signals.flash_loan_detected and signals.flash_profit_eth > 1.0:
        return ('EXPLOIT', 0.88, 'flash_loan_profit',
                VULN_TYPE_MAP['flash_loan_profit'])

    # ── Rule 3: Flash loan + price manipulation combo ─────────────────────────
    if (signals.flash_loan_detected
            and signals.price_read_write_sequences >= 2
            and signals.price_delta_ratio >= 0.10):
        return ('EXPLOIT', 0.87, 'flash_loan_price_manipulation',
                VULN_TYPE_MAP['flash_loan_price_manipulation'])

    # ── Rule 4: Closed-source contract access control ─────────────────────────
    # Catches: hex-selector calls, delegatecall with unknown function, proxy abuse
    if signals.closed_source_state_change:
        return ('EXPLOIT', 0.85, 'closed_source_access_control',
                VULN_TYPE_MAP['closed_source_access_control'])

    # ── Rule 4b: Compoundv2-style inflation attack ────────────────────────────
    if signals.inflation_attack:
        return ('EXPLOIT', 0.82, 'compoundv2_inflation',
                VULN_TYPE_MAP['compoundv2_inflation'])

    # ── Rule 5: Price manipulation pattern (no flash loan needed) ─────────────
    if signals.price_read_write_sequences >= 2 and signals.price_delta_ratio >= 0.15:
        return ('EXPLOIT', 0.83, 'price_manipulation',
                VULN_TYPE_MAP['price_manipulation'])

    # ── Rule 6: Privileged call with created-contract address in params ────────
    if signals.created_contract_in_privileged_call:
        return ('EXPLOIT', 0.82, 'privileged_call_with_creation',
                VULN_TYPE_MAP['privileged_call_with_creation'])

    # ── Rule 7: delegatecall into tx-created contract ─────────────────────────
    if signals.arbitrary_external_call:
        return ('EXPLOIT', 0.82, 'delegatecall_created_contract',
                VULN_TYPE_MAP['delegatecall_created_contract'])

    # ── Rule 8: Generic access control bypass ─────────────────────────────────
    if signals.access_control_bypass:
        return ('EXPLOIT', 0.80, 'access_control_bypass',
                VULN_TYPE_MAP['access_control_bypass'])

    # ── Rule 9: Reentrancy pattern alone (no confirmed profit) ────────────────
    if signals.reentrancy_score >= signals.reentrancy_detection_threshold:
        return ('EXPLOIT', 0.75, 'reentrancy_pattern',
                VULN_TYPE_MAP['reentrancy_pattern'])

    # ── Rule 10: Weak flash-loan signal only (need LLM to confirm) ─────────────
    if signals.flash_loan_detected and signals.flash_callback_detected:
        return ('UNCERTAIN', 0.55, 'flash_loan_unconfirmed', 'Flash Loan Attack')

    # ── Rule 11: Large profit transfer without known pattern ──────────────────
    if signals.large_transfer_to_eoa and signals.profit_extraction_eth > 2.0:
        return ('UNCERTAIN', 0.52, 'suspicious_profit', 'Unknown')

    # ── Rule 12: Single bare transfer — likely donation step of multi-tx exploit ─
    # A transaction whose ONLY external action is a token transfer cannot be
    # classified in isolation. Compoundv2 inflation attacks, sandwich setups, and
    # certain rug-pull patterns all use a bare transfer as step 1 of N.
    if signals.single_transfer_only:
        return ('UNCERTAIN', 0.60, 'multi_tx_context_required',
                'Multi-Transaction Exploit (context required)')

    # ── Rule 13: No signals at all → UNCERTAIN ────────────────────────────────
    no_signals = (
        signals.reentrancy_score < 0.1
        and not signals.flash_loan_detected
        and signals.price_read_write_sequences == 0
        and not signals.access_control_bypass
        and not signals.inflation_attack
        and signals.profit_extraction_eth < 0.1
        and not signals.large_transfer_to_eoa
    )
    if no_signals:
        return ('UNCERTAIN', 0.40, 'no_signals_llm_required', 'Unknown')

    # ── Rule 14: Everything else → UNCERTAIN ─────────────────────────────────
    return ('UNCERTAIN', 0.45, 'ambiguous', VULN_TYPE_MAP['ambiguous'])


def describe(verdict: str, confidence: float, rule: str, vuln_type: str) -> str:
    """Human-readable one-liner for logging / evidence cards."""
    return (f"[{verdict}] confidence={confidence:.0%}  "
            f"rule='{rule}'  type='{vuln_type}'")
