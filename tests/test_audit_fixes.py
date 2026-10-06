"""audit-fixes regression tests: BENIGN fast-path, theta_gate escalation, SLOAD.

Covers the mechanisms implemented on the audit-fixes branch for the issues
found in the FaultSeeker++ paper-vs-repo audit (2026-10-06):
  - RuleClassifier never emitted BENIGN (docstring-only) → Rule 0 + pipeline skip
  - HybridLLMRouter.confidence_gate stored but never read → real escalation
  - SLOAD extraction absent despite "SSTORE/SLOAD" claim → implemented
"""
import pytest

from faultseeker.forensics.signal_extractor import SignalBundle, SignalExtractor
from faultseeker.forensics import rule_classifier


def _bundle(**kw):
    b = SignalBundle()
    for k, v in kw.items():
        setattr(b, k, v)
    return b


# ── BENIGN verdict ──────────────────────────────────────────────────────────

def test_benign_rule_fires_on_no_contract_execution():
    verdict, conf, rule, hint = rule_classifier.classify(
        _bundle(no_contract_execution=True))
    assert verdict == 'BENIGN'
    assert rule == 'no_contract_execution'
    assert hint == 'Benign'
    assert conf >= 0.85


def test_benign_takes_priority_over_exploit_rules():
    # Positive benign evidence wins even if (inconsistently) other flags set.
    verdict, _, _, _ = rule_classifier.classify(
        _bundle(no_contract_execution=True, reentrancy_score=0.9,
                profit_extraction_eth=1.0))
    assert verdict == 'BENIGN'


def test_empty_bundle_still_uncertain():
    verdict, conf, rule, _ = rule_classifier.classify(_bundle())
    assert verdict == 'UNCERTAIN'
    assert rule == 'no_signals_llm_required'


def _extractor_with_flat(flat, storage_events=None):
    se = SignalExtractor.__new__(SignalExtractor)
    se.flat = flat
    se.storage_events = storage_events or []
    se.signals = SignalBundle()
    return se


def test_no_contract_execution_pure_transfer():
    se = _extractor_with_flat([
        {'function': '', 'params': '', 'call_type': 'call', 'address': '0xabc'},
        {'function': '', 'params': '', 'call_type': 'call', 'address': '0xdef'},
    ])
    se._check_no_contract_execution()
    assert se.signals.no_contract_execution is True


def test_no_contract_execution_rejects_contract_call():
    se = _extractor_with_flat([
        {'function': 'transfer', 'params': '0x1234', 'call_type': 'call',
         'address': '0xabc'},
    ])
    se._check_no_contract_execution()
    assert se.signals.no_contract_execution is False


def test_no_contract_execution_rejects_delegatecall():
    se = _extractor_with_flat([
        {'function': '', 'params': '', 'call_type': 'delegatecall',
         'address': '0xabc'},
    ])
    se._check_no_contract_execution()
    assert se.signals.no_contract_execution is False


def test_no_contract_execution_rejects_storage_writes():
    se = _extractor_with_flat(
        [{'function': '', 'params': '', 'call_type': 'call', 'address': '0xabc'}],
        storage_events=[{'op': 'SSTORE', 'slot': '0x1'}],
    )
    se._check_no_contract_execution()
    assert se.signals.no_contract_execution is False


def test_no_contract_execution_empty_trace_unknown():
    se = _extractor_with_flat([])
    se._check_no_contract_execution()
    assert se.signals.no_contract_execution is False


# ── theta_gate escalation ───────────────────────────────────────────────────

def _router():
    from faultseeker.core.llm_router import HybridLLMRouter
    return HybridLLMRouter()


def test_should_escalate_tier2_below_gate():
    r = _router()
    assert r.should_escalate('generation_agent', local_confidence=0.0) is True
    assert r.should_escalate('organization_agent', local_confidence=0.59) is True
    assert r.should_escalate('generation_agent', local_confidence=0.9) is False


def test_should_escalate_ignores_other_tiers():
    r = _router()
    assert r.should_escalate('AddressClassifier', local_confidence=0.0) is False
    assert r.should_escalate('reasoning_agent', local_confidence=0.0) is False


def test_select_model_escalates_on_low_confidence():
    r = _router()
    assert r.select_model(agent_role='generation_agent',
                          local_confidence=0.0) == r.cloud_model
    assert r.select_model(agent_role='generation_agent',
                          local_confidence=0.95) == r.local_model
    # default (no confidence supplied): legacy local-first behavior
    assert r.select_model(agent_role='generation_agent') == r.local_model


def test_escalate_agent_rebuilds_on_cloud():
    from faultseeker.core.llm_router import build_routed_agent
    r = _router()
    agent = build_routed_agent("sys", router=r, agent_role='generation_agent',
                               system_prompt='You are a tester')
    assert agent.model == r.local_model
    escalated = r.escalate_agent(agent)
    assert escalated.model == r.cloud_model
    assert escalated.agent_role == 'generation_agent'
    assert getattr(escalated, 'escalated_from_local', False) is True


# ── SLOAD extraction ────────────────────────────────────────────────────────

def _struct_logs():
    return [
        {'op': 'SSTORE', 'depth': 1, 'pc': 10,
         'stack': ['0x' + 'aa' * 32, '0x' + 'bb' * 32], 'storage': {}},
        {'op': 'SLOAD', 'depth': 1, 'pc': 20,
         'stack': ['0x' + 'cc' * 32], 'storage': {}},
    ]


def test_sload_events_extracted():
    from faultseeker.utils.rpc_provider import extract_storage_writes_from_struct_logs
    evs = extract_storage_writes_from_struct_logs(
        _struct_logs(), root_trace={'address': '0x' + 'dd' * 20})
    ops = [e['op'] for e in evs]
    assert ops == ['SSTORE', 'SLOAD']
    sload = evs[1]
    assert sload['slot'].lower().endswith('cc' * 4)
    assert sload['depth'] == 1


def test_normalizer_keeps_sstore_only():
    from faultseeker.utils.rpc_provider import extract_storage_writes_from_struct_logs
    evs = extract_storage_writes_from_struct_logs(
        _struct_logs(), root_trace={'address': '0x' + 'dd' * 20})
    se = SignalExtractor.__new__(SignalExtractor)
    se.storage_events = evs
    normed = se._normalized_storage_events()
    assert len(normed) == 1
    assert normed[0]['slot'].lower().endswith('aa' * 4)


def test_normalizer_backward_compat_no_op_field():
    se = SignalExtractor.__new__(SignalExtractor)
    se.storage_events = [{'address': '0xdd', 'slot': '0xaa', 'depth': 1}]
    assert len(se._normalized_storage_events()) == 1
