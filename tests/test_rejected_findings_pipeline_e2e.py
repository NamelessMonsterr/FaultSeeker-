"""Offline regression: real candidate filter, finalizer, pipeline result assembly,
scorer and optional console annotation. Only network/LLM stages are stubbed.
CONSOLE_REPO_PATH points to the companion console checkout with PR3 applied.
"""
import importlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
from faultseeker.core.pipeline import FaultSeekerPipeline
from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer

ADDRESS = '0x00000000fdac7708d0d360bddc1bc7d097f47439'
SELECTOR = '0xfa461e33'
CANON = f'{SELECTOR}_{ADDRESS}'
RENAMED = f'uniswapV3SwapCallback_{ADDRESS}'
FABRICATED = 'transfer_0xdead000000000000000000000000000000000000'


def pipeline_from_model(response, function=SELECTOR, address=ADDRESS):
    """Drive real filter/finalizer from a stubbed model response."""
    canonical = f'{function}_{address}'
    analyzer = FunctionAnalyzer.__new__(FunctionAnalyzer)
    analyzer.functions_to_be_inspected = {canonical: {'count': 1, 'calls': []}}
    analyzer.tx_analysis = {'function_call_loc_memo': {
        f'{function}::{address}': [{'depth': [0, 1, 2]}]}}
    analyzer.potentially_vulnerable_functions = {}
    analyzer.rejected_findings = []
    analyzer.cheatsheet = []
    analyzer.understanding_result = ''
    analyzer.current_task = ''
    analyzer.processing_result = ''
    analyzer.organization_agent = SimpleNamespace(query=lambda prompt: response)
    analyzer.vulnerability_prompts = SimpleNamespace(update_potentially_vulnerable_function='')

    def analyze(*args):
        analyzer._update_potentially_vulnerable_function()
        analyzer._process_potentially_vulnerable_functions()
        return {'finalized_vulnerable_functions': analyzer._finalize_potentially_vulnerable_functions(),
                'rejected_findings': analyzer.rejected_findings}

    pipe = FaultSeekerPipeline(SimpleNamespace(
        calibration_model_path='/nonexistent', human_in_loop=False, track_cost=False))
    pipe._agents_initialized = True
    forensic = SimpleNamespace(
        transaction_hash='0xabc123', chain='eth', trace={'children': []},
        repeated_patterns=[], function_call_loc_memo={}, balance_change={},
        potential_attacker=[], potential_victim=[], signals={}, rule_confidence=0.0,
        duration=0.1, get_function_count=lambda: 1)
    pipe.forensics_orchestrator = SimpleNamespace(run=lambda *args: (forensic, {}, {}))
    pipe.function_ranker = SimpleNamespace(rank=lambda *args: SimpleNamespace(address_list=[address]))
    pipe.function_analyzer = SimpleNamespace(run=analyze)
    return pipe


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setenv('FAULTSEEKER_SKIP_VIZ', '1')
    def blocked(*args, **kwargs):
        raise AssertionError('Network access forbidden in offline integration test')
    import socket
    monkeypatch.setattr(socket, 'create_connection', blocked)
    monkeypatch.setattr(socket.socket, 'connect', blocked)


@pytest.mark.parametrize('valid', [False, True])
def test_filter_pipeline_forwarding_and_real_scoring(valid):
    response = {RENAMED: {'evidence': 'bad', 'confidence_score': 0.8},
                FABRICATED: {'evidence': 'bad', 'confidence_score': 0.8}}
    if valid:
        response[CANON] = {'evidence': 'callback manipulates price', 'confidence_score': 0.9}
    result = pipeline_from_model(response).analyze_transaction(txn_hash='0xabc123', chain='eth')
    assert {r['key'] for r in result['rejected_findings']} == {RENAMED, FABRICATED}
    assert len(result['scored_functions']) == int(valid)
    if valid:
        assert result['scored_functions'][0]['function'] == SELECTOR
        assert result['scored_functions'][0]['depth'] == 3
    assert 'uniswapV3SwapCallback' not in json.dumps(result['scored_functions'])
    assert '0xdead' not in json.dumps(result['evidence_cards'])


@pytest.mark.parametrize('response', ['not json', None, [1, 2], {'functions': [1]}])
def test_malformed_output_survives_real_pipeline_as_rejected(response):
    result = pipeline_from_model(response).analyze_transaction(txn_hash='0xabc123', chain='eth')
    assert result['rejected_findings']
    assert all(r['reason'] == 'malformed_model_output' for r in result['rejected_findings'])
    assert result['scored_functions'] == []


@pytest.mark.parametrize('valid', [False, True])
def test_real_pipeline_to_console_annotation(valid, monkeypatch):
    console = os.getenv('CONSOLE_REPO_PATH')
    if not console:
        pytest.skip('Set CONSOLE_REPO_PATH to enable companion console annotation')
    monkeypatch.syspath_prepend(console)
    identity = importlib.import_module('app.trace_identity')
    guards = importlib.import_module('app.pipeline_guards')
    fixture = json.loads((Path(console) / 'tests/fixtures/hedgey_verified_trace.json').read_text())
    tx = fixture['provenance']['transaction_hash']
    seq = identity.sequence_from_parity(fixture['responses']['trace_transaction'], tx, 'eth')
    root = seq['trace']
    response = {RENAMED: {'evidence': 'bad', 'confidence_score': 0.8},
                FABRICATED: {'evidence': 'bad', 'confidence_score': 0.8}}
    if valid:
        response[f"{root['function']}_{root['address']}"] = {
            'evidence': 'callback manipulates price', 'confidence_score': 0.9}
    pipe = pipeline_from_model(response, root['function'], root['address'])
    result = pipe.analyze_transaction(txn_hash=tx, chain='eth')
    runtime = guards.PipelineRuntime(tx, 'eth')
    runtime.sequence = seq
    report = runtime.annotate_result(result)
    assert report['analysis_status'] == 'partial'
    assert report['classification']['rule_verdict'] == 'INCONCLUSIVE'
    assert report['analysis_integrity']['unverified_targets'] == []
    assert len(report['scored_functions']) == int(valid)
    assert any('excluded from scoring' in line for line in report['limitations'])


@pytest.mark.parametrize('record', [None, [], {'evidence': 'claimed fault'}])
def test_malformed_canonical_value_survives_pipeline_as_rejected(record):
    result = pipeline_from_model({CANON: record}).analyze_transaction(txn_hash='0xabc123', chain='eth')
    assert result['scored_functions'] == []
    assert len(result['rejected_findings']) == 1
    assert result['rejected_findings'][0]['reason'] == 'malformed_model_output'


def test_empty_object_remains_legitimate_no_findings():
    result = pipeline_from_model({}).analyze_transaction(txn_hash='0xabc123', chain='eth')
    assert result['scored_functions'] == []
    assert result['rejected_findings'] == []


@pytest.mark.parametrize('record', [None, [], {'evidence': 'claimed fault'}])
def test_malformed_canonical_value_forces_partial_in_console(record, monkeypatch):
    console = os.getenv('CONSOLE_REPO_PATH')
    if not console:
        pytest.skip('Set CONSOLE_REPO_PATH to enable companion console annotation')
    monkeypatch.syspath_prepend(console)
    identity = importlib.import_module('app.trace_identity')
    guards = importlib.import_module('app.pipeline_guards')
    fixture = json.loads((Path(console) / 'tests/fixtures/hedgey_verified_trace.json').read_text())
    tx = fixture['provenance']['transaction_hash']
    seq = identity.sequence_from_parity(fixture['responses']['trace_transaction'], tx, 'eth')
    root = seq['trace']
    key = f"{root['function']}_{root['address']}"
    result = pipeline_from_model({key: record}, root['function'], root['address']).analyze_transaction(txn_hash=tx, chain='eth')
    runtime = guards.PipelineRuntime(tx, 'eth')
    runtime.sequence = seq
    report = runtime.annotate_result(result)
    assert report['analysis_status'] == 'partial'
    assert report['classification']['rule_verdict'] == 'INCONCLUSIVE'
    assert report['scored_functions'] == []
