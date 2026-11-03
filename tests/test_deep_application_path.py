"""Controlled analysis boundary; real normalization/cache/sequence/flatten/save.

All trace data is synthetic. No full forensic/model or on-chain claim is made.
"""
import copy
import json
import sys

def test_main_preserves_1024_frames_through_cache_and_report(monkeypatch, tmp_path):
    from faultseeker import main as entry
    from faultseeker.utils.rpc_provider import normalize_trace_node
    from faultseeker.data_collection.txn_replayer import TransactionReplayer
    from faultseeker.data_collection.txn_sequencer import TransactionSequencer
    from faultseeker.forensics import trace_analyzer

    tx = '0x' + 'a' * 64
    address = '0x' + '1' * 40
    raw = {'type': 'CALL', 'from': address, 'to': address, 'input': '0x12345678', 'calls': []}
    current = raw
    for _ in range(1023):
        child = {'type': 'CALL', 'from': address, 'to': address, 'input': '0x12345678', 'calls': []}
        current['calls'] = [child]
        current = child
    monkeypatch.setattr(trace_analyzer, 'build_agent', lambda *args: None)

    def controlled_analysis(self, **kwargs):
        canonical = normalize_trace_node(raw)
        replayer = TransactionReplayer(str(tmp_path / 'replay'), str(tmp_path / 'structured'))
        replayer.cache_structured_trace(tx, {'transaction_hash': tx, 'chain': 'eth', 'trace': canonical})
        cached = replayer.get_structured_cache(tx)
        assert cached is not None
        # Same nested deepcopy boundary used by console provenance hooks.
        cached = copy.deepcopy(cached)
        sequencer = TransactionSequencer()
        monkeypatch.setattr(sequencer.replayer, 'get_structured_trace', lambda *args: cached)
        monkeypatch.setattr(sequencer.replayer, 'run', lambda *args: '')
        sequence = sequencer.run(tx, 'eth')
        result = trace_analyzer.TraceAnalyzer(sequence, {}, model='offline-no-model').run()
        rows = result['flatten_trace']
        assert len(rows) == 1024 and rows[-1]['depth'] == [0] * 1024
        assert rows[-1]['address'] == address
        return {'canonical_trace': result['canonical_trace'], 'retained_frames': len(rows),
                'deepest_depth': rows[-1]['depth'], 'scope': 'controlled trace-processing only'}

    monkeypatch.setattr(entry.FaultSeekerPipeline, 'analyze_transaction', controlled_analysis)
    previous = sys.getrecursionlimit()
    try:
        entry.main(txn_hash=tx, chain='eth', forensics_model='offline',
                   function_analysis_model='offline', cache_dir=str(tmp_path / 'cache'),
                   output_path=str(tmp_path / 'report.json'))
        with (tmp_path / 'report.json').open(encoding='utf-8') as report_file:
            saved = json.load(report_file)
        assert saved['retained_frames'] == 1024
        nodes = 0
        node = saved['canonical_trace']
        while node:
            nodes += 1
            children = node['children']
            node = children[0] if children else None
        assert nodes == 1024
    finally:
        sys.setrecursionlimit(previous)
