"""Synthetic trace boundaries; no live trace or verdict ground truth implied."""
import sys
import pytest
from faultseeker.forensics.trace_analyzer import TraceAnalyzer


def analyzer():
    result = TraceAnalyzer.__new__(TraceAnalyzer)
    result.address_call_memo = {}
    result.function_call_loc_memo = {}
    result.function_calls_to_expand = {"flashloan": [], "callback": []}
    result.function_calls_to_expand_loc = {"flashloan": [], "flashloan_callback": [], "name_in_hash": []}
    result.address_calls_with_created_contract_in_params = []
    result.txn_seq = {"created_address": []}
    result.repeated_patterns = {"keys": [], "keys_function_only": []}
    return result


def frame(index, children=None):
    return {"type": "call", "call_type": "call", "address": "0x" + "1" * 40,
            "function": "0x12345678", "params": "", "marker": [index],
            "children": children or []}


def test_1024_frames_flatten_without_changing_process_recursion_limit():
    root = frame(0)
    leaf = root
    for index in range(1, 1024):
        child = frame(index)
        leaf["children"] = [child]
        leaf = child
    before = sys.getrecursionlimit()
    assert before == 1000, "Run in the standalone offline depth runner; no import-side recursion workaround"
    result = analyzer()._flatten_trace_single(root, [0])
    assert len(result) == 1024
    assert [item["marker"][0] for item in result] == list(range(1024))
    assert result[-1]["depth"] == [0] * 1024
    assert all("children" not in item for item in result)
    assert sys.getrecursionlimit() == before
    result[-1]["marker"].append("copied")
    assert leaf["marker"] == [1023]


def test_sibling_preorder_depth_and_repeated_pattern_metadata():
    root = frame(99, [frame(1), frame(2), frame(3), frame(4)])
    instance = analyzer()
    result = instance._flatten_trace_single(root, [7])
    assert [item["marker"][0] for item in result] == [99, 1, 2, 3, 4]
    assert [item["depth"] for item in result] == [[7], [7, 0], [7, 1], [7, 2], [7, 3]]
    assert len(instance.function_call_loc_memo["0x12345678::" + "0x" + "1" * 40]) == 5
    assert instance.repeated_patterns["keys"]
    pattern = instance.repeated_patterns["keys"][0]["pattern"]
    assert all("children" not in node for node in pattern)
    pattern[0]["marker"].append("copied")
    assert root["children"][0]["marker"] == [1]


def test_cycle_rejected_but_reused_siblings_remain_distinct_frames():
    cyclic = frame(0)
    cyclic['children'] = [cyclic]
    with pytest.raises(ValueError, match='Cyclic trace'):
        analyzer()._flatten_trace_single(cyclic, [0])
    shared = frame(1)
    rows = analyzer()._flatten_trace_single(frame(0, [shared, shared]), [0])
    assert [row['depth'] for row in rows] == [[0], [0, 0], [0, 1]]
