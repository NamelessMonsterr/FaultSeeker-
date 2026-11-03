"""Synthetic trace-shape regressions; no on-chain/provider correctness claimed."""
import sys
import pytest

from faultseeker.data_collection.trace_parser import TraceNode
from faultseeker.data_collection.txn_sequencer import TransactionSequencer
from faultseeker.data_collection.trace_visualizer import TraceGraphGenerator, TransactionTraceVisualizer


def legacy_chain(count=1024):
    root = {"type": "call", "address": "root", "function": "f", "children": []}
    current = root
    for index in range(1, count):
        child = {"type": "call", "address": str(index), "function": "f", "children": []}
        current["children"] = [child]
        current = child
    return root


def object_chain(count=1024):
    root = TraceNode("call", address="root", function="f")
    current = root
    for index in range(1, count):
        child = TraceNode("call", address=str(index), function="f")
        current.children = [child]
        current = child
    return root


def test_from_dict_retains_every_frame_at_normal_recursion_limit():
    assert sys.getrecursionlimit() == 1000
    node = TraceNode.from_dict(legacy_chain())
    count = 1
    while node.children:
        node = node.children[0]
        count += 1
    assert count == 1024 and node.address == "1023"


def test_to_dict_retains_every_frame_at_normal_recursion_limit():
    node = object_chain().to_dict()
    count = 1
    while node["children"]:
        node = node["children"][0]
        count += 1
    assert count == 1024 and node["address"] == "1023"


def test_canonical_conversion_preserves_deepest_selector_and_params():
    root = {"callee": "root", "call_type": "CALL", "input": "0x12345678abcd",
            "function_selector": "0x12345678", "children": []}
    current = root
    for index in range(1, 1024):
        child = {"callee": str(index), "call_type": "DELEGATECALL", "input": "0x87654321ffff",
                 "function_selector": "0x87654321", "children": []}
        current["children"] = [child]
        current = child
    node = TransactionSequencer._canonical_to_legacy_trace(root)
    count = 1
    while node["children"]:
        node = node["children"][0]
        count += 1
    assert count == 1024
    assert (node["address"], node["function"], node["params"], node["call_type"]) == (
        "1023", "0x87654321", "ffff", "delegatecall")


def test_graph_retains_all_nodes_edges_and_deepest_level():
    visualizer = TransactionTraceVisualizer()
    visualizer.build_graph_from_tree(object_chain())
    assert len(visualizer.graph) == 1024
    assert visualizer.graph.number_of_edges() == 1023
    assert visualizer.graph.nodes["node_1023"]["level"] == 1023
    assert visualizer.graph.nodes["node_1023"]["address"] == "1023"


def test_text_generator_retains_deepest_frame():
    lines = TraceGraphGenerator().generate(object_chain()).splitlines()
    assert len(lines) == 1024
    assert "1023::f()" in lines[-1]


def test_shallow_metadata_order_and_non_call_filtering_stay_compatible():
    root = TraceNode("call", gas=9, address="r", function="root", params="abc", call_type="call",
                     value="4", contract_type="C", children=[
                         TraceNode("return", value="ok", children=[TraceNode("call", function="hidden")]),
                         TraceNode("create", address="c", gas=5, function="new C",
                                   children=[TraceNode("call", address="nested", function="f")]),
                         TraceNode("call", address="sibling", function="g")])
    value = root.to_dict()
    restored = TraceNode.from_dict(value)
    assert restored.to_dict() == value
    visualizer = TransactionTraceVisualizer()
    visualizer.build_graph_from_tree(restored)
    assert [data["address"] for _, data in visualizer.graph.nodes(data=True)] == ["r", "c", "nested", "sibling"]
    assert list(visualizer.graph.edges) == [("node_0", "node_1"), ("node_0", "node_3"), ("node_1", "node_2")]
    lines = TraceGraphGenerator().generate(restored).splitlines()
    assert len(lines) == 4  # generator only descends into call nodes, as before
    assert lines[0] == "[9] r::root(abc) [call]"
    assert "[Return] ok" in lines[1] and "new C@c" in lines[2] and "sibling::g()" in lines[3]


@pytest.mark.parametrize("operation", [lambda node: node.to_dict(),
                                      lambda node: TraceGraphGenerator().generate(node),
                                      lambda node: TransactionTraceVisualizer().build_graph_from_tree(node)])
def test_cyclic_object_fails_explicitly_instead_of_looping(operation):
    root = TraceNode("call", address="r", function="f")
    root.children = [root]
    with pytest.raises(ValueError, match="Cyclic"):
        operation(root)


@pytest.mark.parametrize("operation,root", [
    (TraceNode.from_dict, {"type": "call", "children": []}),
    (TransactionSequencer._canonical_to_legacy_trace, {"callee": "r", "children": []}),
])
def test_cyclic_dictionary_fails_explicitly_instead_of_looping(operation, root):
    root["children"] = [root]
    with pytest.raises(ValueError, match="Cyclic"):
        operation(root)


def test_reused_sibling_is_processed_twice_without_false_cycle():
    child = {"type": "call", "address": "shared", "children": []}
    root = TraceNode.from_dict({"type": "call", "children": [child, child]})
    assert len(root.children) == 2 and root.children[0] is not root.children[1]
    value = root.to_dict()
    assert value["children"][0] == value["children"][1]
    assert value["children"][0] is not value["children"][1]
    visualizer = TransactionTraceVisualizer()
    visualizer.build_graph_from_tree(root)
    assert len(visualizer.graph) == 3
