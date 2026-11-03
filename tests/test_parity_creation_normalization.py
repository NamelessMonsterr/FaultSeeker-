"""Synthetic provider-schema regressions, not an on-chain trace fixture."""
import copy

import pytest

from faultseeker.utils.rpc_provider import build_parity_tree, normalize_trace_node

SENDER = "0x" + "1" * 40
CREATED = "0x" + "2" * 40
TARGET = "0x" + "3" * 40
INIT = "0x60806040526000"


def creation(**overrides):
    node = {"type": "create", "traceAddress": [], "subtraces": 0,
            "action": {"from": SENDER, "init": INIT, "value": "0x0", "gas": "0x1000"},
            "result": {"address": CREATED, "code": "0x6000", "gasUsed": "0x20"}}
    node.update(overrides)
    return node


@pytest.mark.parametrize("through_tree", [False, True])
@pytest.mark.parametrize("creation_type", ["create", "create2"])
def test_creation_keeps_result_address_and_initcode(through_tree, creation_type):
    raw = creation(type=creation_type)
    before = copy.deepcopy(raw)
    node = normalize_trace_node(build_parity_tree([raw]) if through_tree else raw)
    assert node["call_type"] == creation_type.upper()
    assert node["callee"] == node["to"] == CREATED
    assert node["input"] == INIT
    assert node["caller"] == SENDER
    assert node["success"] is True
    assert raw == before


@pytest.mark.parametrize("through_tree", [False, True])
@pytest.mark.parametrize("result", [None, {}, "malformed"])
def test_failed_creation_never_uses_initcode_as_an_address(through_tree, result):
    raw = creation(result=result, error="Reverted")
    node = normalize_trace_node(build_parity_tree([raw]) if through_tree else raw)
    assert node["call_type"] == "CREATE"
    assert node["callee"] == node["to"] == ""
    assert node["input"] == INIT
    assert node["success"] is False


@pytest.mark.parametrize("through_tree", [False, True])
def test_call_preserves_destination_input_and_error(through_tree):
    raw = {"type": "call", "traceAddress": [], "action": {"from": SENDER,
           "to": TARGET, "input": "0x12345678"}, "result": {"output": "0x12"},
           "error": "Reverted"}
    node = normalize_trace_node(build_parity_tree([raw]) if through_tree else raw)
    assert node["call_type"] == "CALL"
    assert node["callee"] == TARGET
    assert node["input"] == "0x12345678"
    assert node["return_data"] == "0x12"
    assert node["success"] is False


def test_replayer_parity_fallback_preserves_nested_creation(monkeypatch):
    from faultseeker.data_collection import txn_replayer
    root = {"type": "call", "traceAddress": [], "action": {
        "from": SENDER, "to": TARGET, "input": "0x12345678"}, "result": {"output": "0x"}}
    child = creation(traceAddress=[0])
    def rpc(chain, method, params, **kwargs):
        if method == "trace_replayTransaction":
            return {"trace": [root, child], "stateDiff": {"synthetic": {}}}
        raise RuntimeError("Controlled unsupported debug method")
    monkeypatch.setattr(txn_replayer, "rpc_call", rpc)
    report = txn_replayer.TransactionReplayer._rpc_structured_trace("synthetic-transaction", "eth")
    node = report["trace"]["children"][0]
    assert node["call_type"] == "CREATE"
    assert node["callee"] == CREATED and node["input"] == INIT
    assert node["call_id"] == "0.0" and node["depth"] == 1
