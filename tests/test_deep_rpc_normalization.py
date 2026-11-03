"""Synthetic depth/schema contracts; no provider calls or on-chain fixture."""
import copy
import hashlib
import json
import sys

import pytest

from faultseeker.utils.rpc_provider import normalize_trace_node

# Captured by executing the original normalizer at fca6b998fa0a01f3832be6a0f1aa1d768306da8f.
# These synthetic shallow snapshots need no Git history in a shallow CI checkout.
MIXED_BASE_DIGESTS = {
    "geth": "1e4b38d8301e91a2eda44eed83eaa35162cfdbaa913def0aa28fd17388cbcb76",
    "tenderly": "1e4b38d8301e91a2eda44eed83eaa35162cfdbaa913def0aa28fd17388cbcb76",
    "parity": "c66d63270abbcd5b589f1f820c7fadd6886044dead221ae99866df4185580da2",
}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def raw_node(variant, marker):
    fields = {"type": "delegatecall", "input": "0x12345678" + marker,
              "from": "synthetic-caller-" + marker, "to": "synthetic-callee-" + marker,
              "value": "0x1", "gas": "0x100", "output": "0xab", "error": "Reverted"}
    if variant == "parity":
        return {"type": "call", "action": {key: fields[key] for key in ("input", "from", "to", "value", "gas")},
                "result": {"output": "0xab"}, "error": "Reverted", "children": []}
    if variant == "tenderly":
        return {**fields, "callType": "delegatecall", "caller": fields["from"],
                "callee": fields["to"], "children": []}
    return {**fields, "calls": []}


@pytest.mark.parametrize("variant", ["geth", "tenderly", "parity"])
def test_normalize_1024_frames_without_changing_recursion_limit(variant):
    before_limit = sys.getrecursionlimit()
    raw = raw_node(variant, "0")
    current = raw
    children_key = "calls" if variant == "geth" else "children"
    for index in range(1, 1024):
        child = raw_node(variant, str(index))
        current[children_key] = [child]
        current = child
    normalized = normalize_trace_node(raw, depth=5, call_id="root")
    original, result = raw, normalized
    count = 0
    while True:
        assert result is not original
        assert result["depth"] == 5 + count
        assert result["call_id"] == "root" + ".0" * count
        assert result["callee"] == "synthetic-callee-" + str(count)
        assert result["input"] == "0x12345678" + str(count)
        assert result["success"] is False
        assert "call_id" not in original
        count += 1
        if not result["children"]:
            break
        assert len(result["children"]) == 1
        result = result["children"][0]
        original = original[children_key][0]
    assert count == 1024
    assert sys.getrecursionlimit() == before_limit


@pytest.mark.parametrize("variant", ["geth", "tenderly", "parity"])
def test_mixed_shallow_variants_match_frozen_base_and_child_order(variant):
    raw = raw_node(variant, "parent")
    key = "calls" if variant == "geth" else "children"
    raw[key] = [raw_node("geth", "first"), raw_node("tenderly", "second"),
                raw_node("parity", "third"), None, {}]
    original = copy.deepcopy(raw)
    assert digest(normalize_trace_node(raw, 3, "custom")) == MIXED_BASE_DIGESTS[variant]
    assert raw == original


@pytest.mark.parametrize("raw,expected", [
    *[(raw, "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a") for raw in (None, {}, [], 0, "invalid")],
    ({"type": "CALL", "input": "0x", "calls": [], "children": [{"type": "ignored"}]},
     "b0b2f81d12bd8e5c84156917ece69ebe1f4a875128d22fe9feb251770aabf9d2"),
    ({"type": "call", "action": {"input": "0x", "from": "sender", "to": "target"},
      "output": "0x22", "result": {"output": "0x11"}, "children": []},
     "96850a8e3cc503031fef10b81b3227147e9af5773c60af0794c7ae79f2dc4a4e"),
    ({"callType": "staticcall", "caller": "caller", "callee": "callee", "children": [], "output": None},
     "f743a9cde8538a37e53ad007f06bd617e883c44a32bcd2a0863d2a48b918c4e5")])
def test_shallow_edge_cases_match_frozen_base(raw, expected):
    assert digest(normalize_trace_node(raw)) == expected


def test_cyclic_local_input_fails_without_rejecting_shared_sibling_nodes():
    raw = raw_node("geth", "root")
    raw["calls"] = [raw]
    with pytest.raises(ValueError, match="Cyclic trace"):
        normalize_trace_node(raw)
    child = raw_node("geth", "shared")
    raw["calls"] = [child, child]
    normalized = normalize_trace_node(raw)
    assert [node["call_id"] for node in normalized["children"]] == ["0.0", "0.1"]
    assert normalized["children"][0] is not normalized["children"][1]
    assert all(node["callee"] == "synthetic-callee-shared" for node in normalized["children"])
