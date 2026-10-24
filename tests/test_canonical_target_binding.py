"""Echo-acceptance binding: model-returned candidate keys must exactly name an
observed call id (functions_to_be_inspected key or trace-derived
function_call_loc_memo entry). Renamed, fabricated, or malformed targets are
rejected into rejected_findings and never enter the scoring set.
"""
import pytest

from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer

ADDR = "0x00000000fdac7708d0d360bddc1bc7d097f47439"
SEL = "0xfa461e33"
CANON = f"{SEL}_{ADDR}"          # canonical observed id the model was shown
RENAMED = f"uniswapV3SwapCallback_{ADDR}"  # the run-9f027d5d321a rename
FABRICATED = "transfer_0xdead000000000000000000000000000000000000"
MALFORMED = "no_underscore_address_here"  # has '_' but no valid pair; and truly no '_' below
NO_UNDERSCORE = "transfer"


class _StubAgent:
    def __init__(self, response):
        self.response = response

    def query(self, prompt, **kwargs):
        return self.response


def _make_analyzer(response, memo_extra=None):
    fa = FunctionAnalyzer.__new__(FunctionAnalyzer)
    fa.functions_to_be_inspected = {CANON: {"count": 3, "calls": []}}
    memo = {f"{SEL}::{ADDR}": [{"depth": [0, 1, 2]}]}
    if memo_extra:
        memo.update(memo_extra)
    fa.tx_analysis = {"function_call_loc_memo": memo}
    fa.potentially_vulnerable_functions = {}
    fa.rejected_findings = []
    fa.cheatsheet = []
    fa.understanding_result = ""
    fa.current_task = ""
    fa.processing_result = ""
    fa.organization_agent = _StubAgent(response)
    fa.vulnerability_prompts = type(
        "P", (), {"update_potentially_vulnerable_function": ""})()
    return fa


def test_canonical_echo_accepted_and_depth_resolved():
    fa = _make_analyzer({CANON: {"evidence": "callback manipulates price",
                                 "confidence_score": 0.9}})
    fa._update_potentially_vulnerable_function()
    assert list(fa.potentially_vulnerable_functions) == [CANON]
    assert fa.potentially_vulnerable_functions[CANON]["depth"] == 3
    assert fa.rejected_findings == []


def test_renamed_same_address_rejected():
    fa = _make_analyzer({RENAMED: {"evidence": "renamed label",
                                   "confidence_score": 0.9}})
    fa._update_potentially_vulnerable_function()
    assert fa.potentially_vulnerable_functions == {}
    assert len(fa.rejected_findings) == 1
    assert fa.rejected_findings[0]["key"] == RENAMED
    assert fa.rejected_findings[0]["reason"] == "unbindable_target"


def test_fabricated_address_rejected():
    fa = _make_analyzer({FABRICATED: {"evidence": "invented target",
                                      "confidence_score": 0.8}})
    fa._update_potentially_vulnerable_function()
    assert fa.potentially_vulnerable_functions == {}
    assert [r["key"] for r in fa.rejected_findings] == [FABRICATED]


def test_malformed_keys_rejected_not_crash():
    fa = _make_analyzer({MALFORMED: {"evidence": "x", "confidence_score": 0.5},
                         NO_UNDERSCORE: {"evidence": "y", "confidence_score": 0.5}})
    fa._update_potentially_vulnerable_function()
    assert fa.potentially_vulnerable_functions == {}
    assert {r["key"] for r in fa.rejected_findings} == {MALFORMED, NO_UNDERSCORE}


def test_case_variant_normalizes_to_canonical_exact_string():
    fa = _make_analyzer({f"0xFA461E33_{ADDR.upper()}": {"evidence": "case jitter",
                                                        "confidence_score": 0.7}})
    fa._update_potentially_vulnerable_function()
    assert list(fa.potentially_vulnerable_functions) == [CANON]  # canonical casing stored
    assert fa.rejected_findings == []


def test_mixed_valid_and_rejected_only_valid_scored():
    fa = _make_analyzer({
        CANON: {"evidence": "real", "confidence_score": 0.9},
        RENAMED: {"evidence": "renamed", "confidence_score": 0.8},
        FABRICATED: {"evidence": "invented", "confidence_score": 0.7},
    })
    fa._update_potentially_vulnerable_function()
    assert list(fa.potentially_vulnerable_functions) == [CANON]
    assert {r["key"] for r in fa.rejected_findings} == {RENAMED, FABRICATED}


def test_wrapper_shapes_still_unwrap_then_filter():
    fa = _make_analyzer({"vulnerable_functions": {
        CANON: {"evidence": "wrapped", "confidence_score": 0.9},
        RENAMED: {"evidence": "wrapped rename", "confidence_score": 0.8},
    }})
    fa._update_potentially_vulnerable_function()
    assert list(fa.potentially_vulnerable_functions) == [CANON]
    assert [r["key"] for r in fa.rejected_findings] == [RENAMED]


def test_name_keyed_list_unwraps_then_filters():
    fa = _make_analyzer([{"name": CANON, "evidence": "ok", "confidence_score": 0.9},
                         {"name": RENAMED, "evidence": "bad", "confidence_score": 0.8}])
    fa._update_potentially_vulnerable_function()
    assert list(fa.potentially_vulnerable_functions) == [CANON]
    assert [r["key"] for r in fa.rejected_findings] == [RENAMED]


def test_trace_wide_memo_id_accepted_but_no_beyond_trace():
    # A memo-derived id (observed in trace but not a selected target) is accepted
    # - parity with the console's trace-wide allowed set. Anything absent from
    # the trace is still rejected.
    other = "0xdeadbeef_0x1111111111111111111111111111111111111111"
    fa = _make_analyzer(
        {other: {"evidence": "observed but not selected", "confidence_score": 0.6},
         "0x12345678_0x2222222222222222222222222222222222222222": {
             "evidence": "not in trace", "confidence_score": 0.6}},
        memo_extra={"0xdeadbeef::0x1111111111111111111111111111111111111111":
                    [{"depth": [0]}]},
    )
    fa._update_potentially_vulnerable_function()
    assert list(fa.potentially_vulnerable_functions) == [other]
    assert [r["key"] for r in fa.rejected_findings] == [
        "0x12345678_0x2222222222222222222222222222222222222222"]


def test_accepted_id_never_expands_beyond_checked_trace():
    # Every accepted id must correspond to a (function, address) pair present in
    # the checked trace universe (functions_to_be_inspected keys + memo entries).
    fa = _make_analyzer({CANON: {"evidence": "real", "confidence_score": 0.9},
                         RENAMED: {"evidence": "bad", "confidence_score": 0.8}})
    fa._update_potentially_vulnerable_function()
    universe = set(fa.functions_to_be_inspected) | {
        k.replace("::", "_", 1) for k in fa.tx_analysis["function_call_loc_memo"]}
    assert set(fa.potentially_vulnerable_functions) <= universe


def test_empty_and_emptydict_results_noop():
    fa = _make_analyzer({})
    fa._update_potentially_vulnerable_function()
    assert fa.potentially_vulnerable_functions == {}
    assert fa.rejected_findings == []


def test_malformed_string_result_rejected_not_crash():
    fa = _make_analyzer("not json at all")
    fa._update_potentially_vulnerable_function()
    assert fa.potentially_vulnerable_functions == {}
    assert len(fa.rejected_findings) == 1
    assert fa.rejected_findings[0]["reason"] == "malformed_model_output"


def test_none_result_rejected_not_crash():
    fa = _make_analyzer(None)
    fa._update_potentially_vulnerable_function()
    assert fa.potentially_vulnerable_functions == {}
    assert fa.rejected_findings[0]["reason"] == "malformed_model_output"


def test_junk_list_result_rejected_not_crash():
    fa = _make_analyzer([1, 2, 3])
    fa._update_potentially_vulnerable_function()
    assert fa.potentially_vulnerable_functions == {}
    assert fa.rejected_findings[0]["reason"] == "malformed_model_output"


def test_mixed_list_preserves_valid_and_rejects_junk():
    fa = _make_analyzer([{"name": CANON, "evidence": "real", "confidence_score": 0.9}, 42])
    fa._update_potentially_vulnerable_function()
    assert list(fa.potentially_vulnerable_functions) == [CANON]
    assert fa.rejected_findings[0]["reason"] == "malformed_model_output"
