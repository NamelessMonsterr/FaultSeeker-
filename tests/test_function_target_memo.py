"""Synthetic ranker-schema targets; actual review method, no model/source calls."""
from copy import deepcopy
from types import SimpleNamespace

from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
from faultseeker.function_analysis.function_ranker import FunctionRanker

A, B, C = ["0x" + digit * 40 for digit in "123"]
SELECTOR = "0x12345678"


def review(targets, *, created=None, patterns=None, ranking=None):
    analyzer = FunctionAnalyzer.__new__(FunctionAnalyzer)
    analyzer.functions_to_be_inspected = {
        function + "_" + address: {"count": 1, "calls": [{"depth": [], "params": "0x"}]}
        for function, address in targets
    }
    analyzer.address_calls_with_created_contract_in_params = deepcopy(created or {})
    analyzer.repeated_patterns = deepcopy(patterns or [])
    if ranking is not None:
        analyzer.functions_to_be_inspected = deepcopy(ranking.functions_to_be_inspected)
        analyzer.address_calls_with_created_contract_in_params = deepcopy(ranking.address_calls_with_created_contract_in_params)
        analyzer.repeated_patterns = deepcopy(ranking.repeated_patterns)
    analyzer.trace = []
    analyzer.understanding_result = "controlled"
    analyzer.potentially_vulnerable_functions = {}
    analyzer._prepare_children_call_memo = lambda selected: None
    analyzer._retrieve_related_info = lambda address, function: {}
    analyzer._retrieve_chidlren_calls_memo_single = lambda function, address: None
    analyzer.select_high_appearance_count_children_calls = lambda: []
    analyzed = []
    analyzer._function_analysis_init = lambda: analyzed.append(deepcopy(analyzer.function_call_info_summary))
    analyzer._review_function_calls()
    return analyzed, analyzer


def pattern(function, address):
    return {"pattern": [{"function": function, "address": address, "depth": []}], "repeats": 4}


def created_group(function, addresses):
    return {function: {"count": len(addresses), "address": addresses,
        "calls": [{"address": address, "depth": [], "params": "0x"} for address in addresses]}}


def test_same_selector_at_different_addresses_is_analyzed_separately():
    calls = [{"function": SELECTOR, "address": address, "gas": 1, "params": "0x", "depth": []}
             for address in (A, B)]
    forensics = SimpleNamespace(address_calls_with_created_contract=[],
                                functions_to_be_inspected={"function_name_with_hash": calls})
    ranking = FunctionRanker().rank(forensics, {"repeated_patterns": {}})
    assert len(ranking.functions_to_be_inspected) == 2
    analyzed, analyzer = review([], ranking=ranking)
    assert [(row["function"], row["address"]) for row in analyzed] == [(SELECTOR, A), (SELECTOR, B)]
    assert all("analysis_result" in entry for entry in analyzer.functions_to_be_inspected.values())


def test_repeated_pattern_does_not_hide_same_selector_at_another_address():
    analyzed, _ = review([(SELECTOR, A), (SELECTOR, B)], patterns=[pattern(SELECTOR, A)])
    assert len(analyzed) == 2
    assert analyzed[0]["pattern"][0]["address"] == A
    assert analyzed[1]["address"] == B


def test_created_group_marks_its_addresses_without_hiding_another_target():
    analyzed, _ = review([(SELECTOR, A), (SELECTOR, B), (SELECTOR, C)],
                         created=created_group(SELECTOR, [A, B]))
    assert len(analyzed) == 2
    assert {row["address"] for row in analyzed[0]["calls"]} == {A, B}
    assert analyzed[1]["address"] == C


def test_exact_pair_is_not_reanalyzed_across_all_three_groups():
    analyzed, _ = review([(SELECTOR, A)], created=created_group(SELECTOR, [A]),
                         patterns=[pattern(SELECTOR, A)])
    assert len(analyzed) == 1


def test_function_names_with_underscores_preserve_target_identity():
    function = "inspect_campaign"
    analyzed, _ = review([(function, A), (function, B)], created=created_group(function, [A]))
    assert len(analyzed) == 2
    assert analyzed[0]["function"] == function
    assert analyzed[1]["function"] == function and analyzed[1]["address"] == B


def test_addresses_are_case_insensitive_but_function_names_are_not():
    mixed_address = "0x" + "aB" * 20
    analyzed, _ = review([("Inspect", mixed_address), ("Inspect", mixed_address.lower()),
                          ("inspect", mixed_address)])
    assert [(row["function"], row["address"]) for row in analyzed] == [
        ("Inspect", mixed_address), ("inspect", mixed_address)]
