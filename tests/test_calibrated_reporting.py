"""Exercise real Stage 3 reporting with controlled upstream-stage boundaries.

Inputs below are synthetic scoring data, not an on-chain trace or ground truth.
No RPC, model request or trained-calibrator correctness is verified here.
"""
import copy
from types import SimpleNamespace

import pytest

from faultseeker.core import pipeline as module
from faultseeker.core.confidence_scorer import calibrated_confidence


@pytest.fixture
def run_pipeline(monkeypatch, tmp_path):
    heuristic = {
        "overall": 0.6025,
        "level": "moderate",
        "components": {"pattern_match": 0.8, "code_evidence": 0.35,
                       "txn_consistency": 0.42, "llm_confidence": 0.85},
        "explanation": ["Overall confidence: 60.2% (moderate)"],
    }
    original = [{"function": name, "address": "synthetic-address",
                 "evidence": ["Controlled scoring test"], "confidence": copy.deepcopy(heuristic)}
                for name in ("first", "second")]
    model = tmp_path / "calibrator.json"
    model.write_text("{}", encoding="utf-8")
    config = SimpleNamespace(output_dir=str(tmp_path), calibration_model_path=str(model),
                             human_in_loop=False, track_cost=False)
    pipeline = module.FaultSeekerPipeline(config)
    monkeypatch.setattr(pipeline, "_initialize_agents", lambda: None)
    forensics = SimpleNamespace(
        transaction_hash="synthetic-calibration-test", chain="eth", trace={},
        repeated_patterns=[], function_call_loc_memo={}, balance_change={},
        potential_attacker=[], potential_victim=[], signals={}, rule_confidence=0.0,
        duration=0, get_function_count=lambda: 2)
    pipeline.forensics_orchestrator = SimpleNamespace(
        run=lambda *args: (forensics, {}, {}),
        txn_sequencer=SimpleNamespace(save_visualization=lambda path: None))
    pipeline.function_ranker = SimpleNamespace(rank=lambda *args: SimpleNamespace(address_list=[]))
    pipeline.function_analyzer = SimpleNamespace(run=lambda *args: {"finalized_vulnerable_functions": [{}]})
    monkeypatch.setattr(module.ConfidenceScorer, "score_all", lambda *args: copy.deepcopy(original))

    def run(predictions):
        predictions = iter(predictions)
        def predict(row):
            value = next(predictions)
            if isinstance(value, Exception):
                raise value
            return value
        monkeypatch.setattr(module.LogisticConfidenceCalibrator, "load",
                            lambda path: SimpleNamespace(predict_proba=predict))
        return pipeline.analyze_transaction(txn_hash="synthetic-calibration-test", chain="eth"), original
    return run


def test_real_stage3_calibration_updates_level_explanation_and_evidence(run_pipeline):
    report, original = run_pipeline([0.9941, 0.1])
    confidence = report["scored_functions"][0]["confidence"]
    assert confidence["overall"] == 0.9941
    assert confidence["level"] == "very_high"
    assert "99.4%" in confidence["explanation"][0]
    assert confidence["heuristic_confidence"] == original[0]["confidence"]
    assert confidence["components"] == original[0]["confidence"]["components"]
    assert report["evidence_cards"][0]["confidence"] == confidence
    assert report["scored_functions"][1]["confidence"]["level"] == "very_low"


@pytest.mark.parametrize("failed_prediction", [RuntimeError("Controlled calibration failure"),
                                              float("nan"), float("inf"), -0.1, 1.1])
def test_failed_second_calibration_preserves_all_heuristic_results(run_pipeline, failed_prediction):
    report, original = run_pipeline([0.9941, failed_prediction])
    assert report["scored_functions"] == original
    assert [card["confidence"] for card in report["evidence_cards"]] == [
        item["confidence"] for item in original]


def test_calibrated_order_and_evidence_cards_agree(run_pipeline):
    report, _ = run_pipeline([0.1, 0.9941])
    assert [item["function"] for item in report["scored_functions"]] == ["second", "first"]
    assert [card["function_signature"]["function"] for card in report["evidence_cards"]] == ["second", "first"]
    assert report["evidence_cards"][0]["confidence"]["level"] == "very_high"


@pytest.mark.parametrize("probability,level", [(0.0, "very_low"), (0.3, "low"), (0.5, "moderate"),
                                               (0.7, "high"), (0.9, "very_high"), (1.0, "very_high"),
                                               (0.69994, "moderate"), (0.69996, "high")])
def test_reported_level_matches_the_stored_probability(probability, level):
    result = calibrated_confidence({}, probability, "controlled-model")
    assert result["level"] == level
    assert result["overall"] == round(probability, 4)


@pytest.mark.parametrize("probability", [-0.1, 1.1, float("nan"), float("inf"), -float("inf"), True, False])
def test_invalid_calibration_probability_is_not_reported(probability):
    with pytest.raises(ValueError):
        calibrated_confidence({}, probability, "controlled-model")


def test_heuristic_evidence_is_preserved_without_mutating_the_input():
    heuristic = {"overall": 0.6025, "level": "moderate", "components": {"code_evidence": 0.35},
                 "explanation": ["Overall confidence: 60.2% (moderate)"]}
    original = copy.deepcopy(heuristic)
    report = calibrated_confidence(heuristic, 0.9941, "controlled-model")
    assert heuristic == original
    assert report["heuristic_confidence"] == original
    report["components"]["code_evidence"] = 0
    assert heuristic == original and report["heuristic_confidence"] == original
