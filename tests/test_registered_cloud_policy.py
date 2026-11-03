"""Policy-only regressions with actual analyzer loops and no model requests."""
from types import SimpleNamespace

import pytest

from faultseeker.utils import agent
from faultseeker.prompts import local_model_prompts as prompts
from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer


@pytest.fixture
def registered(monkeypatch):
    # Replacement (not mutation) mirrors the console's per-run registration.
    monkeypatch.setattr(agent, "PROVIDER_CONFIG", {
        **agent.PROVIDER_CONFIG,
        "itera/": ("https://model.invalid/v1", "ITERA_API_KEY"),
    })


def test_registered_cloud_uses_cloud_prompts_and_tracks_registry_replacement(registered, monkeypatch):
    model = "itera/qwen3.8-27b"
    assert not prompts.is_local_model(model)
    assert type(prompts.get_worker_prompts(model)) is prompts.WorkerPrompts
    assert type(prompts.get_vuln_prompts(model)) is prompts.VulnerabilityAnalysisPrompts
    monkeypatch.setattr(agent, "PROVIDER_CONFIG", {k: v for k, v in agent.PROVIDER_CONFIG.items() if k != "itera/"})
    assert prompts.is_local_model(model)
    assert type(prompts.get_worker_prompts(model)) is prompts.LocalWorkerPrompts


@pytest.mark.parametrize("model,local", [("gpt-4o-mini", False), ("gemini-2.0-flash", False),
    ("phi3:mini", True), ("unregistered/model", True)])
def test_existing_cloud_and_unknown_local_prompt_policy(registered, model, local):
    assert prompts.is_local_model(model) is local


@pytest.mark.parametrize("method,cloud_iterations,local_iterations", [
    ("_function_analysis_init", 3, 8), ("_txn_analysis_init", 2, 3)])
@pytest.mark.parametrize("model,cloud", [("itera/qwen3.8-27b", True),
    ("gpt-4o-mini", True), ("phi3:mini", False)])
def test_actual_analysis_loop_uses_registered_provider_policy(registered, method, cloud_iterations, local_iterations, model, cloud):
    analyzer = FunctionAnalyzer.__new__(FunctionAnalyzer)
    analyzer.txn_analyzer_model = model
    analyzer.function_call_info_summary = {}
    analyzer.understanding_result = "controlled understanding"
    analyzer.potentially_vulnerable_functions = {}
    analyzer.function_prompts = SimpleNamespace(function_analysis_init_prompt="{task_tree}",
        check_analysis_adequacy="adequacy", check_analysis_adequacy_alt="adequacy")
    analyzer.reasoning_agent = SimpleNamespace(query=lambda *a, **kw: "controlled task tree")
    analyzer.organization_agent = SimpleNamespace(query=lambda *a, **kw: "no")
    for name in ("_update_current_understanding", "_perform_task", "_update_task_tree",
                 "_update_potentially_vulnerable_function"):
        setattr(analyzer, name, lambda *a, **kw: None)
    analyzer._temp_check = lambda: False
    selected = []
    def select():
        selected.append(True)
        return {"task": "controlled nonempty task"}
    analyzer._select_task = select
    getattr(analyzer, method)()
    assert len(selected) == (cloud_iterations if cloud else local_iterations)
