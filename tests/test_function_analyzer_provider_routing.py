"""Actual FunctionAnalyzer construction/query with synthetic provider responses."""
import json

import httpx
from openai import OpenAI
import pytest

from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer
from faultseeker.utils import agent, utils

MODEL = "itera/qwen3.8-27b"
AGENTS = ("reasoning_agent", "generation_agent", "processing_agent",
          "organization_agent", "children_call_filtering_agent", "agent")


@pytest.fixture
def itera_registration(monkeypatch):
    monkeypatch.setitem(agent.PROVIDER_CONFIG, "itera/", ("https://model.invalid/v1", "ITERA_API_KEY"))
    monkeypatch.setenv("ITERA_API_KEY", "dummy-only-itera-key")
    monkeypatch.setenv("OPENAI_API_KEY", "dummy-only-openai-key")


def test_function_analyzer_uses_registered_provider_for_all_six_agents(itera_registration):
    analyzer = FunctionAnalyzer(model=MODEL)
    assert all(isinstance(getattr(analyzer, name), agent.UniversalAgent) for name in AGENTS)
    assert all(getattr(analyzer, name).base_url == "https://model.invalid/v1" for name in AGENTS)


def test_function_analyzer_query_reaches_cloud_instead_of_swallowing_local_failure(itera_registration, monkeypatch):
    local_calls, cloud_calls = [], []
    def unavailable_local(**kwargs):
        local_calls.append(kwargs)
        raise RuntimeError("Controlled missing local model")
    monkeypatch.setattr(agent, "chat", unavailable_local)
    def handle(request):
        cloud_calls.append(json.loads(request.content))
        return httpx.Response(200, json={"id": "mock", "object": "chat.completion", "created": 0,
            "model": MODEL, "choices": [{"index": 0, "message": {"role": "assistant", "content": "Ready"},
                                       "finish_reason": "stop"}]})
    client = OpenAI(api_key="dummy-only-itera-key", base_url="https://model.invalid/v1",
                    max_retries=0, http_client=httpx.Client(transport=httpx.MockTransport(handle)))
    monkeypatch.setattr(agent, "OpenAI", lambda **kwargs: client)
    try:
        analyzer = FunctionAnalyzer(model=MODEL)
        answer = analyzer.reasoning_agent.query("Controlled routing check", format="str")
        assert answer == "Ready"
        assert local_calls == []
        assert len(cloud_calls) == 1 and cloud_calls[0]["model"] == MODEL
    finally:
        client.close()


@pytest.mark.parametrize("model,expected", [("gpt-4o-mini", agent.GPTAgent),
    ("o3-mini", agent.GPTAgent), ("gemini-2.0-flash", agent.UniversalAgent),
    ("phi3:mini", agent.OllmaAgent)])
def test_legacy_import_contract_delegates_to_central_factory(monkeypatch, model, expected):
    monkeypatch.setenv("OPENAI_API_KEY", "dummy-only-key")
    monkeypatch.setenv("GOOGLE_API_KEY", "dummy-only-key")
    built = utils.build_agent("Controlled task", "  " + model.upper() + "  ")
    assert isinstance(built, expected)
    assert built.model == model


def test_legacy_wrapper_respects_current_central_factory(monkeypatch):
    seen = []
    sentinel = object()
    def factory(task, model):
        seen.append((task, model))
        return sentinel
    monkeypatch.setattr(agent, "build_provider_agent", factory)
    assert utils.build_agent("Unchanged task", "  ITERA/QWEN3.8-27B  ") is sentinel
    assert seen == [("Unchanged task", MODEL)]


def test_legacy_wrapper_preserves_central_unsupported_provider_failure():
    with pytest.raises(NotImplementedError, match="not supported"):
        utils.build_agent("Controlled task", "claude-unsupported")
