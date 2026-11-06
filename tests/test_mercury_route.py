"""Mercury (Inception Labs) provider routing tests.

Mercury models are OpenAI-compatible but reasoning-style: without
reasoning_effort='instant' they can spend the whole completion budget on
encrypted reasoning and return empty content. These tests pin the engine-side
dispatch so 'mercury-*' models go to the Mercury endpoint with the right key
and reasoning control, mirroring the console adapter.
"""

from faultseeker.utils import agent as agent_mod
from faultseeker.utils.agent import PROVIDER_CONFIG, UniversalAgent, build_provider_agent
from faultseeker.core.llm_router import HybridLLMRouter


def test_mercury_in_provider_config():
    base_url, env_var = PROVIDER_CONFIG['mercury-']
    assert base_url == 'https://api.inceptionlabs.ai/v1'
    assert env_var == 'MERCURY_API_KEY'


def test_build_provider_agent_routes_mercury_to_universal(monkeypatch):
    monkeypatch.setenv('MERCURY_API_KEY', 'test-key')
    agent = build_provider_agent('task', 'mercury-3')
    assert isinstance(agent, UniversalAgent)
    assert agent.base_url == 'https://api.inceptionlabs.ai/v1'
    assert agent.api_key == 'test-key'


def test_mercury_base_url_env_override(monkeypatch):
    monkeypatch.setenv('MERCURY_API_KEY', 'test-key')
    monkeypatch.setenv('MERCURY_BASE_URL', 'https://mercury.example.test/v1')
    agent = build_provider_agent('task', 'mercury-3')
    assert agent.base_url == 'https://mercury.example.test/v1'


def test_send_message_adds_reasoning_effort_instant(monkeypatch):
    monkeypatch.setenv('MERCURY_API_KEY', 'test-key')
    agent = build_provider_agent('task', 'mercury-3')
    seen = {}

    class _FakeCompletion:
        class _Usage:
            prompt_tokens = 1
            completion_tokens = 1
        usage = _Usage()
        choices = [type('C', (), {'message': type('M', (), {'content': '{"ok": true}'})()})()]

    def fake_call(create_client, kwargs, model):
        seen['kwargs'] = kwargs
        return _FakeCompletion()

    monkeypatch.setattr(agent_mod, '_llm_call_with_retry', fake_call)
    agent.query('hello', temperature=0)
    assert seen['kwargs'].get('extra_body') == {'reasoning_effort': 'instant'}


def test_non_mercury_models_unaffected(monkeypatch):
    monkeypatch.setenv('XAI_API_KEY', 'test-key')
    agent = build_provider_agent('task', 'grok-3')
    seen = {}

    class _FakeCompletion:
        usage = None
        choices = [type('C', (), {'message': type('M', (), {'content': 'ok'})()})()]

    def fake_call(create_client, kwargs, model):
        seen['kwargs'] = kwargs
        return _FakeCompletion()

    monkeypatch.setattr(agent_mod, '_llm_call_with_retry', fake_call)
    agent.query('hello', temperature=0)
    assert 'extra_body' not in seen['kwargs']


def test_router_classifies_mercury_as_cloud():
    router = HybridLLMRouter(track_cost=False)
    assert not router._is_local_model('mercury-3')
    assert router._is_local_model('phi3:mini')
    assert not router._is_local_model('gpt-4o')
