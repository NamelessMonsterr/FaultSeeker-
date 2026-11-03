"""Mocked urllib request contracts; no public provider is called."""
import io
import json
import urllib.error

import pytest

from faultseeker.utils import rpc_provider as rpc


def test_rpc_request_identifies_application_and_preserves_wire_contract(monkeypatch):
    seen = []
    body = b'{"jsonrpc":"2.0","id":7,"method":"eth_chainId","params":[]}'
    def open_request(request, **kwargs):
        seen.append((request, kwargs))
        return io.BytesIO(b'{"jsonrpc":"2.0","id":7,"result":"0x1"}')
    monkeypatch.setattr(rpc.urllib.request, "urlopen", open_request)
    assert rpc._http_post("https://rpc.invalid/", body, timeout=17) == {
        "jsonrpc": "2.0", "id": 7, "result": "0x1"}
    assert len(seen) == 1
    request, kwargs = seen[0]
    assert request.get_header("User-agent") == "FaultSeeker"
    assert request.get_header("Content-type") == "application/json"
    assert request.get_method() == "POST"
    assert request.data == body and request.full_url == "https://rpc.invalid/"
    assert kwargs == {"timeout": 17}


@pytest.mark.parametrize("status,expected", [(401, rpc._AuthError), (403, rpc._AuthError),
    (429, rpc._RateLimitError), (500, rpc._ServerError), (502, rpc._ServerError),
    (404, urllib.error.HTTPError)])
def test_http_error_classification_and_attempt_count_unchanged(monkeypatch, status, expected):
    attempts = []
    def fail(request, **kwargs):
        attempts.append(request)
        raise urllib.error.HTTPError(request.full_url, status, "Controlled failure", {}, None)
    monkeypatch.setattr(rpc.urllib.request, "urlopen", fail)
    with pytest.raises(expected):
        rpc._http_post("https://rpc.invalid/", b"{}", timeout=4)
    assert len(attempts) == 1


def test_timeout_propagates_without_retry(monkeypatch):
    attempts = []
    def fail(request, **kwargs):
        attempts.append(kwargs)
        raise TimeoutError("Controlled timeout")
    monkeypatch.setattr(rpc.urllib.request, "urlopen", fail)
    with pytest.raises(TimeoutError):
        rpc._http_post("https://rpc.invalid/", b"{}", timeout=3)
    assert attempts == [{"timeout": 3}]


def test_invalid_json_remains_an_error(monkeypatch):
    monkeypatch.setattr(rpc.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(b"not json"))
    with pytest.raises(json.JSONDecodeError):
        rpc._http_post("https://rpc.invalid/", b"{}")
