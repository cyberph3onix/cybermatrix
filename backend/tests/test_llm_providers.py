"""The real GeminiLlm / AnthropicLlm classes (and the real Anthropic SDK) against mocked HTTP.

No keys, no network. Checks the request we send, how we parse the answer, that failures become LlmUnavailable, and
that a key never appears in an error. Provider choice: Gemini first, Anthropic as fallback, else no LLM."""
import json

import httpx
import pytest
import respx

from app.ai import llm as llm_mod
from app.ai.llm import AnthropicLlm, GeminiLlm, LlmUnavailable, default_llm

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
GEMINI_RE = r"https://generativelanguage\.googleapis\.com/v1beta/models/.+:generateContent"
SCHEMA = {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]}
SECRET_A, SECRET_G = "sk-ant-SECRET-123", "AIzaSECRET-456"


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    """These tests must never reach a real API, even by mistake (a fake key was once sent out by a bad mock)."""
    import httpx2

    async def boom(self, request):
        raise AssertionError(f"real network request attempted: {request.url}")
    monkeypatch.setattr(httpx2.AsyncHTTPTransport, "handle_async_request", boom)
    # httpx (Gemini) is covered by respx.mock, which already refuses unmatched requests


@pytest.fixture(autouse=True)
def _no_retry_sleep(monkeypatch):
    try:  # the Anthropic SDK backs off before its one retry; don't wait in tests
        from anthropic._base_client import BaseClient
        monkeypatch.setattr(BaseClient, "_calculate_retry_timeout", lambda *a, **k: 0.0)
    except Exception:  # noqa: BLE001
        pass


def tool_use(name, payload):
    return {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-haiku-5-5",
            "content": [{"type": "tool_use", "id": "tu_1", "name": name, "input": payload}],
            "stop_reason": "tool_use", "usage": {"input_tokens": 5, "output_tokens": 5}}


# ---------- provider selection ----------

def test_gemini_is_preferred_anthropic_is_the_fallback_and_none_means_no_llm(monkeypatch):
    for k in ("GEMINI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_MODEL"):
        monkeypatch.delenv(k, raising=False)
    assert default_llm() is None
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)
    assert isinstance(default_llm(), AnthropicLlm) and default_llm().model == "claude-haiku-5-5"
    monkeypatch.setenv("GEMINI_API_KEY", SECRET_G)
    g = default_llm()
    assert isinstance(g, GeminiLlm) and g.model == llm_mod.GEMINI_MODEL
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
    assert default_llm().model == "gemini-3.5-flash-lite"


def test_missing_keys_raise_unavailable_not_keyerror(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(LlmUnavailable):
        AnthropicLlm()
    with pytest.raises(LlmUnavailable):
        GeminiLlm()


# ---------- Anthropic (the fallback) ----------
# The Anthropic SDK 2.x uses `httpx2`, not `httpx`, so respx can't see it: inject a mock transport instead.

def anthropic_llm(handler):
    import httpx2
    calls = []

    def wrapped(request):
        calls.append(request)
        return handler(request)

    return AnthropicLlm(http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(wrapped))), calls


def ok(payload):
    import httpx2
    return lambda request: httpx2.Response(200, json=payload)


async def test_anthropic_sends_a_forced_tool_call_and_parses_the_tool_use_block(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)
    llm, calls = anthropic_llm(ok(tool_use("explain", {"summary": "ok"})))
    out = await llm.call_tool(system="SYS", user="USER", tool_name="explain", schema=SCHEMA, max_tokens=123)
    assert out == {"summary": "ok"}
    req = calls[0]
    body = json.loads(req.content)
    assert str(req.url) == ANTHROPIC_URL
    assert SECRET_A in (req.headers.get("x-api-key") or req.headers.get("authorization", ""))  # SDK 2.x: Bearer
    assert SECRET_A not in str(req.url)
    assert body["model"] == "claude-haiku-5-5" and body["max_tokens"] == 123 and body["system"] == "SYS"
    assert body["messages"] == [{"role": "user", "content": "USER"}]
    assert body["tool_choice"] == {"type": "tool", "name": "explain"}
    assert body["tools"][0]["name"] == "explain" and body["tools"][0]["input_schema"] == SCHEMA


def err(status, kind, msg):
    import httpx2
    return lambda request: httpx2.Response(status, json={"type": "error", "error": {"type": kind, "message": msg}})


@pytest.mark.parametrize("handler", [
    err(401, "authentication_error", "bad key sk-ant-SECRET-123"),
    err(429, "rate_limit_error", "slow down"),
    err(500, "api_error", "boom"),
    ok({"id": "m", "type": "message", "role": "assistant", "model": "x", "stop_reason": "end_turn",
        "content": [{"type": "text", "text": "I refuse"}], "usage": {"input_tokens": 1, "output_tokens": 1}}),
    ok(tool_use("some_other_tool", {"summary": "wrong tool"})),
], ids=["401", "429", "500", "no-tool-use", "wrong-tool"])
async def test_anthropic_failures_become_llm_unavailable_without_leaking_the_key(monkeypatch, handler):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)
    llm, _ = anthropic_llm(handler)
    with pytest.raises(LlmUnavailable) as e:
        await llm.call_tool(system="s", user="u", tool_name="explain", schema=SCHEMA)
    assert SECRET_A not in str(e.value) and "SECRET" not in repr(e.value)


async def test_anthropic_timeout_becomes_llm_unavailable(monkeypatch):
    import httpx2
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)

    def slow(request):
        raise httpx2.ConnectTimeout("slow")
    llm, _ = anthropic_llm(slow)
    with pytest.raises(LlmUnavailable):
        await llm.call_tool(system="s", user="u", tool_name="explain", schema=SCHEMA)


async def test_message_pipeline_works_end_to_end_on_the_anthropic_fallback(monkeypatch):
    """Real AnthropicLlm + real Anthropic SDK + the real message pipeline; only the HTTP transport is mocked."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)
    from app.pipeline_message import assess_message
    from tests.test_message import SMS
    llm, calls = anthropic_llm(ok(tool_use("report_signals", {"signals": [
        {"check_id": "MSG.URGENCY", "quote": "within 24 hours"}, {"check_id": "URL.INTEL.GSB", "quote": "not allowed"}]})))
    r = await assess_message(SMS, llm=llm)
    ids = {f.check_id for f in r.findings}
    assert "MSG.URGENCY" in ids and "URL.INTEL.GSB" not in ids  # allowed ids only
    run = next(c for c in r.check_runs if c.check_group == "message.signals")
    assert run.status == "completed" and run.source == "llm:claude-haiku-5-5"
    sent = json.loads(calls[0].content)["messages"][0]["content"]
    assert sent.startswith("<untrusted_input>") and "Ramesh" not in sent and "482913" not in sent  # redacted first


# ---------- Gemini (the default) ----------

def gemini_ok(payload):
    return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": json.dumps(payload)}]}}]})


@respx.mock
async def test_gemini_request_shape_key_in_header_and_thinking_off(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", SECRET_G)
    route = respx.post(url__regex=GEMINI_RE).mock(return_value=gemini_ok({"summary": "ok"}))
    out = await GeminiLlm().call_tool(system="SYS", user="USER", tool_name="explain", schema=SCHEMA, max_tokens=99)
    assert out == {"summary": "ok"}
    req = route.calls[0].request
    body = json.loads(req.content)
    assert req.headers["x-goog-api-key"] == SECRET_G and SECRET_G not in str(req.url)
    cfg = body["generationConfig"]
    assert cfg["responseJsonSchema"] == SCHEMA and cfg["responseMimeType"] == "application/json"
    assert cfg["maxOutputTokens"] == 99 and cfg["thinkingConfig"] == {"thinkingBudget": 0} and cfg["temperature"] == 0
    assert body["systemInstruction"]["parts"][0]["text"] == "SYS"
    assert body["contents"][0]["parts"][0]["text"] == "USER"


@respx.mock
@pytest.mark.parametrize("response", [
    httpx.Response(429, json={"error": {"code": 429, "message": "quota"}}),
    httpx.Response(400, json={"error": {"code": 400, "message": "bad schema"}}),
    httpx.Response(200, json={"candidates": []}),
    httpx.Response(200, json={"promptFeedback": {"blockReason": "SAFETY"}}),
    httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "not json {"}]}}]}),
    httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "[1, 2]"}]}}]}),
])
async def test_gemini_failures_become_llm_unavailable_without_leaking_the_key(monkeypatch, response):
    monkeypatch.setenv("GEMINI_API_KEY", SECRET_G)
    respx.post(url__regex=GEMINI_RE).mock(return_value=response)
    with pytest.raises(LlmUnavailable) as e:
        await GeminiLlm().call_tool(system="s", user="u", tool_name="explain", schema=SCHEMA)
    assert SECRET_G not in str(e.value) and "SECRET" not in repr(e.value)
