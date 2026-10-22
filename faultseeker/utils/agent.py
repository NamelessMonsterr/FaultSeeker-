import abc
import json
import logging
import re
import time
from typing import Dict, List, Any, Union, Optional
import traceback
import threading
from ollama import chat
from openai import OpenAI
import os
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# ── Local model tuning constants ──────────────────────────────────────────────
LOCAL_MODEL_TIMEOUT_SECS = 2       # Hard timeout per Ollama call (reduced for fast fail-fast when offline)
LOCAL_MODEL_NUM_CTX      = 4096    # Explicit context window for Ollama
LOCAL_MODEL_MAX_PROMPT   = 6000    # Truncate prompts longer than this (chars)
LOCAL_MODEL_MAX_TURNS    = 2       # History turns to keep for local models
LOCAL_MODEL_JSON_RETRIES = 5       # More retries since small models are flaky


# ── Provider registry ──────────────────────────────────────────────────
# Maps model-name prefix → (base_url, env_var_for_api_key)
PROVIDER_CONFIG = {
    # OpenAI
    'gpt-':     ('https://api.openai.com/v1',                                    'OPENAI_API_KEY'),
    'o1-':      ('https://api.openai.com/v1',                                    'OPENAI_API_KEY'),
    'o3-':      ('https://api.openai.com/v1',                                    'OPENAI_API_KEY'),
    'o4-':      ('https://api.openai.com/v1',                                    'OPENAI_API_KEY'),
    # xAI Grok (OpenAI-compatible)
    'grok-':    ('https://api.x.ai/v1',                                          'XAI_API_KEY'),
    # Alibaba Qwen via DashScope (OpenAI-compatible)
    'qwen-':    ('https://dashscope.aliyuncs.com/compatible-mode/v1',            'DASHSCOPE_API_KEY'),
    # Google Gemini (OpenAI-compatible endpoint)
    'gemini-':  ('https://generativelanguage.googleapis.com/v1beta/openai/',     'GOOGLE_API_KEY'),
    # NaraRouter / bynara (OpenAI-compatible free router, 7M tokens/day)
    'agnes':    ('https://router.bynara.id/v1',                                'NARAROUTER_API_KEY'),
    'jev':      ('https://router.bynara.id/v1',                                'NARAROUTER_API_KEY'),
    'laguna':   ('https://router.bynara.id/v1',                                'NARAROUTER_API_KEY'),
    'nemotron': ('https://router.bynara.id/v1',                                'NARAROUTER_API_KEY'),
    'minimax':  ('https://router.bynara.id/v1',                                'NARAROUTER_API_KEY'),
    # GroqCloud (OpenAI-compatible, free dev tier)
    'llama-':   ('https://api.groq.com/openai/v1',                             'GROQ_API_KEY'),
    'qwen/':    ('https://api.groq.com/openai/v1',                             'GROQ_API_KEY'),
    'openai/gpt-oss': ('https://api.groq.com/openai/v1',                       'GROQ_API_KEY'),
    'allam-':   ('https://api.groq.com/openai/v1',                             'GROQ_API_KEY'),
    # Anthropic Claude (NB: not OpenAI-compatible natively — requires anthropic sdk)
    'claude-':  ('https://api.anthropic.com/v1',                                 'ANTHROPIC_API_KEY'),
}

# Models that support native JSON response_format
JSON_MODE_MODELS = {
    'gpt-4o', 'gpt-4o-mini', 'gpt-4.1', 'gpt-4.1-mini', 'gpt-4.1-nano',
    'gpt-4-turbo',
    'grok-3', 'grok-3-mini', 'grok-2',
    'gemini-2.0-flash', 'gemini-1.5-pro', 'gemini-1.5-flash',
    'qwen-plus', 'qwen-turbo', 'qwen-max',
}


# ── Bounded LLM calls (console demo hardening) ────────────────────────────────
# Without an explicit client timeout the OpenAI SDK waits ~600s per attempt and
# retries internally, so one slow provider wedged a whole analysis run. These
# knobs bound every call; auth/quota failures are re-raised so the console's
# per-key rotation can engage instead of silently producing empty output.
LLM_CALL_TIMEOUT_SECS = int(os.getenv('FAULTSEEKER_LLM_TIMEOUT_SECS', '120'))
LLM_CALL_RETRIES = int(os.getenv('FAULTSEEKER_LLM_RETRIES', '4'))
# NaraRouter-class routers flap ~30% of calls (429/5xx/slow); give them room.
LLM_RETRY_BACKOFF_LADDER = [5, 15, 45, 90]


def _llm_call_with_retry(create_client, kwargs, model):
    """One chat.completions.create with bounded timeout + limited retries.

    Raises on auth/quota/not-found (caller rotates keys or fails fast) and on
    exhausted transient failures; returns the completion on success.
    """
    import random
    from openai import (APITimeoutError, APIConnectionError, RateLimitError,
                        AuthenticationError, PermissionDeniedError, NotFoundError,
                        BadRequestError, APIStatusError)
    transient = (APITimeoutError, APIConnectionError, RateLimitError)
    attempt = 0
    while True:
        client = create_client()
        try:
            return client.chat.completions.create(**kwargs)
        except (AuthenticationError, PermissionDeniedError, NotFoundError):
            raise                      # key/model problem: rotation-worthy
        except BadRequestError as e:
            msg = str(e).lower()
            if 'api key' in msg or 'incorrect api key' in msg or 'invalid api key' in msg:
                raise AuthenticationError(str(e))
            raise                      # genuine request problem: do not retry
        except APIStatusError as e:
            # Router-side 5xx flaps are transient; other status errors are not.
            if getattr(e, 'status_code', 0) < 500:
                raise
            attempt += 1
            if attempt > LLM_CALL_RETRIES:
                raise
            backoff = LLM_RETRY_BACKOFF_LADDER[min(attempt - 1, len(LLM_RETRY_BACKOFF_LADDER) - 1)] + random.uniform(0, 3)
            print(f"   [!] LLM call to {model} failed ({type(e).__name__} {getattr(e, 'status_code', '')}, attempt {attempt}); retrying in {int(backoff)}s...", flush=True)
            time.sleep(backoff)
        except transient as e:
            attempt += 1
            if attempt > LLM_CALL_RETRIES:
                raise                  # let the caller rotate keys / fail loudly
            backoff = LLM_RETRY_BACKOFF_LADDER[min(attempt - 1, len(LLM_RETRY_BACKOFF_LADDER) - 1)] + random.uniform(0, 3)
            print(f"   [!] LLM call to {model} failed ({type(e).__name__}, attempt {attempt}); retrying in {int(backoff)}s...", flush=True)
            time.sleep(backoff)


JSON_RETRY_PROMPT = (
    "Your previous response was not valid JSON. "
    "Return ONLY a valid JSON object or array. "
    "No explanations, no markdown fences, no extra text."
)


class AbstractAgent(abc.ABC):

    def __init__(
        self,
        task: str,
        model_name: str,
    ):
        self.model = model_name
        self.memory = []
        self._init_resources(task)

    def _init_resources(self, task):
        system_message = {
            "role": "system",
            "content": '\n'.join([task])
        }
        self.memory.append(system_message)

    # to be implemented in the child class
    def _send_message(self, user_message: str, temperature=0) -> str:
        pass

    def _record_router_query(
        self,
        prompt_len: int,
        resp_len: int,
        duration_ms: float,
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
    ):
        router = getattr(self, 'router', None)
        if router and hasattr(router, 'record_query'):
            agent_role = getattr(self, 'agent_role', '')
            tier = router.get_tier(agent_role=agent_role) if hasattr(router, 'get_tier') else 2
            router.record_query(
                model=self.model,
                tier=tier,
                prompt_length=prompt_len,
                response_length=resp_len,
                duration_ms=duration_ms,
                agent_role=agent_role,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )

    # ── Robust JSON parser (Fix 1) ─────────────────────────────────────
    def _extract_json(self, text: str):
        """
        Try to extract a JSON object/array from raw LLM text using
        multiple strategies in order of preference:
          1. json.loads on the stripped text
          2. Extract from ```json ... ``` fence
          3. Extract from ``` ... ``` fence
          4. Regex extraction of first {...} or [...]
          5. eval() fallback (last resort)
        """
        # Strategy 1 — clean and direct parse
        cleaned = text.strip().strip('`').strip()
        try:
            return json.loads(cleaned)
        except Exception:
            pass

        # Strategy 2 — ```json fence
        fence_json = re.search(r'```json\s*([\s\S]*?)```', text)
        if fence_json:
            try:
                return json.loads(fence_json.group(1).strip())
            except Exception:
                pass

        # Strategy 3 — generic ``` fence
        fence_generic = re.search(r'```\s*([\s\S]*?)```', text)
        if fence_generic:
            try:
                return json.loads(fence_generic.group(1).strip())
            except Exception:
                pass

        # Strategy 4 — regex for first {...} or [...]
        obj_match = re.search(r'(\{[\s\S]*\})', text)
        if obj_match:
            try:
                return json.loads(obj_match.group(1))
            except Exception:
                pass

        arr_match = re.search(r'(\[[\s\S]*\])', text)
        if arr_match:
            try:
                return json.loads(arr_match.group(1))
            except Exception:
                pass

        # Strategy 5 — all structural parsing failed; do NOT eval() LLM output
        # (eval on untrusted text is a critical security vulnerability)
        logger.warning("_extract_json: all JSON strategies failed; returning raw text for retry")
        raise ValueError("Invalid JSON from LLM — cannot parse response")

    def _process_json_response(self, response: str) -> Dict[str, Any]:
        try:
            return self._extract_json(response)
        except ValueError:
            return {}

    def _process_dict_response(self, response: str) -> Dict[str, Any]:
        try:
            result = self._extract_json(response)
        except ValueError:
            return [response]
        if isinstance(result, (dict, list)):
            return result
        return [response]

    def _process_response(self, response: str, format: str) -> Union[List[str], Dict[str, Any]]:
        if format == 'json':
            return self._process_json_response(response)
        elif format == 'dict':
            return self._process_dict_response(response)
        return response

    def _query_with_json_retry(self, user_message: str, temperature: float, max_retries: int = 3) -> Any:
        """
        Query the LLM and retry up to max_retries times if the output
        is not valid JSON. On each retry, inject a correction prompt.
        """
        result_raw = self._send_message(user_message, temperature)
        retries = 0
        while retries <= max_retries:
            try:
                return self._extract_json(result_raw)
            except ValueError:
                retries += 1
                if retries > max_retries:
                    logger.warning("JSON parsing failed after %d retries; returning empty dict", max_retries)
                    return {}
                logger.debug("JSON retry %d/%d", retries, max_retries)
                result_raw = self._send_message(JSON_RETRY_PROMPT, 0.0)  # Force temp=0 on retries

    def query(self, user_message: str, temperature=0, format='json') -> Any:
        if format == 'str':
            return self._send_message(user_message, temperature)

        # Use retry-enabled query for JSON formats
        try:
            return self._query_with_json_retry(user_message, temperature)
        except Exception as e:
            logger.error("query() failed completely: %s", e)
            return {}


class OllmaAgent(AbstractAgent):
    def __init__(self, task, model_name: str = "deepseek-r1:14b"):
        super().__init__(task, model_name)

    def _truncate_history(self, history, max_turns=LOCAL_MODEL_MAX_TURNS):
        """Keep only the system prompt + last max_turns pairs to stay within context."""
        system_prompt = history[0]
        message_pairs = history[1:]
        truncated = message_pairs[-(max_turns * 2):]
        return [system_prompt] + truncated

    def _send_message(self, user_message: str, temperature=0.0) -> str:
        # Cap prompt length so local model context window isn't blown out
        start_time = time.time()
        if len(user_message) > LOCAL_MODEL_MAX_PROMPT:
            logger.warning(
                "Prompt truncated: original length %d chars exceeds LOCAL_MODEL_MAX_PROMPT=%d",
                len(user_message), LOCAL_MODEL_MAX_PROMPT,
            )
            user_message = user_message[:LOCAL_MODEL_MAX_PROMPT] + "\n[TRUNCATED FOR LOCAL MODEL]"

        self.memory.append({"role": "user", "content": user_message})
        result_container = [None]
        error_container  = [None]
        raw_response_container = [None]

        def _call():
            try:
                response = chat(
                    model=self.model,
                    messages=self._truncate_history(self.memory),
                    options={
                        'temperature': temperature,
                        'num_ctx': LOCAL_MODEL_NUM_CTX,
                    }
                )
                raw_response_container[0] = response
                result_container[0] = response['message']['content']
            except Exception as e:
                error_container[0] = e

        t = threading.Thread(target=_call, daemon=True)
        t.start()
        t.join(timeout=LOCAL_MODEL_TIMEOUT_SECS)

        dur_ms = (time.time() - start_time) * 1000.0

        if t.is_alive():
            print(f"\n   [!] Local model '{self.model}' timed out after {LOCAL_MODEL_TIMEOUT_SECS}s. Returning empty.")
            self.memory.append({"role": "assistant", "content": ""})
            self._record_router_query(len(user_message), 0, dur_ms)
            return ""

        if error_container[0]:
            err = error_container[0]
            print(f"   [!] Local model '{self.model}' error: {type(err).__name__}: {err}")
            self.memory.append({"role": "assistant", "content": ""})
            self._record_router_query(len(user_message), 0, dur_ms)
            return ""

        assistant_response = result_container[0] or ""
        self.memory.append({"role": "assistant", "content": assistant_response})

        raw_resp = raw_response_container[0]
        inp_tok = raw_resp.get('prompt_eval_count') if isinstance(raw_resp, dict) else None
        out_tok = raw_resp.get('eval_count') if isinstance(raw_resp, dict) else None
        self._record_router_query(len(user_message), len(assistant_response), dur_ms, input_tokens=inp_tok, output_tokens=out_tok)

        return assistant_response

    def query(self, user_message: str, temperature=0.0, format='json') -> Any:
        """Override with local-model tuned settings: lower temp, more retries."""
        if format == 'str':
            return self._send_message(user_message, temperature)
        try:
            return self._query_with_json_retry(
                user_message, temperature=0.0,
                max_retries=LOCAL_MODEL_JSON_RETRIES
            )
        except Exception as e:
            raw = self._send_message(user_message, 0.0)
            return self._process_response(raw, format)


class GPTAgent(AbstractAgent):
    """OpenAI GPT agent (gpt-4o, gpt-4.1, o1, o3 etc.)"""

    def __init__(self, task, model_name):
        load_dotenv()
        self.openai_api_key = os.getenv('OPENAI_API_KEY')
        super().__init__(task, model_name=model_name)

    def _truncate_history(self, history, max_turns=1):
        system_prompt = history[0]
        message_pairs = history[1:]
        truncated = message_pairs[-(max_turns * 2):]
        return [system_prompt] + truncated

    def _send_message(self, user_message, temperature=0):
        start_time = time.time()
        try:
            user_message = user_message[:10000]
            self.memory.append({"role": "user", "content": user_message})
            kwargs = dict(
                messages=self._truncate_history(self.memory),
                model=self.model,
                temperature=temperature,
            )
            if self.model in JSON_MODE_MODELS or any(
                self.model.startswith(p) for p in ('gpt-4o', 'gpt-4.1', 'gpt-4-turbo')
            ):
                kwargs['response_format'] = {"type": "json_object"}
            chat_completion = _llm_call_with_retry(
                lambda: OpenAI(api_key=self.openai_api_key,
                               timeout=LLM_CALL_TIMEOUT_SECS, max_retries=0),
                kwargs, self.model)
            reply = chat_completion.choices[0].message.content or ""
            self.memory.append({"role": "assistant", "content": reply})

            dur_ms = (time.time() - start_time) * 1000.0
            usage = getattr(chat_completion, 'usage', None)
            inp_tok = getattr(usage, 'prompt_tokens', None) if usage else None
            out_tok = getattr(usage, 'completion_tokens', None) if usage else None
            self._record_router_query(len(user_message), len(reply), dur_ms, input_tokens=inp_tok, output_tokens=out_tok)

            return reply
        except Exception as e:
            # Auth/quota/timeout failures must propagate so the console worker
            # can rotate to a fallback key; only content-level problems are
            # swallowed into an empty reply.
            from openai import (APITimeoutError, APIConnectionError, RateLimitError,
                                AuthenticationError, PermissionDeniedError, NotFoundError,
                                APIStatusError)
            transient_fail = isinstance(e, (APITimeoutError, APIConnectionError, RateLimitError)) or \
                (isinstance(e, APIStatusError) and getattr(e, 'status_code', 0) >= 500)
            if transient_fail:
                fb = os.getenv('FAULTSEEKER_LLM_FALLBACK_MODEL', '').strip()
                if fb and fb != self.model:
                    print(f"   [!] {self.model} exhausted retries ({type(e).__name__}); trying fallback model {fb}", flush=True)
                    try:
                        fb_kwargs = dict(messages=self._truncate_history(self.memory),
                                         model=fb, temperature=0)
                        cc = _llm_call_with_retry(
                            lambda: OpenAI(api_key=self.api_key, base_url=self.base_url,
                                           timeout=LLM_CALL_TIMEOUT_SECS, max_retries=0),
                            fb_kwargs, fb)
                        reply = cc.choices[0].message.content or ""
                        self.memory.append({"role": "assistant", "content": reply})
                        return reply
                    except Exception as fb_e:  # noqa: BLE001
                        print(f"   [!] fallback model {fb} also failed ({type(fb_e).__name__})", flush=True)
                self.memory.append({"role": "assistant", "content": ''})
                raise
            if isinstance(e, (AuthenticationError, PermissionDeniedError, NotFoundError)):
                self.memory.append({"role": "assistant", "content": ''})
                raise
            self.memory.append({"role": "assistant", "content": ''})
            return "An error occurred."


class UniversalAgent(AbstractAgent):
    """
    Multi-provider agent supporting Qwen, Grok, Gemini, and any
    OpenAI-compatible REST API. Automatically selects the right
    base_url and API key from PROVIDER_CONFIG based on model prefix.
    """

    def __init__(self, task: str, model_name: str,
                 base_url: Optional[str] = None,
                 api_key: Optional[str] = None):
        load_dotenv()
        # Auto-detect provider from model prefix
        detected_base_url, env_var = self._detect_provider(model_name)
        if env_var == 'NARAROUTER_API_KEY':
            detected_base_url = os.getenv('NARAROUTER_BASE_URL', detected_base_url)
        if env_var == 'GROQ_API_KEY':
            detected_base_url = os.getenv('GROQ_BASE_URL', detected_base_url)
        self.base_url = base_url or detected_base_url
        self.api_key  = api_key  or os.getenv(env_var, '')
        if not self.api_key:
            raise ValueError(
                f"No API key found for model '{model_name}'. "
                f"Set the '{env_var}' environment variable in .env"
            )
        super().__init__(task, model_name=model_name)

    @staticmethod
    def _detect_provider(model_name: str):
        for prefix, config in PROVIDER_CONFIG.items():
            if model_name.startswith(prefix):
                return config  # (base_url, env_var)
        # Default to OpenAI
        return 'https://api.openai.com/v1', 'OPENAI_API_KEY'

    def _truncate_history(self, history, max_turns=2):
        system_prompt = history[0]
        message_pairs = history[1:]
        truncated = message_pairs[-(max_turns * 2):]
        return [system_prompt] + truncated

    def _send_message(self, user_message: str, temperature: float = 0) -> str:
        start_time = time.time()
        try:
            user_message = user_message[:10000]
            self.memory.append({"role": "user", "content": user_message})
            kwargs = dict(
                messages=self._truncate_history(self.memory),
                model=self.model,
                temperature=temperature,
            )
            # Enable JSON mode if model supports it
            if self.model in JSON_MODE_MODELS:
                kwargs['response_format'] = {"type": "json_object"}
            chat_completion = _llm_call_with_retry(
                lambda: OpenAI(api_key=self.api_key, base_url=self.base_url,
                               timeout=LLM_CALL_TIMEOUT_SECS, max_retries=0),
                kwargs, self.model)
            reply = chat_completion.choices[0].message.content or ""
            self.memory.append({"role": "assistant", "content": reply})

            dur_ms = (time.time() - start_time) * 1000.0
            usage = getattr(chat_completion, 'usage', None)
            inp_tok = getattr(usage, 'prompt_tokens', None) if usage else None
            out_tok = getattr(usage, 'completion_tokens', None) if usage else None
            self._record_router_query(len(user_message), len(reply), dur_ms, input_tokens=inp_tok, output_tokens=out_tok)

            return reply
        except Exception as e:
            # Auth/quota/timeout failures must propagate so the console worker
            # can rotate to a fallback key; only content-level problems are
            # swallowed into an empty reply.
            from openai import (APITimeoutError, APIConnectionError, RateLimitError,
                                AuthenticationError, PermissionDeniedError, NotFoundError)
            if isinstance(e, (APITimeoutError, APIConnectionError, RateLimitError,
                              AuthenticationError, PermissionDeniedError, NotFoundError)):
                self.memory.append({"role": "assistant", "content": ''})
                raise
            self.memory.append({"role": "assistant", "content": ''})
            return "An error occurred."


def build_provider_agent(task: str, model_name: str) -> AbstractAgent:
    """
    Factory — returns the right agent class for a given model name.

    Supported prefixes:
      gpt-*, o1-*, o3-*, o4-*  → GPTAgent (OpenAI)
      grok-*                   → UniversalAgent (xAI)
      qwen-*                   → UniversalAgent (Alibaba DashScope)
      gemini-*                 → UniversalAgent (Google)
      claude-*                 → NOT SUPPORTED (Anthropic SDK required)
      <anything else>          → OllmaAgent (local Ollama)
    """
    # Claude requires the Anthropic SDK, which is not integrated here.
    # Routing through OpenAI-compatible UniversalAgent silently fails
    # (different auth headers, different request schema). Fail fast instead.
    if model_name.startswith('claude-'):
        raise NotImplementedError(
            f"Claude model '{model_name}' is not supported. "
            "Install the 'anthropic' package and implement an AnthropicAgent, "
            "or choose a supported model (gpt-*, gemini-*, grok-*, qwen-*, or a local Ollama model)."
        )

    cloud_prefixes = tuple(PROVIDER_CONFIG.keys())
    if not any(model_name.startswith(p) for p in cloud_prefixes):
        return OllmaAgent(task, model_name)
    openai_prefixes = ('gpt-', 'o1-', 'o3-', 'o4-')
    if any(model_name.startswith(p) for p in openai_prefixes):
        return GPTAgent(task, model_name)
    return UniversalAgent(task, model_name)