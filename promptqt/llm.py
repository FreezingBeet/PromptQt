"""LLM provider layer.

Every model call in PromptQT goes through `LLMClient.chat()`, so the rest of the
code does not care which provider is used.

Providers:
- GeminiClient: Google Gemini through the official `google-genai` SDK (default).
- OpenAICompatClient: any OpenAI-compatible /chat/completions endpoint
  (OpenAI, Groq, OpenRouter, a local Ollama server, ...).
- ScriptedClient: an offline stand-in used ONLY by the unit tests.
"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass
from typing import Callable

import requests

# Tried in order when the chosen Gemini model is overloaded (503) or retired (404).
GEMINI_FALLBACKS = ("gemini-3.6-flash", "gemini-3.5-flash-lite")


class LLMError(RuntimeError):
    """Raised when a provider call fails after all retries."""


@dataclass
class Message:
    role: str  # "user" or "assistant"
    content: str


class LLMClient:
    """Base class. Subclasses implement `_chat_once`.

    If the model is overloaded or retired, the client switches to the next model in
    `fallbacks` and stays on it. `models_used` records which models really answered.
    """

    name = "base"

    def __init__(self, model: str, max_retries: int = 4, backoff: float = 2.0, fallbacks: list[str] | tuple = ()):
        self.model = model
        self.requested_model = model
        self.chain = [model] + [m for m in dict.fromkeys(fallbacks) if m and m != model]
        self.max_retries = max_retries
        self.backoff = backoff
        self.calls = 0
        self.models_used: dict[str, bool] = {}  # insertion-ordered set
        self._lock = threading.Lock()

    def chat(
        self,
        system: str | None,
        messages: list[Message],
        temperature: float = 0.7,
        json_mode: bool = False,
        max_tokens: int = 2048,
    ) -> str:
        while True:
            model = self.model
            for attempt in range(self.max_retries + 1):
                try:
                    self.calls += 1
                    text = self._chat_once(model, system, messages, temperature, json_mode, max_tokens)
                    self.models_used[model] = True
                    return text
                except Exception as err:  # noqa: BLE001 - provider SDKs raise many types
                    # Retired model: switch now. Overloaded model: give it one retry, then switch.
                    one_retry_done = attempt >= min(1, self.max_retries)
                    if (_is_model_gone(err) or (_is_overloaded(err) and one_retry_done)) and self._fall_back(model):
                        break
                    if not _is_retryable(err) or attempt == self.max_retries:
                        raise LLMError(f"{self.name} call failed ({model}): {err}") from err
                    time.sleep(self.backoff * (2**attempt))

    def _fall_back(self, failed_model: str) -> bool:
        """Move to the next model in the chain. Returns False if there is none left."""
        with self._lock:
            if self.model != failed_model:  # another thread already switched
                return True
            i = self.chain.index(failed_model) if failed_model in self.chain else len(self.chain)
            if i + 1 >= len(self.chain):
                return False
            self.model = self.chain[i + 1]
            return True

    def used_label(self) -> str:
        """Which model(s) actually answered, flagged if a fallback was needed."""
        used = list(self.models_used) or [self.model]
        label = " + ".join(used)
        if used != [self.requested_model]:
            label += f" (fallback: {self.requested_model} was unavailable)"
        return label

    def ask(self, system: str | None, user: str, **kw) -> str:
        return self.chat(system, [Message("user", user)], **kw)

    def ask_json(self, system: str | None, user: str, temperature: float = 0.2, **kw):
        """Ask for JSON and parse it. Retries once with a repair hint if parsing fails."""
        raw = self.ask(system, user, temperature=temperature, json_mode=True, **kw)
        try:
            return parse_json(raw)
        except ValueError:
            repair = user + "\n\nYour previous answer was not valid JSON. Reply with valid JSON only."
            raw = self.ask(system, repair, temperature=0.0, json_mode=True, **kw)
            try:
                return parse_json(raw)
            except ValueError as err:
                raise LLMError(str(err)) from err

    def _chat_once(self, model, system, messages, temperature, json_mode, max_tokens) -> str:
        raise NotImplementedError


def _is_retryable(err: Exception) -> bool:
    text = str(err).lower()
    return any(k in text for k in ("429", "rate", "quota", "503", "500", "unavailable", "timeout", "overloaded"))


def _is_overloaded(err: Exception) -> bool:
    text = str(err).lower()
    return any(k in text for k in ("503", "unavailable", "overloaded", "high demand"))


def _is_model_gone(err: Exception) -> bool:
    text = str(err).lower()
    return "404" in text and ("not_found" in text or "not found" in text)


def parse_json(raw: str):
    """Parse JSON from a model reply, tolerating ```json fences and leading prose."""
    text = raw.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for open_c, close_c in (("{", "}"), ("[", "]")):
        start, end = text.find(open_c), text.rfind(close_c)
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                continue
    raise ValueError(f"Model did not return valid JSON: {raw[:200]!r}")


# --------------------------------------------------------------------------- Gemini
class GeminiClient(LLMClient):
    name = "gemini"

    def __init__(self, api_key: str, model: str = "gemini-3.8-flash", fallbacks=GEMINI_FALLBACKS, **kw):
        super().__init__(model, fallbacks=fallbacks, **kw)
        if not api_key:
            raise LLMError("A Gemini API key is required (get one free at https://aistudio.google.com/apikey).")
        from google import genai  # imported lazily so tests do not need the SDK

        self._genai = genai
        self._client = genai.Client(api_key=api_key)

    def _chat_once(self, model, system, messages, temperature, json_mode, max_tokens) -> str:
        types = self._genai.types
        contents = [
            types.Content(role="model" if m.role == "assistant" else "user", parts=[types.Part(text=m.content)])
            for m in messages
        ]
        config = types.GenerateContentConfig(
            system_instruction=system or None,
            temperature=temperature,
            max_output_tokens=max_tokens,
            response_mime_type="application/json" if json_mode else None,
        )
        resp = self._client.models.generate_content(model=model, contents=contents, config=config)
        text = resp.text
        if text is None:
            # Blocked by Gemini's own safety filter: count it as a refusal, not a crash.
            return "[No text returned: the model's safety filter blocked this reply.]"
        return text


# ------------------------------------------------------------------ OpenAI-compatible
class OpenAICompatClient(LLMClient):
    name = "openai-compatible"

    def __init__(self, api_key: str, model: str, base_url: str = "https://api.openai.com/v1", **kw):
        super().__init__(model, **kw)
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    def _chat_once(self, model, system, messages, temperature, json_mode, max_tokens) -> str:
        payload_msgs = ([{"role": "system", "content": system}] if system else []) + [
            {"role": m.role, "content": m.content} for m in messages
        ]
        body = {"model": model, "messages": payload_msgs, "temperature": temperature, "max_tokens": max_tokens}
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        r = requests.post(f"{self.base_url}/chat/completions", json=body, headers=headers, timeout=120)
        if r.status_code >= 400:
            raise LLMError(f"HTTP {r.status_code}: {r.text[:300]}")
        return r.json()["choices"][0]["message"]["content"] or ""


# ------------------------------------------------------------------------ tests only
class ScriptedClient(LLMClient):
    """Offline client for unit tests. `responder(system, messages, json_mode)` returns the reply."""

    name = "scripted"

    def __init__(self, responder: Callable[[str | None, list[Message], bool], str], model: str = "scripted"):
        super().__init__(model, max_retries=0)
        self.responder = responder
        self.log: list[tuple[str | None, list[Message]]] = []

    def _chat_once(self, model, system, messages, temperature, json_mode, max_tokens) -> str:
        self.log.append((system, list(messages)))
        return self.responder(system, messages, json_mode)


def make_client(provider: str, api_key: str, model: str, base_url: str | None = None,
                fallbacks: list[str] | None = None) -> LLMClient:
    """`fallbacks=None` means the provider default (Gemini: GEMINI_FALLBACKS; others: none)."""
    if provider == "gemini":
        return GeminiClient(api_key=api_key, model=model, fallbacks=GEMINI_FALLBACKS if fallbacks is None else fallbacks)
    if provider == "openai-compatible":
        return OpenAICompatClient(api_key=api_key, model=model, base_url=base_url or "https://api.openai.com/v1",
                                  fallbacks=fallbacks or ())
    raise LLMError(f"Unknown provider: {provider}")
