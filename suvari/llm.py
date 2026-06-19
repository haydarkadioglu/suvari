"""
LLM Client — multi-provider support.
OpenAI, Anthropic (Claude), DeepSeek, Google Gemini, OpenRouter, Ollama.
"""

import os
import json
from pathlib import Path
from typing import Optional
import httpx
from dotenv import load_dotenv

# Auto-load .env files (project root + global config)
load_dotenv()
load_dotenv(Path.home() / ".config" / "suvari" / ".env")


class LLMClient:
    """Multi-provider LLM client."""

    PROVIDERS = {
        "anthropic": {
            "base_url": "https://api.anthropic.com/v1",
            "models": ["claude-sonnet-4-20250514", "claude-sonnet-4", "claude-3-5-sonnet-latest"],
            "env_key": "ANTHROPIC_API_KEY",
            "api_type": "anthropic",
        },
        "deepseek": {
            "base_url": "https://api.deepseek.com/v1",
            "models": ["deepseek-chat", "deepseek-reasoner"],
            "env_key": "DEEPSEEK_API_KEY",
            "api_type": "openai",
        },
        "gemini": {
            "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
            "models": ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"],
            "env_key": "GEMINI_API_KEY",
            "api_type": "openai",
        },
        "openrouter": {
            "base_url": "https://openrouter.ai/api/v1",
            "models": [
                "openai/gpt-4o", "anthropic/claude-sonnet-4",
                "deepseek/deepseek-chat", "google/gemini-2.5-flash",
                "qwen/qwen-2.5-72b",
            ],
            "env_key": "OPENROUTER_API_KEY",
            "api_type": "openai",
        },
        "ollama": {
            "base_url": "http://localhost:11434/v1",
            "models": ["llama3", "qwen2.5", "mistral", "deepseek-r1"],
            "env_key": None,
            "api_type": "openai",
        },
    }

    def __init__(self, provider: str = "openai", model: Optional[str] = None):
        if provider not in self.PROVIDERS:
            raise ValueError(
                f"Unknown provider: {provider}. "
                f"Supported: {', '.join(self.PROVIDERS)}"
            )

        self.provider = provider
        self.config = self.PROVIDERS[provider]
        self.model = model or self.config["models"][0]

        env_key = self.config["env_key"]
        if env_key:
            self.api_key = os.environ.get(env_key)
            if not self.api_key:
                raise ValueError(
                    f"{env_key} environment variable not set.\n"
                    f"  Run:  export {env_key}=sk-...\n"
                    f"  Or:   suvari.py configure"
                )
        else:
            self.api_key = None

        self.extra_headers = {}
        if provider == "openrouter":
            self.extra_headers = {
                "HTTP-Referer": "https://github.com/haydarkadioglu/suvari",
                "X-Title": "Suvari",
            }

        self.client = httpx.Client(timeout=180)

    def chat(
        self,
        messages: list,
        system: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
        stream: bool = False,
    ) -> str:
        """Send a chat prompt with safety context injection for OpenAI."""
        # Inject safety context for OpenAI (reduces refusal rate)
        if system:
            messages = [{"role": "system", "content": system}] + messages

        if self.config["api_type"] == "anthropic":
            return self._chat_anthropic(messages, temperature, max_tokens)

        if stream:
            return self._chat_openai_stream(messages, temperature, max_tokens)
        return self._chat_openai(messages, temperature, max_tokens)

    def chat_json(
        self,
        messages: list,
        system: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> dict:
        """Send a chat prompt, expect JSON response."""
        if system:
            messages = [{"role": "system", "content": system}] + messages

        messages.append({
            "role": "user",
            "content": "Respond ONLY with valid JSON. No markdown, no explanation.",
        })

        text = self.chat(messages, temperature=temperature, max_tokens=max_tokens)

        # Clean JSON from markdown code blocks
        text = text.strip()
        if text.startswith("```"):
            first_newline = text.find("\n")
            if first_newline != -1:
                text = text[first_newline:].strip()
        if text.endswith("```"):
            text = text[:-3].strip()
        if text.startswith("json"):
            text = text[4:].strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON response: {text[:100]}", "raw": text}

    # ─── OpenAI-compatible (OpenAI, DeepSeek, OpenRouter, Ollama, Gemini) ───

    def _chat_openai_stream(self, messages: list, temperature: float, max_tokens: int) -> str:
        """OpenAI-compatible streaming API call. Prints tokens as they arrive."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        headers.update(self.extra_headers)

        body = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }

        import sys
        full = ""
        base = self.config["base_url"]
        with self.client.stream("POST", f"{base}/chat/completions", json=body, headers=headers, timeout=120) as resp:
            for line in resp.iter_lines():
                if not line:
                    continue
                if line.startswith("data: "):
                    chunk = line[6:]
                    if chunk.strip() == "[DONE]":
                        break
                    try:
                        import json
                        data = json.loads(chunk)
                        delta = data.get("choices", [{}])[0].get("delta", {}).get("content", "")
                        if delta:
                            full += delta
                            sys.stdout.write(delta)
                            sys.stdout.flush()
                    except json.JSONDecodeError:
                        continue
        print()
        return full

    def _chat_openai(self, messages: list, temperature: float, max_tokens: int) -> str:
        """OpenAI-compatible API call."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        headers.update(self.extra_headers)

        body = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        resp = self.client.post(
            f"{self.config['base_url']}/chat/completions",
            headers=headers,
            json=body,
        )

        if resp.status_code == 401:
            raise PermissionError(
                f"API key error ({self.provider}): Unauthorized. Check your API key."
            )
        if resp.status_code == 429:
            raise RuntimeError(
                f"Rate limited ({self.provider}): Too many requests. Try again later."
            )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    # ─── Anthropic/Claude (native API) ───

    def _chat_anthropic(self, messages: list, temperature: float, max_tokens: int) -> str:
        """Anthropic Claude native API call."""
        system_text = None
        anthropic_messages = []

        for m in messages:
            if m["role"] == "system":
                system_text = m["content"]
            else:
                role = "assistant" if m["role"] == "assistant" else "user"
                anthropic_messages.append({"role": role, "content": m["content"]})

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        headers.update(self.extra_headers)

        body = {
            "model": self.model,
            "messages": anthropic_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_text:
            body["system"] = system_text

        resp = self.client.post(
            f"{self.config['base_url']}/messages",
            headers=headers,
            json=body,
        )

        if resp.status_code == 401:
            raise PermissionError("API key error (anthropic): Unauthorized. Check your ANTHROPIC_API_KEY.")
        if resp.status_code == 429:
            raise RuntimeError("Rate limited (anthropic): Too many requests.")
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]

    def __del__(self):
        if hasattr(self, "client"):
            self.client.close()
