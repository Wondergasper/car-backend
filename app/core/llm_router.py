"""
LLM Router - Gemini (primary) -> Mistral 7B -> Llama 3 8B -> Phi-3 Mini (local fallback)
"""
import os
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)

MISTRAL_MODEL = "mistralai/Mistral-7B-Instruct-v0.3"
LLAMA3_MODEL  = "meta-llama/Meta-Llama-3-8B-Instruct"
PHI3_MODEL    = "microsoft/Phi-3-mini-4k-instruct"
HF_BASE_URL   = "https://api-inference.huggingface.co/models"


class LLMRouter:
    def __init__(self, api_key: str = "", hf_token: str = ""):
        self.api_key      = api_key   or os.getenv("GOOGLE_API_KEY", "")
        self.hf_token     = hf_token  or os.getenv("HUGGINGFACE_TOKEN", "")
        self.offline_mode = os.getenv("OFFLINE_MODE", "false").lower() == "true"
        self.last_model_used = "none"

    async def generate(
        self,
        system_prompt: str,
        user_message: str,
        history: Optional[List[dict]] = None,
        task: str = "compliance_qa",
    ) -> str:
        history = history or []

        if self.offline_mode:
            logger.info("OFFLINE_MODE=true - routing to Phi-3 Mini")
            return await self._phi3_local(system_prompt, user_message)

        if task == "long_document" and self.hf_token:
            try:
                return await self._llama3_hf(system_prompt, user_message, history)
            except Exception as e:
                logger.warning("Llama3 failed: %s", e)

        if self.api_key:
            try:
                return await self._gemini(system_prompt, user_message, history)
            except Exception as e:
                logger.warning("Gemini failed: %s - trying Mistral...", e)

        if self.hf_token:
            try:
                return await self._mistral_hf(system_prompt, user_message, history)
            except Exception as e:
                logger.warning("Mistral failed: %s - trying Llama3...", e)

        if self.hf_token:
            try:
                return await self._llama3_hf(system_prompt, user_message, history)
            except Exception as e:
                logger.warning("Llama3 fallback failed: %s - trying Phi3...", e)

        return await self._phi3_local(system_prompt, user_message)

    async def _gemini(self, system_prompt: str, user_message: str, history: List[dict]) -> str:
        from google import genai as google_genai
        from google.genai import types as genai_types
        # Use typed HttpOptions to force the stable v1 endpoint
        # (google-genai SDK defaults to v1beta; gemini-1.5-flash requires v1)
        client = google_genai.Client(
            api_key=self.api_key,
            http_options=genai_types.HttpOptions(api_version="v1"),
        )

        # Build history as Content objects (role must be "user" or "model")
        contents = []
        for m in history[-8:]:
            role = m.get("role", "user")
            if role == "assistant":
                role = "model"
            contents.append(
                genai_types.Content(role=role, parts=[genai_types.Part(text=m["content"])])
            )
        # Append the current user message
        contents.append(
            genai_types.Content(role="user", parts=[genai_types.Part(text=user_message)])
        )

        config = genai_types.GenerateContentConfig(system_instruction=system_prompt)
        response = await client.aio.models.generate_content(
            model="gemini-1.5-flash",
            contents=contents,
            config=config,
        )
        self.last_model_used = "gemini-1.5-flash"
        return response.text

    async def _hf_chat(
        self, model_id: str, system_prompt: str, user_message: str,
        history: List[dict], max_tokens: int = 1024
    ) -> str:
        import httpx
        messages = [{"role": "system", "content": system_prompt}]
        for m in history[-6:]:
            messages.append({"role": m["role"], "content": m["content"]})
        messages.append({"role": "user", "content": user_message})
        url = f"{HF_BASE_URL}/{model_id}/v1/chat/completions"
        async with httpx.AsyncClient(timeout=90.0) as client:
            resp = await client.post(
                url,
                headers={
                    "Authorization": f"Bearer {self.hf_token}",
                    "Content-Type": "application/json"
                },
                json={"model": model_id, "messages": messages,
                      "max_tokens": max_tokens, "temperature": 0.3},
            )
            resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    async def _mistral_hf(self, system_prompt: str, user_message: str, history: List[dict]) -> str:
        result = await self._hf_chat(MISTRAL_MODEL, system_prompt, user_message, history, 1024)
        self.last_model_used = "mistral-7b"
        return result

    async def _llama3_hf(self, system_prompt: str, user_message: str, history: List[dict]) -> str:
        result = await self._hf_chat(LLAMA3_MODEL, system_prompt, user_message, history, 2048)
        self.last_model_used = "llama3-8b"
        return result

    async def _phi3_local(self, system_prompt: str, user_message: str) -> str:
        import asyncio
        import traceback as _tb
        def _run_sync() -> str:
            try:
                from transformers import pipeline, AutoConfig
                logger.info("Loading Phi-3 Mini locally on CPU...")

                # Phi-3 rope_scaling compat fix: older cached model files lack the
                # 'type' key that transformers 4.43+ requires. Patch it before load.
                try:
                    cfg = AutoConfig.from_pretrained(PHI3_MODEL, trust_remote_code=True)
                    if hasattr(cfg, "rope_scaling") and isinstance(cfg.rope_scaling, dict):
                        if "type" not in cfg.rope_scaling:
                            cfg.rope_scaling["type"] = "longrope"
                    pipe = pipeline(
                        "text-generation", model=PHI3_MODEL, config=cfg,
                        dtype="float32", device_map="cpu", trust_remote_code=True
                    )
                except Exception as cfg_err:
                    logger.warning("Phi-3 config patch failed (%s); retrying without patch", cfg_err)
                    pipe = pipeline(
                        "text-generation", model=PHI3_MODEL,
                        dtype="float32", device_map="cpu", trust_remote_code=True
                    )

                # Pass a raw string prompt — avoids additional KeyError:'type'
                # from Phi-3's multi-modal message handler when receiving dicts.
                s = "<|"
                prompt = (
                    s + "system|>\n" + system_prompt + "\n" + s + "end|>\n"
                    + s + "user|>\n" + user_message + "\n" + s + "end|>\n"
                    + s + "assistant|>\n"
                )
                output = pipe(prompt, max_new_tokens=512, do_sample=False)
                generated = output[0]["generated_text"]

                # Newer transformers may return a list of message dicts
                if isinstance(generated, list):
                    for msg in reversed(generated):
                        if isinstance(msg, dict) and msg.get("role") == "assistant":
                            return msg.get("content", "").strip()
                    return str(generated[-1])

                # Standard: generated_text is a plain string — extract assistant reply
                text = str(generated)
                assistant_tag = s + "assistant|>"
                if assistant_tag in text:
                    text = text.split(assistant_tag)[-1].strip()
                return text
            except ImportError:
                raise RuntimeError("Install transformers and torch: pip install transformers torch")
            except Exception as exc:
                logger.error("Phi-3 local inference error: %s\n%s", exc, _tb.format_exc())
                raise

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _run_sync)
        self.last_model_used = "phi3-mini"
        return result
