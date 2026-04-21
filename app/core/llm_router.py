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
        import google.generativeai as genai
        genai.configure(api_key=self.api_key)
        model = genai.GenerativeModel("gemini-1.5-flash", system_instruction=system_prompt)
        gemini_history = [{"role": m["role"], "parts": [m["content"]]} for m in history[-8:]]
        chat = model.start_chat(history=gemini_history)
        response = await chat.send_message_async(user_message)
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
        def _run_sync() -> str:
            try:
                from transformers import pipeline
                import torch
                logger.info("Loading Phi-3 Mini locally on CPU...")
                pipe = pipeline(
                    "text-generation", model=PHI3_MODEL,
                    torch_dtype=torch.float32, device_map="cpu", trust_remote_code=True
                )
                # Build Phi-3 chat prompt using concatenation (avoids XML escape issues)
                s = "<|"
                prompt = (
                    s + "system|>\n" + system_prompt + "\n" + s + "end|>\n"
                    + s + "user|>\n" + user_message + "\n" + s + "end|>\n"
                    + s + "assistant|>\n"
                )
                output = pipe(prompt, max_new_tokens=512, do_sample=False)
                text = output[0]["generated_text"]
                assistant_tag = s + "assistant|>"
                if assistant_tag in text:
                    text = text.split(assistant_tag)[-1].strip()
                return text
            except ImportError:
                raise RuntimeError("Install transformers and torch: pip install transformers torch")

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _run_sync)
        self.last_model_used = "phi3-mini"
        return result
