"""LLM Proxy 调用客户端 —— 通过 HTTP 调用后台 LLM 代理服务"""

from __future__ import annotations
import json
import httpx
from typing import AsyncIterator
from config import LLM_PROXY_URL, LLM_API_KEY, LLM_MODEL


async def chat_completion(
    messages: list[dict],
    temperature: float = 0.3,
    stream: bool = True,
) -> AsyncIterator[str] | str:
    """调用 LLM proxy，支持流式和非流式两种模式"""
    headers = {
        "Content-Type": "application/json",
    }
    if LLM_API_KEY:
        headers["Authorization"] = f"Bearer {LLM_API_KEY}"

    payload = {
        "model": LLM_MODEL,
        "messages": messages,
        "temperature": temperature,
        "stream": stream,
    }

    if stream:
        return _stream_response(headers, payload)
    else:
        return await _blocking_response(headers, payload)


async def _stream_response(headers: dict, payload: dict) -> AsyncIterator[str]:
    """流式返回 LLM 生成内容"""
    async with httpx.AsyncClient(timeout=120.0) as client:
        async with client.stream("POST", LLM_PROXY_URL, headers=headers, json=payload) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line or not line.startswith("data: "):
                    continue
                data = line[6:]
                if data.strip() == "[DONE]":
                    break
                try:
                    chunk = json.loads(data)
                    delta = chunk["choices"][0].get("delta", {})
                    content = delta.get("content", "")
                    if content:
                        yield content
                except (json.JSONDecodeError, KeyError, IndexError):
                    continue


async def _blocking_response(headers: dict, payload: dict) -> str:
    """非流式一次性返回结果"""
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(LLM_PROXY_URL, headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]
