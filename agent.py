"""安全数据和情报分析 Agent —— 核心调度逻辑"""

from __future__ import annotations
import json
from typing import AsyncIterator
from llm_client import chat_completion
from tools import (
    get_tools_description,
    get_openai_tools_schema,
    call_tool,
)

# ---------------------------------------------------------------------------
# System Prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """你是一位资深的网络安全分析师和威胁情报专家。你的职责是帮助安全团队分析威胁数据、解读安全事件、提供防御建议。

## 你的能力
1. **IOC 提取** — 从任意文本中自动提取 IP、域名、URL、哈希、CVE 等威胁指标
2. **日志分析** — 识别安全日志中的异常行为模式（暴力破解、端口扫描、横向移动等）
3. **威胁分类** — 基于 MITRE ATT&CK 框架对威胁进行分类和映射
4. **情报摘要** — 对安全情报报告进行结构化摘要和关键信息提取
5. **安全咨询** — 提供漏洞分析、应急响应建议、加固方案等专业意见

## 你可以使用的工具
{tools_description}

## 工作准则
- 始终使用专业、准确的安全术语
- 对于威胁事件，从 TTP（战术、技术、过程）维度进行分析
- 给出可操作的防御建议和缓解措施
- 如果收到的数据可以用工具分析，主动调用工具获取结构化结果
- 对分析结果给出清晰的风险等级评估
- 在不确定时明确说明，不要编造威胁情报
""".format(tools_description=get_tools_description())


# ---------------------------------------------------------------------------
# Agent 核心
# ---------------------------------------------------------------------------

class SecurityAgent:
    """安全情报分析 Agent"""

    def __init__(self):
        self.conversation: list[dict] = [
            {"role": "system", "content": SYSTEM_PROMPT}
        ]

    def reset(self):
        """重置对话历史"""
        self.conversation = [
            {"role": "system", "content": SYSTEM_PROMPT}
        ]

    async def chat(self, user_message: str) -> AsyncIterator[str]:
        """处理用户消息，返回流式响应"""
        self.conversation.append({"role": "user", "content": user_message})

        # 第一轮：先尝试非流式调用以检测 tool_call
        first_response = await self._call_llm_with_tools()

        # 检查是否有 tool_calls
        if first_response.get("tool_calls"):
            tool_results = self._execute_tools(first_response["tool_calls"])

            # 把 assistant 的 tool_call 消息加入历史
            self.conversation.append({
                "role": "assistant",
                "content": first_response.get("content") or "",
                "tool_calls": first_response["tool_calls"],
            })

            # 把每个工具结果加入历史
            for tc, result in zip(first_response["tool_calls"], tool_results):
                self.conversation.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": json.dumps(result, ensure_ascii=False, indent=2),
                })

            # 第二轮：基于工具结果，流式生成最终回复
            full_text = []
            async for chunk in await chat_completion(self.conversation, stream=True):
                full_text.append(chunk)
                yield chunk

            assistant_reply = "".join(full_text)
            self.conversation.append({"role": "assistant", "content": assistant_reply})

        else:
            # 无 tool_call，直接将内容流式输出
            content = first_response.get("content", "")
            if content:
                self.conversation.append({"role": "assistant", "content": content})
                yield content
            else:
                # fallback：流式调用
                full_text = []
                async for chunk in await chat_completion(self.conversation, stream=True):
                    full_text.append(chunk)
                    yield chunk
                assistant_reply = "".join(full_text)
                self.conversation.append({"role": "assistant", "content": assistant_reply})

    async def _call_llm_with_tools(self) -> dict:
        """非流式调用 LLM，检测是否触发 tool_calls"""
        import httpx
        from config import LLM_PROXY_URL, LLM_API_KEY, LLM_MODEL

        headers = {"Content-Type": "application/json"}
        if LLM_API_KEY:
            headers["Authorization"] = f"Bearer {LLM_API_KEY}"

        payload = {
            "model": LLM_MODEL,
            "messages": self.conversation,
            "temperature": 0.3,
            "stream": False,
            "tools": get_openai_tools_schema(),
        }

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(LLM_PROXY_URL, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                message = data["choices"][0]["message"]
                return message
        except Exception:
            # 如果 tool calling 不被支持，退回普通模式
            return await self._call_llm_plain()

    async def _call_llm_plain(self) -> dict:
        """退回不带 tools 的普通调用"""
        content = await chat_completion(self.conversation, stream=False)
        return {"content": content, "tool_calls": None}

    def _execute_tools(self, tool_calls: list[dict]) -> list[dict]:
        """执行 tool_calls 中的所有工具"""
        results = []
        for tc in tool_calls:
            func_name = tc["function"]["name"]
            try:
                args = json.loads(tc["function"]["arguments"])
            except json.JSONDecodeError:
                args = {}
            result = call_tool(func_name, args)
            results.append(result)
        return results
