"""A2 Agentic 多轮闭环（2026-09-17 落地）。

为什么是「文本约定 + 本地回灌」而不是 provider 的 function calling：
  现有 provider 客户端族（src/agents/a2_ai_agent.py）的
  ``create_message(system, messages, max_tokens, temperature) -> str`` 是纯
  prompt→completion，**请求体里没有 tools / tool_choice 参数**，即当前 provider 通道不
  提供 function calling。因此本模块在系统提示里声明工具与调用格式，让模型主动决定查证什么，
  本地执行后把结果作为新的 user 消息回灌，形成真正的多轮 loop：

    1. 系统提示声明可用工具（来自 a2_tools.TOOL_SCHEMAS）与调用格式；
    2. 模型需要查证时输出一行 ``TOOL: {"name": ..., "arguments": {...}}``；
    3. 本地 a2_tools.execute_tool 执行（全部只读），结果以【工具结果】回灌；
    4. 循环至模型给出最终结论（不再出现 TOOL 行）或达轮次上限。

价值：把闭环里 A2 的二次分析从「一次性 completion（把 I2 反馈文本注入 prompt）」
变成「可主动查证的多轮推理」，直接针对 I2 判定的 hypothesis_defect（端点幻觉 /
参数缺失 / 族误判）——此前这些缺陷的根因之一就是 A2 只能看 prompt 里塞进来的片段。

安全：所有工具只读（见 a2_tools），路径越界被拒，exploit 探测只列清单不执行。
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from src.agents import a2_tools

_TOOL_LINE_RE = re.compile(r"^\s*TOOL:\s*(\{.*?\})\s*$", re.MULTILINE)


def _tool_manifest() -> str:
    # §4.2 三期：含外部 MCP 工具（mcp__<server>__<tool>）；无外部工具时与旧版一致。
    lines = [f"- {s['name']}：{s['description']}" for s in a2_tools.all_tool_schemas()]
    return "\n".join(lines)


def _parse_tool_calls(text: str) -> List[Dict[str, Any]]:
    """从模型输出里解析 TOOL 调用行；解析失败的行直接跳过（不打断 loop）。"""
    calls: List[Dict[str, Any]] = []
    for m in _TOOL_LINE_RE.finditer(text or ""):
        try:
            obj = json.loads(m.group(1))
        except Exception:
            continue
        if isinstance(obj, dict) and obj.get("name"):
            calls.append(obj)
    return calls


def build_agentic_system(base_system: str, max_calls_per_round: int = 3) -> str:
    """在系统提示里追加工具声明与调用格式（不改变原有任务指令）。"""
    return (
        (base_system or "")
        + "\n\n【可用工具（全部只读）】\n"
        + _tool_manifest()
        + "\n\n【调用方式】需要查证时，单独一行输出：\n"
        + 'TOOL: {"name": "<工具名>", "arguments": {...}}\n'
        + f"每轮最多 {int(max_calls_per_round)} 次调用。工具结果会以【工具结果】为标题回灌给你。\n"
        + "证据充足后直接给出最终 JSON 结论，不要再输出 TOOL 行。"
    )


def _tool_result_budget_chars(model: str) -> int:
    """工具结果回灌的字符预算（模型无关）：本地小模型收紧，云端/推理模型放宽。

    宽裕档（large/medium/cloud/reasoning）上下文充足，直接给 4000；
    其余（local/small 及未知档，含 SAFE_FALLBACK）按画像 input_budget 的 10% 计并夹在
    [400, 2000]，避免多轮工具结果把受限上下文打爆。取不到画像时回落 2000，fail-open。

    2026-09-19 修正：原实现用 `input_budget * 4`（4 字符/token）。本项目真实提示词实测
    只有 2.34~2.38 字符/token，该换算会把小模型的可用容量高估约 1.7 倍；改用
    estimate_tokens 的反函数口径（每 token 约 2 字符）折算，偏保守。
    """
    try:
        from src.core.model_capabilities import resolve_profile, input_budget
        prof = resolve_profile(model=model or "", provider="")
        if prof.tier in ("large", "medium", "cloud", "reasoning"):
            return 4000
        return int(min(2000, max(400, input_budget(prof) * 2 * 0.10)))
    except Exception:
        return 2000


def _trim_history(messages: List[Dict[str, str]], keep_rounds: int) -> List[Dict[str, str]]:
    """多轮增长保护：保住首条任务消息，只保留最近 keep_rounds 轮（每轮 2 条）。

    超出部分丢弃——多轮推理里近期上下文通常比早期工具结果更有价值，且能防止
    小上下文模型被历史撑爆。keep_rounds>=实际轮数时不触发。
    """
    if keep_rounds <= 0:
        return messages
    cap = 1 + 2 * int(keep_rounds)
    if len(messages) <= cap:
        return messages
    return [messages[0]] + messages[-(cap - 1):]


def run_agentic_loop(
    client: Any,
    system: str,
    user_prompt: str,
    *,
    max_rounds: int = 3,
    max_tool_calls_per_round: int = 3,
    max_tokens: int = 4096,
    temperature: float = 0.0,
    keep_rounds: int = 3,
    model: str = "",
    logger: Any = None,
) -> Dict[str, Any]:
    """带工具调用的多轮推理；返回最终文本 + 轮次 + 工具调用记录。

    fail-open：任何一轮 create_message 抛异常都向上抛出，由调用方决定是否回落
    （本模块不吞异常，避免把「LLM 不可用」伪装成「分析完成」）。

    上下文预算（P1-6，模型无关）：
      - 工具结果回灌按模型画像做 token 预算，本地小模型收紧、云端放宽；
      - 超过 keep_rounds 的历史轮次被裁剪，保首条任务消息 + 最近若干轮。
    """
    # §4.2 三期收口（2026-09-20）：启动时幂等加载外部 MCP server 并注册其工具。
    # 未配置 `mcp.enabled` 时零开销直接返回；接线异常一律吞掉（fail-open），
    # 外部进程不可控，绝不能因此阻断主扫描。
    try:
        from src.mcp.bootstrap import ensure_external_tools_loaded
        _mcp = ensure_external_tools_loaded()
        if logger is not None and _mcp.get("tools"):
            logger.info("[agentic] 已接入外部 MCP 工具 %s 个：%s",
                        len(_mcp["tools"]), ", ".join(_mcp["tools"]))
        if logger is not None and _mcp.get("errors"):
            logger.warning("[agentic] 外部 MCP 接线存在失败项：%s", "; ".join(_mcp["errors"]))
    except Exception:
        pass

    agentic_system = build_agentic_system(system, max_tool_calls_per_round)
    model_name = model or str(getattr(client, "model", "") or "")
    budget_chars = _tool_result_budget_chars(model_name)
    messages: List[Dict[str, str]] = [{"role": "user", "content": user_prompt}]
    tool_calls: List[Dict[str, Any]] = []
    text = ""
    rounds = 0

    for rnd in range(1, int(max_rounds or 1) + 1):
        rounds = rnd
        text = client.create_message(
            system=agentic_system, messages=messages,
            max_tokens=max_tokens, temperature=temperature,
        ) or ""
        calls = _parse_tool_calls(text)[: int(max_tool_calls_per_round)]
        if not calls:
            if logger is not None:
                logger.info("[agentic] 第 %s 轮未请求工具，结束（最终结论）", rnd)
            return {"text": text, "rounds": rounds, "tool_calls": tool_calls, "stopped_by": "final"}

        blocks: List[str] = []
        for c in calls:
            name = str(c.get("name") or "")
            args = c.get("arguments") if isinstance(c.get("arguments"), dict) else {}
            res = a2_tools.execute_tool(name, args)
            tool_calls.append({
                "round": rnd, "name": name, "arguments": args,
                "ok": bool(res.get("ok")),
            })
            blocks.append(
                f"【工具 {name} 结果】\n{json.dumps(res, ensure_ascii=False)[:budget_chars]}"
            )
            if logger is not None:
                logger.info("[agentic] 第 %s 轮调用工具 %s（ok=%s，结果预算 %sch）", rnd, name, res.get("ok"), budget_chars)

        messages.append({"role": "assistant", "content": text})
        messages.append({
            "role": "user",
            "content": "\n\n".join(blocks) + "\n\n请基于以上工具结果继续；证据充足则直接给出最终 JSON 结论。",
        })
        messages = _trim_history(messages, keep_rounds)

    return {"text": text, "rounds": rounds, "tool_calls": tool_calls, "stopped_by": "max_rounds"}
