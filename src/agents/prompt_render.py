"""Prompt 模板安全渲染。

    A2 审计提示词模板（src/prompts/audit_prompts.yaml）用 Python 的
    ``str.format`` 渲染。``format`` 会把模板里**所有** ``{xxx}`` 当成占位符，
    一旦提示词正文中出现字面花括号——例如路由示例 ``/order/{id}``、``/address/{id}``——
    就会抛 ``KeyError: 'id'``。

    该异常被 A2 的 ``except Exception`` 吞掉并静默返回空结果，导致 task 9 的
    60 个文件全部分析失败、A2 阶段耗时 0.1s、业务逻辑类 findings 归零，
    而任务状态仍显示 completed，无人察觉。

约定：
    调用方只替换自己**显式传入**的键，其余占位符一律当作字面量原样保留。
    这样提示词里可以安全地书写 ``{id}`` / ``{orderId}`` 之类的路由示例，
"""

from __future__ import annotations

import re

__all__ = ["render_prompt", "PLACEHOLDER_RE"]

# 匹配单层 {xxx}，排除已被转义的 {{xxx}}
PLACEHOLDER_RE = re.compile(r"(?<!\{)\{([^{}]*)\}(?!\})")


def _field_name(spec: str) -> str:
    """从 format spec 里取出字段名。

    ``{user.name}`` -> ``user``；``{items[0]}`` -> ``items``；
    ``{n:>4}`` -> ``n``；``{x!r}`` -> ``x``。
    """
    name = spec.split("!", 1)[0]
    name = name.split(":", 1)[0]
    name = name.split("[", 1)[0]
    name = name.split(".", 1)[0]
    return name.strip()


def render_prompt(template: str, **kwargs) -> str:
    """安全渲染模板：仅替换 kwargs 中提供的键，其余 ``{xxx}`` 保留为字面量。

    Args:
        template: 含占位符的模板字符串
        **kwargs: 调用方可提供的替换值

    Returns:
        渲染后的字符串。不会因模板中出现未知占位符而抛异常。
    """
    if not template:
        return template

    # 调用方忘了传时，若不给默认值，render 后会把字面量 `{skill_hints}` 留给模型。这里统一
    # 兜底为空串，保证任何渲染路径都不会泄漏该占位符（显式传入时以传入值为准）。
    kwargs.setdefault("skill_hints", "")

    def _escape_unknown(match: re.Match) -> str:
        spec = match.group(1)
        if _field_name(spec) in kwargs:
            return match.group(0)  # 已知键，交给 format 正常替换
        return "{{" + spec + "}}"  # 未知键，转义为字面量

    return PLACEHOLDER_RE.sub(_escape_unknown, template).format(**kwargs)
