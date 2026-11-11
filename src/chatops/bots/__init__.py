"""ChatOps bot adapters (G11).

Renders a skill answer into a chat-platform message payload. Feishu/DingTalk/
WeCom share a common Markdown card shape; a generic webhook adapter posts the
same payload. Outbound delivery is opt-in and proxy-aware — by default
``build_payload`` only *formats* the message and returns it; nothing is sent, so
tests need zero network access.
"""

from typing import Any, Dict, List


def format_answer_markdown(answer: Dict[str, Any]) -> str:
    """Human-readable Markdown summary of a ScaChatOpsSkill answer."""
    parsed = answer.get("parsed") or {}
    name = parsed.get("name") or "(未识别组件)"
    lines: List[str] = [f"**SCA 查询：{name}**"]
    lines.append(f"- 是否使用：{'是' if answer.get('in_use') else '否'}")
    projects = answer.get("projects") or []
    if projects:
        lines.append(f"- 项目/清单：{', '.join(projects)}")
    lines.append(f"- 是否命中漏洞版本：{'是' if answer.get('vulnerable') else '否'}")
    exposure = answer.get("exposure") or {}
    lines.append(
        f"- 暴露面：安装 {exposure.get('installation_count', 0)} 处，命中 {exposure.get('vulnerable_hit_count', 0)} 条"
        + ("（含恶意组件）" if exposure.get("malicious") else "")
    )
    for hit in (answer.get("vulnerability_hits") or [])[:5]:
        lines.append(f"  - {hit.get('advisory_id')} [{hit.get('severity')}] {hit.get('summary', '')}")
    lines.append(f"- 修复建议：{answer.get('remediation', '')}")
    return "\n".join(lines)


class ChatBotAdapter:
    """Base adapter: builds a platform message payload from a skill answer."""

    platform = "generic"

    def build_payload(self, answer: Dict[str, Any]) -> Dict[str, Any]:
        text = format_answer_markdown(answer)
        return {"platform": self.platform, "msgtype": "markdown", "text": text}


class FeishuBotAdapter(ChatBotAdapter):
    platform = "feishu"

    def build_payload(self, answer: Dict[str, Any]) -> Dict[str, Any]:
        text = format_answer_markdown(answer)
        # Feishu interactive-card lite shape.
        return {
            "platform": self.platform,
            "msg_type": "interactive",
            "card": {
                "elements": [{"tag": "markdown", "content": text}],
                "header": {"title": {"tag": "plain_text", "content": "SCA ChatOps"}},
            },
        }


class DingTalkBotAdapter(ChatBotAdapter):
    platform = "dingtalk"

    def build_payload(self, answer: Dict[str, Any]) -> Dict[str, Any]:
        text = format_answer_markdown(answer)
        return {
            "platform": self.platform,
            "msgtype": "markdown",
            "markdown": {"title": "SCA ChatOps", "text": text},
        }


class WeComBotAdapter(ChatBotAdapter):
    platform = "wecom"

    def build_payload(self, answer: Dict[str, Any]) -> Dict[str, Any]:
        text = format_answer_markdown(answer)
        return {"platform": self.platform, "msgtype": "markdown", "markdown": {"content": text}}


_ADAPTERS = {
    "generic": ChatBotAdapter,
    "feishu": FeishuBotAdapter,
    "dingtalk": DingTalkBotAdapter,
    "wecom": WeComBotAdapter,
}


def get_bot_adapter(platform: str) -> ChatBotAdapter:
    return _ADAPTERS.get((platform or "generic").lower(), ChatBotAdapter)()
