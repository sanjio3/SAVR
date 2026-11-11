"""Ticketing / AppSec platform integration (G12, 第四版 /2.9).

Abstraction over external issue trackers. Concrete default is offline: render a
finding to a Markdown ticket body ("复制到工单") and, when a webhook URL is
configured, build the JSON payload. Actual delivery is opt-in and proxy-aware;
``create_ticket`` in the base/offline adapter never performs network I/O — it
returns the prepared ticket so a caller (or a real adapter) can send it. GitLab/
Jira adapters are stubbed with a clear extension point.
"""

from typing import Any, Dict, Optional


def render_ticket_markdown(finding: Dict[str, Any]) -> str:
    """Render a finding into a copy-to-ticket Markdown body."""
    title = finding.get("attack_chain_summary") or finding.get("display_title") or finding.get("title") or "Security finding"
    family = finding.get("display_family") or finding.get("type") or "unknown"
    severity = finding.get("severity") or "UNKNOWN"
    file_path = finding.get("file") or finding.get("file_path") or ""
    line = finding.get("line") or ""
    vuln_hash = finding.get("vulnerability_hash_v2") or ""
    lines = [
        f"## [{severity}] {title}",
        "",
        f"- 类别：{family}",
        f"- 位置：{file_path}:{line}" if file_path else "- 位置：(未知)",
        f"- 指纹：`{vuln_hash}`" if vuln_hash else "",
        "",
        "### 描述",
        str(finding.get("description") or finding.get("attack_chain_summary") or ""),
    ]
    remediation = finding.get("remediation") or finding.get("fix_suggestion")
    if remediation:
        lines += ["", "### 修复建议", str(remediation)]
    return "\n".join(line for line in lines if line != "")


class TicketingAdapter:
    """Base adapter: prepares a ticket; delivery is the concern of subclasses."""

    platform = "offline"

    def __init__(self, *, webhook_url: str = "", enabled: bool = False):
        self.webhook_url = webhook_url
        self.enabled = enabled

    def create_ticket(self, finding: Dict[str, Any], *, project: str = "") -> Dict[str, Any]:
        body = render_ticket_markdown(finding)
        title = finding.get("display_title") or finding.get("title") or "Security finding"
        payload = {
            "platform": self.platform,
            "project": project,
            "title": title,
            "body": body,
            "labels": ["security", str(finding.get("display_family") or "sast")],
            "delivered": False,  # offline default never sends
            "webhook_url": self.webhook_url,
        }
        return payload

    def sync_status(self, ticket_id: str, status: str) -> Dict[str, Any]:
        return {"platform": self.platform, "ticket_id": ticket_id, "status": status, "delivered": False}


class WebhookTicketingAdapter(TicketingAdapter):
    platform = "webhook"


class GitLabTicketingAdapter(TicketingAdapter):
    platform = "gitlab"
    # Extension point: implement create_ticket via GitLab Issues API when enabled.


class JiraTicketingAdapter(TicketingAdapter):
    platform = "jira"
    # Extension point: implement create_ticket via Jira REST API when enabled.


_ADAPTERS = {
    "offline": TicketingAdapter,
    "webhook": WebhookTicketingAdapter,
    "gitlab": GitLabTicketingAdapter,
    "jira": JiraTicketingAdapter,
}


def get_ticketing_adapter(platform: str, *, webhook_url: str = "", enabled: bool = False) -> TicketingAdapter:
    cls = _ADAPTERS.get((platform or "offline").lower(), TicketingAdapter)
    return cls(webhook_url=webhook_url, enabled=enabled)
