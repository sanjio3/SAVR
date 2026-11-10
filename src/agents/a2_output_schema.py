"""A2 输出 JSON Schema（2026-10-25，plan §20.3.3 约束解码）。

## 为什么做

`analyze()` 的契约校验失败会「带错误回灌重试一次」。重试是最贵的浪费——每次重试 =
一次完整 prefill + decode（实测 decode 严格随输出 token 线性，tok/s 恒定 30~36）。
Ollama 的 `format` 走 llama.cpp 的 grammar 约束解码，用 JSON Schema 可以从**源头**
让输出必然合规，把「格式幻觉 → 回退重试」这条最贵的浪费压掉。

## 约束口径（与 `_output_contract()` 的 full 档一致，**不裁字段**）

- lean 档裁字段已被 A/B **否决**（掉 TP 3 个 + 多 1 个 FP），所以 schema 保留
  `snippet` / `why_bypassable` / `sink_reached_explanation` 等全部审计字段；
- `spec` 允许为 `null`（对应「false_positive 时 spec 为 null」的契约）；
- `verdict` 用 enum 限定为 real / false_positive（8B 模型会填反，enum 能从语法层堵住）；
- `line` 限定 integer（模型爱写字符串）。

本模块只负责「产出 schema」与「选档位」，不做 LLM 调用，便于单测。
"""
from __future__ import annotations

import json
from typing import Any, Dict

# 合法档位：json（默认，等价于 format="json"，行为不变）/ schema（grammar 约束）/ off（不约束）
FORMAT_MODES = ("json", "schema", "off")

# sanitizer.type 的合法取值（与 _output_contract() full 档文案一致）
_SANITIZER_TYPES = (
    "parameterized", "whitelist", "encode_html", "encode_sql", "blacklist_replace",
    "regex", "truncate", "cast", "none", "unknown",
)
_PARAM_LOCATIONS = ("query", "body", "cookie", "header")


def resolve_format_mode(raw: str) -> str:
    """把环境变量值规整成合法档位（非法值回退 json，保持历史行为）。"""
    v = str(raw or "").strip().lower()
    return v if v in FORMAT_MODES else "json"


def a2_output_schema() -> Dict[str, Any]:
    """返回 A2 输出的 JSON Schema（数组，每项一个 finding 的判定）。"""
    return {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "line": {"type": "integer"},
                "verdict": {"type": "string", "enum": ["real", "false_positive"]},
                "reason": {"type": "string"},
                "spec": {
                    "type": ["object", "null"],
                    "properties": {
                        "route": {"type": "string"},
                        "method": {"type": "string", "enum": ["GET", "POST", "PUT",
                                                              "DELETE", "PATCH", "HEAD"]},
                        "param_name": {"type": "string"},
                        "param_location": {"type": "string", "enum": list(_PARAM_LOCATIONS)},
                        "payload": {"type": "string"},
                        "bypass_payloads": {"type": "array", "items": {"type": "string"}},
                        "content_type": {"type": "string"},
                        "sanitizer": {
                            "type": "object",
                            "properties": {
                                "present": {"type": "boolean"},
                                "type": {"type": "string", "enum": list(_SANITIZER_TYPES)},
                                "strength": {"type": "string",
                                             "enum": ["strong", "weak", "unknown", "none"]},
                                "location": {"type": "string"},
                                # snippet / why_bypassable 必须保留：模型「抄一遍净化器实现」
                                # 这个动作本身帮助它判 strength ⇒ 直接影响 verdict（砍掉掉 TP）。
                                "snippet": {"type": "string"},
                                "why_bypassable": {"type": "string"},
                            },
                            "required": ["present", "type", "strength"],
                        },
                    },
                    "required": ["route", "method", "param_name", "param_location",
                                 "payload", "bypass_payloads", "sanitizer"],
                },
            },
            "required": ["line", "verdict", "reason", "spec"],
        },
    }


def schema_json() -> str:
    """序列化后的 schema 文本（便于落日志/比对）。"""
    return json.dumps(a2_output_schema(), ensure_ascii=False, sort_keys=True)
