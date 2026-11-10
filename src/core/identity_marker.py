"""身份指纹强度判定（唯一真相源）。

背景（R23-4 事故）：业务族差分重放用「响应体是否包含受害者标识」判定数据泄露
（d1_service.replay_bola 的 victim_markers），该标识同时来自登记期派生
（trigger_spec_registry._account_identifiers）与运行期账户属性。

账户属性里 username / email 是强指纹，而 JWT 里的 uid 常常是单位数（target-mall 为
admin=1 / alice=2 / bob=3）。把 "3" 当作泄露指纹时，几乎任何 JSON 响应体（金额、id、
时间戳）都含有数字 3 → data_leak 恒为真 → 批量假确认。故凡进入「响应体子串匹配」的
标识必须通过本模块的强度判定；哨兵解析等「构造请求」的用途不受此限。

判定规则（保守、只拦明显无区分度的值）：
- 空值、纯空白 → 弱；
- 纯数字且长度 < _MIN_NUMERIC_LEN → 弱（单位数/两位数 uid 无区分度）；
- 其余（用户名、邮箱、长数字 id、UUID 等）→ 强。
"""

from typing import Any, Iterable, List

# 纯数字指纹的最小可接受长度。3 位及以下在 JSON 响应体里几乎必然误命中（金额、页码、
# 数量、状态码片段等），故一律视为弱指纹。
_MIN_NUMERIC_LEN = 4


def is_strong_identity_marker(value: Any) -> bool:
    """该值能否作为「响应体差分」用的受害者身份指纹。"""
    text = str(value or "").strip()
    if not text:
        return False
    if text.isdigit() and len(text) < _MIN_NUMERIC_LEN:
        return False
    return True


def filter_identity_markers(values: Any) -> List[str]:
    """过滤并去重一组候选指纹，保序返回强指纹。"""
    if values is None:
        return []
    if isinstance(values, str):
        candidates: Iterable[Any] = [values]
    elif isinstance(values, (list, tuple, set)):
        candidates = list(values)
    else:
        return []
    out: List[str] = []
    seen = set()
    for item in candidates:
        if not is_strong_identity_marker(item):
            continue
        text = str(item).strip()
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out
