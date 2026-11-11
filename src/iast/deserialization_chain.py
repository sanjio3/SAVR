"""反序列化族的运行时链路确证。

背景：Java 原生反序列化 RCE 在平台上是「能报不能证」的三重断点——
1. canary 是字符串，序列化 payload 是二进制，canary 进不了 readObject 的实参；
2. ``ObjectInputStream.readObject`` 是 final 方法，ByteBuddy 织不进去，探针只钩了
   非 final 的 ``resolveClass`` 并把它当 **transform 跳点**（见
   ``BootstrapGenericSinkAdvice``：显式 return，不进 onGenericSink，故不产 sink 事件）；
3. 实测全库 ``iast_events WHERE sink_file LIKE '%ObjectInputStream%'`` = **0 条**，
   D2 对该族永远 no_evidence，只能停在 ambiguous。

但 gadget 链无论 CC1 / CC6 / CB / C3P0，**最终一定落到 Runtime.exec 或
ProcessBuilder.start**，而这两个探针已经钩住；且 ``resolveClass`` 的 transform 跳点
已经通过 ``TaintStore.recordTaintHop`` 写进了本请求的 taint_path。

所以「链路符合性」这条路是通的：**不必要求 canary 到达 exec 的实参**，只需证明
「攻击者可控字节流 → 经过 ObjectInputStream 反序列化 → 触发命令执行 sink」
三者在同一请求内同时发生，即构成反序列化 RCE 的运行时确证。

本模块提供两件事：
- ``canonical_poc_chain``：deserialization 族的确定性链模板，供 A2 在 LLM 未产出
  poc_chain 时兜底（LLM 自由发挥的链经常漏掉 readObject 节点，导致 I1 无节点可匹配）；
- ``runtime_chain_confirmed``：从 I1 证据判定该链是否被真实观测命中。

与 ``chain_conformance.py`` 的分工：后者是通用逐节点比对器（已含
``_DESERIAL_EQUIV`` 等价集，能把 A2 预测 readObject / 探针观测 resolveClass 判为同一
节点）；本模块是族级确证器，在 canary 通道结构性失效时提供替代确证路径。
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 归一到反序列化族的族名集合（含 A2/CodeQL 各自写法）。
DESERIAL_FAMILIES = frozenset({
    "deserialization",
    "java-deserialization",
    "insecure-deserialization",
    "unsafe-deserialization",
    "java_map_deserialization",
    "map-deserialization",
})

# 「反序列化确实发生」的探针落点：readObject 是 final 织不进去，探针实际落在
# resolveClass / readUnshared；多态库走各自的 readValue / parseObject / load / fromXML。
_DESERIAL_NODE_METHODS = frozenset({
    "readobject", "resolveclass", "readunshared",
})

_DESERIAL_CLASS_TOKENS = (
    "objectinputstream",
    "com.fasterxml.jackson.databind.objectmapper",
    "com.alibaba.fastjson.json",
    "org.yaml.snakeyaml.yaml",
    "com.thoughtworks.xstream.xstream",
    "java.beans.xmldecoder",
)

# gadget 链的执行终点（探针已钩住 exec / start）。
# ``JdbcRowSetImpl.setUrl``（JNDI 型，终点是 InitialContext.lookup → LDAP/RMI 远程加载），
# TemplatesImpl 型终点是 newTransformer/getOutputProperties。这类链同样构成反序列化 RCE，
# 却因终点不在表内而被判「链路未闭合」，第三层确证静默失效。
# 故按 gadget 族补齐终点白名单（只加**语义明确的执行点**）：
#   - 命令执行：exec / ProcessBuilder.start / ProcessImpl / UNIXProcess
#   - JNDI 远程加载：javax.naming 的 lookup（JdbcRowSetImpl / C3P0 / LDAP 型链终点）
#   - 字节码加载执行：TemplatesImpl.newTransformer / getOutputProperties（JDK7u21/CC 变体）
# 刻意**不加** java.lang.reflect.Method.invoke：它是框架反射的通用调用点，
# 在 Spring/Tomcat 里每请求成千上万次，加入会退化成「有反射即确证」的假阳性通道，
# 与零误杀纪律冲突。真 Method.invoke 型链（如部分 CC 变体）终点仍会落到 exec，可被覆盖。
_RCE_SINK_TOKENS = (
    "java.lang.Runtime.exec",
    "java.lang.ProcessBuilder.start",
    "java.lang.ProcessImpl",
    "java.lang.UNIXProcess",
    "java.lang.ProcessImpl.start",
    "javax.naming.InitialContext.lookup",
    "javax.naming.Context.lookup",
    "javax.naming.InitialContext.doLookup",
    "com.sun.rowset.JdbcRowSetImpl.setUrl",
    "com.sun.rowset.JdbcRowSetImpl.connect",
    "TemplatesImpl.newTransformer",
    "TemplatesImpl.getOutputProperties",
    "org.apache.xalan.xsltc.trax.TemplatesImpl",
)


def is_deserialization_family(family: Optional[str]) -> bool:
    """族名是否归一到反序列化族。"""
    f = str(family or "").strip().lower().replace("_", "-")
    if not f:
        return False
    if f in DESERIAL_FAMILIES:
        return True
    # 宽容：LLM 偶尔写成 "java deserialization" / "反序列化"
    return ("deserial" in f) or ("反序列化" in str(family or ""))


def canonical_poc_chain(
    endpoint: str = "",
    param_name: str = "",
    sink_signature: str = "",
) -> List[Dict[str, str]]:
    """deserialization 族的确定性 poc 链模板（source → decode → readObject → exec）。

    为什么需要模板：A2 的 poc_chain 由 LLM 自由产出（``a2_contract_planner``），
    实测常缺 readObject 节点或把 sink 写成业务方法名而非 Runtime.exec，
    于是 I1 逐节点比对时无节点可匹配，链路判据形同虚设。

    节点签名与 ``chain_conformance._origin_matches_signature`` 对齐：
    - ``java.io.ObjectInputStream.readObject`` 与探针观测的 ``resolveClass`` 由
      ``_DESERIAL_EQUIV`` 等价集判为同一节点；
    - ``java.util.Base64$Decoder.decode`` 与 signature ``java.util.Base64.decode``
      由内部类 ``$`` 归一规则判为同一节点。
    """
    _sink = str(sink_signature or "").strip()
    if not _sink or "exec" not in _sink.lower() and "processbuilder" not in _sink.lower():
        _sink = "java.lang.Runtime.exec"
    return [
        {
            "stage": "source",
            "role": "source",
            "node": f"攻击者可控输入 {endpoint or '<endpoint>'}#{param_name or 'data'}",
            "signature": "",
        },
        {
            "stage": "transform",
            "role": "transform",
            "node": "Base64 解码（序列化对象的常见传输形态）",
            "signature": "java.util.Base64.decode",
        },
        {
            "stage": "transform",
            "role": "transform",
            "node": "ObjectInputStream 反序列化入口（污点字节流被还原为对象）",
            "signature": "java.io.ObjectInputStream.readObject",
        },
        {
            "stage": "sink",
            "role": "sink",
            "node": "命令执行 sink（gadget 链终点）",
            "signature": _sink,
        },
    ]


def _collect_origins(iast_evidence: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """从 I1 证据里取出观测到的 transform / sink origin 列表。

    兼容三种形态（按优先级）：
    1. ``chain_conformance.taint_path``（方案 B，最完整）；
    2. ``chain_conformance.per_node`` 里 matched 节点的 signature；
    3. 直接的 ``transform_origins`` / ``sink_origins`` 字段（部分调用方展平后传入）。
    """
    ev = iast_evidence or {}
    cc = ev.get("chain_conformance") if isinstance(ev.get("chain_conformance"), dict) else {}

    t_path = cc.get("taint_path")
    if isinstance(t_path, str):
        import json
        try:
            t_path = json.loads(t_path)
        except (ValueError, TypeError):
            t_path = []
    transforms: List[str] = []
    sinks: List[str] = []
    if isinstance(t_path, list):
        for n in t_path:
            if not isinstance(n, dict):
                continue
            role = str(n.get("role") or "")
            origin = str(n.get("origin") or "")
            if not origin:
                continue
            if role == "transform":
                transforms.append(origin)
            elif role == "sink":
                sinks.append(origin)

    # 直接字段兜底
    for k in ("transform_origins", "observed_transforms"):
        v = ev.get(k)
        if isinstance(v, list):
            transforms.extend(str(x) for x in v if x)
    for k in ("sink_origins", "observed_sinks"):
        v = ev.get(k)
        if isinstance(v, list):
            sinks.extend(str(x) for x in v if x)

    # per_node 兜底：matched 节点按 role 归档
    for n in (cc.get("per_node") or []):
        if not isinstance(n, dict) or n.get("status") != "matched":
            continue
        sig = str(n.get("signature") or "")
        if not sig:
            continue
        if str(n.get("role")) == "transform":
            transforms.append(sig)
        elif str(n.get("role")) == "sink":
            sinks.append(sig)

    # 去重保序
    def _uniq(seq: List[str]) -> List[str]:
        out, seen = [], set()
        for s in seq:
            if s and s not in seen:
                seen.add(s)
                out.append(s)
        return out

    return _uniq(transforms), _uniq(sinks)


def _is_deserialization_node(origin: str) -> bool:
    o = str(origin or "").lower()
    if not o:
        return False
    method = o.rsplit(".", 1)[-1] if "." in o else o
    if method in _DESERIAL_NODE_METHODS:
        # 方法名命中时还要求类名像反序列化入口（避免任何类的 readObject 都被算进来）
        return any(t in o for t in _DESERIAL_CLASS_TOKENS) or "objectinputstream" in o
    return any(t in o for t in _DESERIAL_CLASS_TOKENS)


def _is_rce_sink(origin: str) -> bool:
    o = str(origin or "").lower()
    return any(t.lower() in o for t in _RCE_SINK_TOKENS)


def runtime_chain_confirmed(
    iast_evidence: Optional[Dict[str, Any]],
    family: Optional[str],
) -> Optional[Dict[str, Any]]:
    """反序列化 RCE 的运行时链路确证（canary 通道失效时的替代路径）。

    判据（三者缺一不可）：
    1. 族归一到反序列化族；
    2. 观测路径里存在 ObjectInputStream 类反序列化节点（证明反序列化确实发生）；
    3. 观测路径里存在命令执行 sink（证明该请求确实触发了 RCE 终点）。

    只返回「证据确凿」的结果：任一条不满足即返回 None，交由上层继续走原有
    （no_evidence / time-blind）判定，绝不把不确定包装成确证。
    """
    if not is_deserialization_family(family):
        return None
    if not iast_evidence:
        return None

    transforms, sinks = _collect_origins(iast_evidence)
    deser_nodes = [o for o in transforms if _is_deserialization_node(o)]
    rce_nodes = [o for o in sinks if _is_rce_sink(o)]
    # sink 也可能落在 transform 列表里（探针 role 归类差异），两路并集
    if not rce_nodes:
        rce_nodes = [o for o in transforms if _is_rce_sink(o)]

    if not deser_nodes or not rce_nodes:
        logger.debug(
            "[deser-chain] 链路未闭合：deser_nodes=%s rce_nodes=%s（族=%s）",
            deser_nodes, rce_nodes, family,
        )
        return None

    return {
        "confirmed": True,
        "family": str(family),
        "deserialization_nodes": deser_nodes,
        "rce_sinks": rce_nodes,
        "reason": (
            "反序列化链路确证：同一请求内观测到攻击者可控字节流经 "
            f"{deser_nodes[0]} 反序列化，并触发命令执行 sink {rce_nodes[0]}。"
            "canary 无法进入二进制序列化对象（结构性限制），故以链路符合性替代 canary 到达判据。"
        ),
    }
