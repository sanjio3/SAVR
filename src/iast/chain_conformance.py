"""I1 逐节点链路符合性校验（§A2 poc 链 → 观测污点路径）。

职责：把 A2 预测的 poc 链（污点流经的有序节点序列）与探针实际观测到的污点路径比对，
产出每节点命中报告。

观测数据两路，方案 B 优先、方案 A 兜底：
- 方案 B：探针在每次「携带平台 canary 身份的污点值」经过 hook 时，
  把该 hook 的 origin(class.method) 记入本请求有序 taint_path，reportSink 时回带进事件
  context.taint_path（解析后形如 [{"role":"source|transform|sink","origin":"FQCN.method"}, ...]）。
  I1 据此对每个 transform 节点做「类名后缀 + 方法名」精确匹配，把方案 A 下只能标
  unverifiable 的中间节点（Base64.decode / readObject 等）升级为 matched（确证命中）。
- 方案 A（不动探针兜底）：当事件无 taint_path（旧探针 / 普通请求）时，回落到 stack_trace /
  sink_method / source_value 重建路径。中间节点因 stack 为空只能标 unverifiable（不可证伪）。

节点状态：matched（命中）/ unverifiable（探针有路径但桥接方法未 hook，无法否认链路）/
missing（确凿缺失）。
conforms = 无 missing 节点 且 source 已 matched。
"""
import json
import re
from typing import Any, Dict, List, Optional

# Java 栈帧：at com.foo.Bar.method(Bar.java:42)
_FRAME_RE = re.compile(r"at\s+([\w.$]+)\.(\w+)\((?:[\w.$]+\.\w+):(\d+)\)")
# Python 栈帧：File "x.py", line 42, in method
_PY_FRAME_RE = re.compile(r'File\s+"([^"]+)",\s+line\s+(\d+),\s+in\s+(\w+)')


def _origin_matches_signature(origin: str, signature: str) -> bool:
    """探针回带的 origin(FQCN.method) 与 A2 poc 节点 signature(FQCN.method) 是否同一方法。

    规则：方法名必须相等；类名做宽松匹配（子串包含 / 末尾相等 / 内部类 $ 归一），
    以容忍 A2 用简短类签名（java.util.Base64.decode）而探针用内部类写法
    （java.util.Base64$Decoder.decode）的差异。
    """
    if not origin or not signature:
        return False
    o_method = origin.rsplit('.', 1)[-1]
    s_method = signature.rsplit('.', 1)[-1]
    o_class = origin.rsplit('.', 1)[0] if '.' in origin else origin
    s_class = signature.rsplit('.', 1)[0] if '.' in signature else ''

    # 反序列化等价集（方案 B 核心收益）：ObjectInputStream.readObject 是 final 方法，ByteBuddy
    # 无法对其织入 advice（类被 retransform 但 readObject 本体仍是原字节码，onEnter 永不触发），探针
    # 实际以非 final的 resolveClass（反序列化每个对象时必被调用）/ readUnshared 作为 transform 落点。
    # 三者语义等价「污点流经 ObjectInputStream 反序列化入口」，故 A2 预测 readObject 而探针观测到
    # resolveClass（或反之）时判为同一节点，把方案 A 下只能标 unverifiable 的中间节点升级为 matched。
    # 必须在「严格方法名比对」之前先行判定，否则方法名不同会被 early-return 拒掉（旧实现的死代码 bug）。
    _DESERIAL_EQUIV = {"readobject", "resolveclass", "readunshared"}
    if o_method.lower() in _DESERIAL_EQUIV and s_method.lower() in _DESERIAL_EQUIV:
        # 类名对齐（A2 与探针都用 java.io.ObjectInputStream 时直接成立）；或双方类名都含
        # ObjectInputStream 时放宽等价（容忍 A2 用基类、探针落到更具体子类的写法差异）。
        if (not s_class) or (s_class in o_class or o_class.endswith(s_class) or s_class == o_class
                             or s_class in o_class.rsplit('.', 1)[-1].replace('$', '.')
                             or o_class.rsplit('.', 1)[-1].replace('$', '.').endswith(s_class)):
            return True
        if "objectinputstream" in o_class.lower() and "objectinputstream" in s_class.lower():
            return True
        return False

    if o_method != s_method:
        return False
    if not s_class:
        return True  # signature 只有方法名，方法名匹配即视为同一方法
    if s_class in o_class or o_class.endswith(s_class) or s_class == o_class:
        return True
    # 内部类 $ 与 simple 名归一：java.util.Base64$Decoder → 试 Base64$Decoder / Decoder
    o_simple = o_class.rsplit('.', 1)[-1].replace('$', '.')
    if s_class in o_simple or o_simple.endswith(s_class):
        return True
    return False


def extract_observed_path(event: Dict[str, Any]) -> Dict[str, Any]:
    """从探针 sink 事件重建观测到的污点路径信息。

    返回含方案 A（frames/stack）与方案 B（taint_path/origins）两路字段。
    """
    event = event or {}
    source_value = str(event.get("source_value", "") or "")
    canary = str(event.get("canary", "") or "")
    stack_trace = str(event.get("stack_trace", "") or "")
    sink_method = str(event.get("sink_method", "") or "")
    sink_file = str(event.get("sink_file", "") or "")
    sink_line = int(event.get("sink_line", 0) or 0)

    # 方案 A：stack_trace 帧
    frames: List[str] = []
    for m in _FRAME_RE.finditer(stack_trace):
        cls, method, line = m.group(1), m.group(2), m.group(3)
        frames.append(f"{cls}.{method}")
        frames.append(f"{cls}.{method}:{line}")
        frames.append(f"{cls}:{line}")
    for m in _PY_FRAME_RE.finditer(stack_trace):
        fpath, line, method = m.group(1), m.group(2), m.group(3)
        frames.append(f"{method}")
        frames.append(f"{fpath}:{line}")
    seen = set()
    ordered: List[str] = []
    for f in frames:
        if f not in seen:
            seen.add(f)
            ordered.append(f)

    # 方案 B：taint_path（已由 _parse_taint_path 解析为 [{"role","origin"}]）
    taint_path = event.get("taint_path") or []
    if isinstance(taint_path, str):
        try:
            taint_path = json.loads(taint_path)
        except (ValueError, TypeError):
            taint_path = []
    if not isinstance(taint_path, list):
        taint_path = []
    transform_origins = [str(n.get("origin", "")) for n in taint_path
                         if isinstance(n, dict) and n.get("role") == "transform" and n.get("origin")]
    sink_origins = [str(n.get("origin", "")) for n in taint_path
                    if isinstance(n, dict) and n.get("role") == "sink" and n.get("origin")]
    source_in_path = any(isinstance(n, dict) and n.get("role") == "source" for n in taint_path)
    has_taint_path = bool(taint_path)

    sink_label = ""
    if sink_method:
        sink_label = sink_method
    elif sink_file:
        sink_label = f"{sink_file}:{sink_line}" if sink_line else sink_file

    return {
        "source_present": bool(source_value) or bool(canary) or source_in_path,
        "source_value": source_value,
        "canary": canary,
        "frames": ordered,
        "has_stack": bool(ordered),
        "sink": sink_label,
        "sink_method": sink_method,
        "sink_file": sink_file,
        "sink_line": sink_line,
        # 方案 B
        "taint_path": taint_path,
        "has_taint_path": has_taint_path,
        "transform_origins": transform_origins,
        "sink_origins": sink_origins,
    }


def _node_status(node: Dict[str, Any], observed: Dict[str, Any]) -> Dict[str, Any]:
    """判定单个 poc_chain 节点状态：matched / unverifiable / missing。"""
    role = str(node.get("role", "") or "")
    signature = str(node.get("signature", "") or "").strip()
    label = str(node.get("node", "") or "").strip()
    has_taint_path = observed.get("has_taint_path", False)
    transform_origins = observed.get("transform_origins", [])
    sink_origins = observed.get("sink_origins", [])
    frames = observed.get("frames", [])
    has_stack = observed.get("has_stack", False)

    if role == "source":
        ok = observed.get("source_present", False)
        return {"role": role, "node": label, "signature": signature,
                "status": "matched" if ok else "missing",
                "reason": "source 污点数据进入（canary/source_value/taint_path.source 命中）" if ok
                else "source 污点未观测到进入"}

    if role == "transform":
        # 方案 B：taint_path 精确逐节点匹配
        if has_taint_path:
            for origin in transform_origins:
                if _origin_matches_signature(origin, signature):
                    return {"role": role, "node": label, "signature": signature, "status": "matched",
                            "reason": f"taint_path 命中 origin={origin}（类别/方法匹配 A2 预期）"}
            # 探针有路径数据但未记录该桥接方法：不可证伪，不阻断（与方案 A 的 unverifiable 语义一致）
            return {"role": role, "node": label, "signature": signature, "status": "unverifiable",
                    "reason": "探针 taint_path 未包含该 transform 桥接方法（可能未 hook 此步），不足以证伪链路"}
        # 方案 A 兜底：用 stack_trace 帧
        if signature and signature in frames:
            return {"role": role, "node": label, "signature": signature, "status": "matched",
                    "reason": f"观测帧包含 {signature}"}
        if label and label in frames:
            return {"role": role, "node": label, "signature": signature, "status": "matched",
                    "reason": f"观测帧包含节点标签 {label}"}
        if not has_stack:
            return {"role": role, "node": label, "signature": signature, "status": "unverifiable",
                    "reason": "探针未上报中间节点路径（无 taint_path 且 stack_trace 为空），该 transform 节点不可证伪"}
        return {"role": role, "node": label, "signature": signature, "status": "missing",
                "reason": f"观测路径未包含 {signature or label}"}

    # sink
    if has_taint_path:
        for origin in sink_origins:
            if _origin_matches_signature(origin, signature):
                return {"role": role, "node": label, "signature": signature, "status": "matched",
                        "reason": f"taint_path sink 命中 origin={origin}"}
        # 有 sink 节点但不精确匹配（落点常为框架桥接方法，如 StringHttpMessageConverter.writeInternal）：
        # 以「数据到达 sink」判到达性 matched（方案 A 的 sink_method 存在即 matched 同源）。
        return {"role": role, "node": label, "signature": signature, "status": "matched",
                "reason": f"taint_path 存在 sink 节点（数据到达 sink），落点={sink_origins}"}
    # 方案 A 兜底
    if observed.get("sink_method"):
        return {"role": role, "node": label, "signature": signature, "status": "matched",
                "reason": f"观测 sink_method={observed.get('sink_method')} 命中（canary 到达 sink）"}
    if signature and signature in frames:
        return {"role": role, "node": label, "signature": signature, "status": "matched",
                "reason": f"观测帧包含 {signature}"}
    if not has_stack:
        return {"role": role, "node": label, "signature": signature, "status": "unverifiable",
                "reason": "探针未上报 sink 路径（无 taint_path 且 sink_file 为空/无 stack_trace），无法确认或否认"}
    return {"role": role, "node": label, "signature": signature, "status": "missing",
            "reason": f"观测路径未包含 {signature or label}"}


def verify_chain_conformance(poc_chain: List[Dict[str, Any]], event: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """I1 核心：逐节点比对 A2 poc 链与观测污点路径。

    返回 {conforms, checked, matched, unverifiable, missing:[node], per_node:[...], observed_frames,
          sink, observed_present, has_stack, has_taint_path, taint_path, order_ok}。
    - conforms：无 missing 节点 且 source 已 matched（transform 的 unverifiable 不阻断）。
    - 若 event 为空（I1 未观测到任何事件），conforms=False、per_node 全 missing。
    """
    poc_chain = poc_chain or []
    if not event:
        return {
            "conforms": False,
            "checked": len(poc_chain),
            "matched": 0,
            "unverifiable": 0,
            "missing": [n.get("node", "") for n in poc_chain],
            "per_node": [{"role": n.get("role"), "node": n.get("node"), "signature": n.get("signature"),
                          "status": "missing", "reason": "I1 未观测到任何探针事件（canary 未到达）"} for n in poc_chain],
            "observed_frames": [], "sink": "", "observed_present": False, "has_stack": False,
            "has_taint_path": False, "taint_path": [], "order_ok": True,
        }
    observed = extract_observed_path(event)
    per_node = [_node_status(n, observed) for n in poc_chain]
    matched = sum(1 for p in per_node if p["status"] == "matched")
    unverifiable = sum(1 for p in per_node if p["status"] == "unverifiable")
    missing = [p["node"] for p in per_node if p["status"] == "missing"]
    source_ok = any(p["role"] == "source" and p["status"] == "matched" for p in per_node)

    # 顺序性：source 必须在 transform/sink 之前（观测栈/taint_path 天然满足）；仅当存在 source 节点且
    # 某非 source 节点 matched 而其前的 source 未 matched 时才判 order 异常。
    order_ok = True
    saw_source = False
    for p in per_node:
        if p["role"] == "source":
            saw_source = (p["status"] == "matched") or saw_source
        elif p["status"] == "matched" and not saw_source and any(n["role"] == "source" for n in poc_chain):
            order_ok = False

    conforms = (len(missing) == 0) and source_ok and order_ok and (len(poc_chain) > 0)

    return {
        "conforms": conforms,
        "checked": len(poc_chain),
        "matched": matched,
        "unverifiable": unverifiable,
        "missing": missing,
        "per_node": per_node,
        "observed_frames": observed.get("frames", []),
        "sink": observed.get("sink", ""),
        "observed_present": True,
        "has_stack": observed.get("has_stack", False),
        "has_taint_path": observed.get("has_taint_path", False),
        "taint_path": observed.get("taint_path", []),
        "order_ok": order_ok,
    }
