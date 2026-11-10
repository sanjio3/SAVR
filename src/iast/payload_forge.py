"""SCA 驱动选弹（方案 C：弹药库为主 + LLM 兜底；方案 D：ysoserial 外部工具集成）。

为什么需要这一层
----------------
A2 对反序列化族历来只产出 `base64(serialized_object)` 这类占位串——它描述的是「这里该有个
序列化对象」，而不是一个能被目标 JVM 真正反序列化的 gadget 链。D1 拿到占位串只能降级成
canary 探针，`attack_degraded=True`，一条本该真打的链就此变成弱证据。

反序列化 payload 是**精确字节构造**：链名、库版本、JDK 版本三者任何一个对不上，投出去就是
一堆解不开的废字节。所以不能让 LLM 直接造（它造不出合法的序列化流），必须：

1. 弹药库（config/payload_library.yaml）：按 (family, ecosystem, package, version_range)
   给出当前版本**确定可用**的链 —— 确定性、可审计、可离线（方案 A 的骨架）。
2. 可达性门控（src/iast/reachability.py）：库在 classpath 上 + 代码里有利用入口，
   两条都过才允许选弹（SCA 命中版本 ≠ 可利用）。
3. ysoserial 外部工具（tools/ysoserial-all.jar）：按链名运行时生成真实 gadget 字节流（方案 D）。
4. LLM 兜底（方案 C）：弹药库没覆盖的库才走 LLM 生成候选，且**必须通过自检才允许登记**，
   自检不过就老实返回空，让 D1 降级——绝不让伪造的废弹混进验证链。

LLM 兜底的自检为什么必须是硬门槛
----------------------------------
LLM 生成的「Java 序列化字节」几乎不可能是合法流（缺 AC ED 00 05 魔数、缺类描述符结构）。
若不经自检直接登记，D1 会把废字节投出去，得到一次假阴性，
而这次假阴性会被 I2 当成「打过了但没成」，比老实降级更有害。
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

_LIBRARY_PATH = Path(__file__).resolve().parents[2] / "config" / "payload_library.yaml"
_JAR_PATH = Path(__file__).resolve().parents[2] / "tools" / "ysoserial-all.jar"

# Java 原生序列化流魔数。LLM 生成的假序列化数据基本不可能带这个头，
# 所以它是 ysoserial 类 payload 自检最有效的一道门槛。
_JAVA_SERIALIZED_MAGIC = b"\xac\xed\x00\x05"

_DEFAULT_CALLBACK_PLACEHOLDER = "{callback}"


# --------------------------------------------------------------------------- 版本范围


def _version_tokens(version: str) -> List[int]:
    toks: List[int] = []
    for part in str(version or "").replace("-", ".").replace("_", ".").split("."):
        m = re.match(r"^\d+", part.strip())
        if not m:
            break
        toks.append(int(m.group()))
    return toks


def _cmp_versions(a: str, b: str) -> int:
    """返回 -1/0/1。短版本按 0 补齐（3.1 == 3.1.0）。"""
    ta, tb = _version_tokens(a), _version_tokens(b)
    n = max(len(ta), len(tb))
    ta += [0] * (n - len(ta))
    tb += [0] * (n - len(tb))
    return (ta > tb) - (ta < tb)


def version_in_range(version: str, spec: str) -> bool:
    """判断版本是否落在弹药库的 version_range 内。

    支持：`*`（不限）、`<=1.2.24`、`>=3.1,<=3.2.1`、`==4.0`、`4.0`（等价 ==）。
    版本不可解析时返回 False（保守：判不出就当不在范围内，宁可漏选）。
    """
    spec = str(spec or "").strip()
    if not spec or spec == "*":
        return True
    if not _version_tokens(version):
        return False
    for clause in spec.split(","):
        clause = clause.strip()
        if not clause:
            continue
        m = re.match(r"^(>=|<=|==|>|<|=)?\s*(.+)$", clause)
        if not m:
            continue
        op, target = m.group(1) or "==", m.group(2).strip()
        if not _version_tokens(target):
            continue
        c = _cmp_versions(version, target)
        if op == ">=" and not c >= 0:
            return False
        if op == "<=" and not c <= 0:
            return False
        if op == ">" and not c > 0:
            return False
        if op == "<" and not c < 0:
            return False
        if op in ("==", "=") and c != 0:
            return False
    return True


def _name_matches(declared: str, target: str) -> bool:
    """依赖名匹配：全等，或「冒号后一段」相等（兼容 groupId:artifactId 与裸 artifactId）。"""
    d = str(declared or "").strip().lower()
    t = str(target or "").strip().lower()
    if not d or not t:
        return False
    if d == t:
        return True
    d_tail = d.rsplit(":", 1)[-1]
    t_tail = t.rsplit(":", 1)[-1]
    return bool(d_tail) and d_tail == t_tail


# --------------------------------------------------------------------------- 造弹器


class PayloadForge:
    """SCA 驱动选弹：弹药库匹配 → 可达性门控 → 造弹（ysoserial / text）→ 自检 → LLM 兜底。"""

    def __init__(self,
                 library_path: Optional[str] = None,
                 jar_path: Optional[str] = None,
                 callback_base: str = "",
                 timeout: int = 120,
                 gateway: Any = None,
                 reachability_judge: Optional[Callable[..., Dict[str, Any]]] = None):
        self.library_path = Path(library_path) if library_path else _LIBRARY_PATH
        self.jar_path = Path(jar_path) if jar_path else _JAR_PATH
        self.callback_base = callback_base or ""
        self.timeout = timeout
        self.gateway = gateway
        # 可达性判定可注入：测试里替换掉，避免为跑单测去准备真实代码根。
        self._judge_reachability = reachability_judge
        self._library: Optional[List[Dict[str, Any]]] = None

    # ---------------------------------------------------------------- 弹药库

    @property
    def library(self) -> List[Dict[str, Any]]:
        if self._library is None:
            self._library = self._load_library()
        return self._library

    def _load_library(self) -> List[Dict[str, Any]]:
        if not self.library_path.exists():
            logger.warning("[payload_forge] 弹药库不存在：%s（选弹将全部回落 LLM 兜底）", self.library_path)
            return []
        try:
            import yaml
            data = yaml.safe_load(self.library_path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            logger.warning("[payload_forge] 弹药库加载失败：%s", exc)
            return []
        chains = data.get("chains") or []
        if not self.callback_base:
            self.callback_base = str(data.get("callback_base") or "")
        return [c for c in chains if isinstance(c, dict) and c.get("id")]

    def select_chains(self, component: Dict[str, Any], family: str = "") -> List[Dict[str, Any]]:
        """按 (family, ecosystem, package, version) 从弹药库挑可用链，按 priority 降序。

        只做「版本是否对得上」的匹配；classpath 与利用入口的可达性由调用方判定（或走
        forge_from_sca 的综合入口）。返回空表示弹药库没覆盖这个库/版本。
        """
        component = component or {}
        name = str(component.get("name") or component.get("component_name") or "").strip()
        version = str(component.get("version") or component.get("component_version") or "").strip()
        ecosystem = str(component.get("ecosystem") or "").strip().lower()
        fam = str(family or "").strip().lower()
        if not name:
            return []

        hits: List[Dict[str, Any]] = []
        for chain in self.library:
            chain_fam = str(chain.get("family") or "").strip().lower()
            if fam and chain_fam and chain_fam != fam:
                continue
            if ecosystem and str(chain.get("ecosystem") or "").strip().lower() != ecosystem:
                continue
            if not _name_matches(chain.get("package", ""), name):
                continue
            if not version_in_range(version, chain.get("version_range", "*")):
                continue
            hits.append(chain)
        hits.sort(key=lambda c: int(c.get("priority") or 0), reverse=True)
        return hits

    # ---------------------------------------------------------------- 造弹

    def forge(self, chain: Dict[str, Any], command: str = "",
              runner: Optional[Callable[..., Optional[bytes]]] = None) -> Optional[str]:
        """按链造出可投放的 payload 字符串；失败返回 None（调用方按降级处理）。

        - kind=ysoserial：调 `java -jar ysoserial-all.jar <链名> '<命令>'`，stdout 是二进制
          序列化流，base64 后投放。command 为空时用什么命令由调用方决定（见 forge_from_sca）。
        - kind=text：按 template 构造，把 {callback} 替换成 JNDI 回调地址。
        """
        if not chain:
            return None
        kind = str(chain.get("kind") or "ysoserial").strip().lower()

        if kind == "text":
            return self._forge_text(chain)
        return self._forge_ysoserial(chain, command=command, runner=runner)

    def _forge_text(self, chain: Dict[str, Any]) -> Optional[str]:
        template = str(chain.get("template") or "").strip()
        if not template:
            logger.warning("[payload_forge] text 链 %s 缺 template，无法造弹", chain.get("id"))
            return None
        callback = self.callback_base or "ldap://127.0.0.1:1389/sastai"
        payload = template.replace(_DEFAULT_CALLBACK_PLACEHOLDER, callback)
        if _DEFAULT_CALLBACK_PLACEHOLDER in payload:
            logger.warning("[payload_forge] text 链 %s 的 callback 占位符未替换干净", chain.get("id"))
            return None
        return payload

    def _forge_ysoserial(self, chain: Dict[str, Any], command: str = "",
                         runner: Optional[Callable[..., Optional[bytes]]] = None) -> Optional[str]:
        payload_name = str(chain.get("payload_name") or "").strip()
        if not payload_name:
            logger.warning("[payload_forge] ysoserial 链 %s 缺 payload_name", chain.get("id"))
            return None
        if not command:
            logger.warning("[payload_forge] 链 %s 无 command，拒绝造空命令 gadget"
                           "（空命令的 gadget 打过去无法产生可观测副作用，等同废弹）", chain.get("id"))
            return None
        if not self.jar_path.exists():
            logger.warning("[payload_forge] ysoserial jar 不存在：%s", self.jar_path)
            return None

        runner = runner or _run_ysoserial
        try:
            raw = runner(str(self.jar_path), payload_name, command, self.timeout)
        except Exception as exc:
            logger.warning("[payload_forge] ysoserial 生成失败（链=%s）：%s", payload_name, exc)
            return None
        if not raw:
            logger.warning("[payload_forge] ysoserial 链 %s 未产出字节流", payload_name)
            return None
        return base64.b64encode(raw).decode("ascii")

    # ---------------------------------------------------------------- 自检

    @staticmethod
    def selfcheck(payload: str, kind: str = "ysoserial") -> bool:
        """payload 自检：不过就不许登记。

        ysoserial 类：base64 解码后必须以 Java 序列化魔数 AC ED 00 05 开头。
        —— LLM 生成的假序列化流几乎必挂在这一条上，这正是它存在的意义。
        text 类：必须是合法 JSON，且不含未替换的 {callback} 占位符。
        """
        if not payload:
            return False
        if str(kind).strip().lower() == "text":
            if _DEFAULT_CALLBACK_PLACEHOLDER in payload:
                return False
            try:
                json.loads(payload)
            except (ValueError, TypeError):
                return False
            return True
        try:
            raw = base64.b64decode(payload, validate=True)
        except Exception:
            return False
        return raw.startswith(_JAVA_SERIALIZED_MAGIC) and len(raw) > 8

    # ---------------------------------------------------------------- LLM 兜底

    def llm_forge(self, component: Dict[str, Any], family: str = "",
                  command: str = "") -> List[str]:
        """弹药库没覆盖时的 LLM 兜底（方案 C 的第二条腿）。

        生成的候选**必须过 selfcheck 才返回**，过不了就返回空列表——
        宁可让 D1 老实降级，也不把伪造的废弹投进验证链。
        无 gateway 时直接返回空（不静默造垃圾）。
        """
        if self.gateway is None:
            return []
        name = str((component or {}).get("name") or (component or {}).get("component_name") or "")
        version = str((component or {}).get("version") or (component or {}).get("component_version") or "")
        prompt = (
            f"目标依赖：{name} {version}，漏洞族：{family or 'deserialization'}。\n"
            f"请给出可直接投放到 HTTP 参数位的攻击载荷，命令为：{command or '(由平台指定)'}。\n"
            "要求：只输出 payload 本身（Java 反序列化 gadget 请输出 base64 编码的序列化字节流，"
            "文本型注入请输出 JSON 字符串），不要解释、不要 markdown 代码块。"
        )
        try:
            # 2026-09-19 修：ModelGateway.complete 是 keyword-only 签名
            # （def complete(self, *, purpose, prompt, context=None, prompt_version="")），
            # 原实现写成 complete(prompt) → 恒抛 TypeError → 被下面 except 吞掉，
            # 于是「LLM 兜底造弹」这条腿一直是死的（即便注入了 gateway 也永远返回 []）。
            resp = self.gateway.complete(
                purpose="payload-forge",
                prompt=prompt,
                context={"component": name, "version": version, "family": family or ""},
            )
            text = getattr(resp, "text", None)
            if text is None:  # 防御：兼容非 ModelResponse 的返回形态
                text = str(resp)
        except Exception as exc:
            logger.warning("[payload_forge] LLM 兜底生成失败：%s", exc)
            return []
        candidates = [ln.strip() for ln in str(text or "").splitlines() if ln.strip()]
        kind = "text" if family in ("sqli", "ssti", "command-injection", "command_execution") else "ysoserial"
        passed = [c for c in candidates if self.selfcheck(c, kind)]
        if candidates and not passed:
            logger.warning(
                "[payload_forge] LLM 为 %s 生成了 %d 个候选，但无一通过自检（%s 类），已全部丢弃。",
                name, len(candidates), kind,
            )
        return passed

    # ---------------------------------------------------------------- 综合入口

    def forge_from_sca(self, components: List[Dict[str, Any]], family: str = "",
                       code_root: Optional[str] = None, command: str = "",
                       runner: Optional[Callable[..., Optional[bytes]]] = None) -> Dict[str, Any]:
        """SCA 驱动选弹总入口：可达性门控 → 弹药库选链 → 造弹 → 自检 → LLM 兜底。

        返回 dict：
            payloads            可投放的 payload 列表（空表示无弹可投，D1 应降级）
            selected_chain      实际选中的链（dict）
            reachability        可达性判定结果（dict）
            reason              为什么选/为什么不选（写清楚，便于 I2 与人工复盘）
            source              library / llm / none
            degraded            是否无可投弹（True 时 D1 必须标 attack_degraded）
        """
        components = components or []
        fam = str(family or "").strip().lower()
        result: Dict[str, Any] = {
            "payloads": [], "selected_chain": None, "reachability": None,
            "reason": "", "source": "none", "degraded": True,
        }
        if not components:
            result["reason"] = "无 SCA 组件输入，无法做 SCA 驱动选弹"
            return result

        judge = self._judge_reachability
        if judge is None:
            from src.iast.reachability import judge_reachability as judge  # 延迟导入，避免循环依赖

        # 逐个组件试：第一个「可达 + 有链 + 造弹成功 + 自检通过」的胜出。
        for comp in components:
            reach = judge(comp, fam, code_root)
            if not reach.get("reachable"):
                result["reachability"] = result["reachability"] or reach
                logger.info(
                    "[payload_forge] SCA 组件 %s 未通过可达性判定，跳过：%s",
                    comp.get("name") or comp.get("component_name"), reach.get("reason", ""),
                )
                continue

            for chain in self.select_chains(comp, fam):
                payload = self.forge(chain, command=command, runner=runner)
                if not payload:
                    continue
                if not self.selfcheck(payload, str(chain.get("kind") or "ysoserial")):
                    logger.warning("[payload_forge] 链 %s 造出的 payload 未通过自检，丢弃", chain.get("id"))
                    continue
                result.update({
                    "payloads": [payload],
                    "selected_chain": chain,
                    "reachability": reach,
                    "reason": (
                        f"SCA 驱动选弹：{comp.get('name') or comp.get('component_name')} "
                        f"{comp.get('version') or comp.get('component_version') or ''} "
                        f"命中弹药库链 {chain.get('id')}（{chain.get('payload_name') or 'text'}），"
                        f"可达性已确认且 payload 通过自检"
                    ),
                    "source": "library",
                    "degraded": False,
                })
                return result

        # 弹药库没覆盖 → LLM 兜底（同样要先过可达性，且产物必须过自检）
        for comp in components:
            reach = judge(comp, fam, code_root)
            if not reach.get("reachable"):
                continue
            candidates = self.llm_forge(comp, fam, command=command)
            if candidates:
                result.update({
                    "payloads": candidates,
                    "selected_chain": None,
                    "reachability": reach,
                    "reason": (
                        f"弹药库未覆盖 {comp.get('name')}，改由 LLM 兜底生成并通过自检"
                        f"（{len(candidates)} 个候选）"
                    ),
                    "source": "llm",
                    "degraded": False,
                })
                return result

        result["reason"] = (
            "SCA 组件均未通过可达性判定，或弹药库/LLM 兜底均未产出可用 payload；"
            "D1 应降级为 canary 探针并标 attack_degraded"
        )
        return result


# --------------------------------------------------------------------------- ysoserial 进程调用


# ysoserial 靠反射改写 JDK 内部类字段来构造 gadget（如 HashSet.map /
# AnnotationInvocationHandler.memberValues）。Java 9+ 的 JPMS 会阻断这些反射，
# Java 24 上 CC6 等链必挂（InaccessibleObjectException）。Java 8 不认识 --add-opens，
# 故只在 9+ 加。因此 ysoserial 必须用 JDK8 生成——见 _resolve_java_bin（§Q5）。
_ADD_OPENS_MODULES = ("java.lang", "java.util", "java.io", "java.lang.reflect", "java.net")
_RESOLVED_JAVA_BIN: Optional[str] = None


def _java_major_version(java_bin: str = "java") -> int:
    """探测给定 java 二进制的主版本号；探测失败返回 0（按 Java 8 处理，不加 --add-opens）。"""
    major = 0
    try:
        out = subprocess.run([java_bin, "-version"], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=30, check=False)
        text = ((out.stderr or b"") + (out.stdout or b"")).decode("utf-8", errors="ignore")
        m = re.search(r'version\s+"(\d+)', text)
        if m:
            major = int(m.group(1))
    except Exception as exc:
        logger.debug("[ysoserial] java 版本探测失败，按 Java 8 处理：%s", exc)
    return major


def _resolve_java_bin() -> str:
    """为 ysoserial 解析一个可用的 java 二进制（§Q5：ysoserial 必须在 JDK8 下生成）。

    优先级：
    1. 显式环境变量 ``YSO_JAVA_HOME`` / ``JAVA8_HOME`` → 该 JDK 的 bin/java（用户显式指定即信任为 JDK8）；
    2. ``JAVA_HOME`` 若指向 JDK8（主版本 < 9）→ 用之；
    3. 否则回退 PATH 上的裸 ``java``（保留旧行为，但会打印警告：在 JDK9+ 上大概率失败）。

    关键修正：此前一律用 PATH 裸 ``java``，无视 JAVA_HOME；即使把系统 JAVA_HOME 改成 JDK8，
    只要后端进程 PATH 上仍是 JDK9+，ysoserial 就会生成失败并降级为 canary。
    现在优先读显式 env / JAVA_HOME，确保 JDK8 真正被用上。
    """
    global _RESOLVED_JAVA_BIN
    if _RESOLVED_JAVA_BIN is not None:
        return _RESOLVED_JAVA_BIN

    explicit: List[Path] = []
    for env in ("YSO_JAVA_HOME", "JAVA8_HOME"):
        home = (os.environ.get(env) or "").strip()
        if home:
            explicit.append(Path(home) / "bin" / "java")

    # 1) 显式 env 直接信任为 JDK8
    for cand in explicit:
        for probe in (cand.with_suffix(".exe"), cand):
            try:
                if probe.exists():
                    _RESOLVED_JAVA_BIN = str(probe)
                    logger.info("[ysoserial] 使用 java %s（来自显式 env YSO_JAVA_HOME/JAVA8_HOME）", _RESOLVED_JAVA_BIN)
                    return _RESOLVED_JAVA_BIN
            except OSError:
                continue

    # 2) JAVA_HOME 指向 JDK8 才用
    java_home = (os.environ.get("JAVA_HOME") or "").strip()
    if java_home:
        cand = Path(java_home) / "bin" / "java"
        for probe in (cand.with_suffix(".exe"), cand):
            try:
                if probe.exists() and _java_major_version(str(probe)) < 9:
                    _RESOLVED_JAVA_BIN = str(probe)
                    logger.info("[ysoserial] 使用 java %s（JAVA_HOME 指向 JDK8）", _RESOLVED_JAVA_BIN)
                    return _RESOLVED_JAVA_BIN
            except OSError:
                continue

    # 2.5) 本机已装的 JDK8（2026-11-02 补）：JAVA_HOME 常指向 JDK21（CodeQL 需要），
    # 但机器上往往同时装着 JDK8。不扫一遍就会误报「未找到 JDK8」并回退裸 java——
    # 实测那条警告是假的（PATH 上的 java 恰好就是 1.8.0_65），但换台机器就真会失败。
    # 复用 A1 的 JDK 扫描（它已经会认 jdk65 / 1.8 这类目录名）。
    try:
        from src.agents.a1_codeql_adapter import _scan_jdks
        for _major, _home in _scan_jdks():
            if int(_major) != 8:
                continue
            _cand = Path(str(_home)) / "bin" / "java"
            for _probe in (_cand.with_suffix(".exe"), _cand):
                try:
                    if _probe.exists():
                        _RESOLVED_JAVA_BIN = str(_probe)
                        logger.info("[ysoserial] 使用 java %s（本机扫描到的 JDK8）", _RESOLVED_JAVA_BIN)
                        return _RESOLVED_JAVA_BIN
                except OSError:
                    continue
    except Exception:  # noqa: BLE001
        pass

    # 3) 回退裸 java（大概率在 JDK9+ 上失败并降级）
    _RESOLVED_JAVA_BIN = "java"
    logger.warning("[ysoserial] 未找到 JDK8（YSO_JAVA_HOME/JAVA8_HOME/JAVA_HOME/本机扫描均无），"
                   "回退 PATH 裸 java；ysoserial 在 JDK9+ 上大概率生成失败并降级为 canary。")
    return _RESOLVED_JAVA_BIN


def _run_ysoserial(jar_path: str, payload_name: str, command: str, timeout: int = 120) -> Optional[bytes]:
    """调用 `java -jar ysoserial-all.jar <链名> '<命令>'`，返回原始序列化字节。

    Windows 注意：jar_path 必须是原生 Windows 路径（D:\\... 或 D:/...）。
    传 Git-Bash 风格的 /d/... 会被 JVM 翻成 \\d\\... 导致找不到 jar——
    这里一律用 Path 解析出的原生路径，不手工拼字符串。

    java 二进制由 _resolve_java_bin 解析：优先 JDK8（YSO_JAVA_HOME / JAVA_HOME 指向 JDK8），
    否则回退 PATH 裸 java。Java 9+ 需加 --add-opens，否则 ysoserial 的反射会被 JPMS 挡下。
    """
    java_bin = _resolve_java_bin()
    cmd = [java_bin]
    if _java_major_version(java_bin) >= 9:
        cmd.extend(f"--add-opens=java.base/{m}=ALL-UNNAMED" for m in _ADD_OPENS_MODULES)
    cmd.extend(["-jar", str(Path(jar_path)), payload_name, command])

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", errors="ignore")[:300]
        logger.warning("[ysoserial] 链 %s 生成失败 rc=%d：%s", payload_name, proc.returncode, err)
        return None
    return proc.stdout
