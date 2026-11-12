"""
Attack semantics and attack-plan assembly helpers for D2.
"""
import json
from typing import Any, Dict, List, Optional
from pathlib import Path
from urllib.parse import urlparse

from src.core.exploit_spec import (
    empty_exploit_spec,
    exploit_spec_completeness,
    has_meaningful_exploit_spec,
    merge_exploit_specs,
    normalize_exploit_spec,
)
from .d2_types import VerificationResult


class D2SemanticsMixin:
    @staticmethod
    def _supporting_node_signal(vulnerability: Optional[Dict[str, Any]]) -> str:
        if not vulnerability:
            return ""
        parts: List[str] = []
        for node in list(vulnerability.get("supporting_nodes") or [])[:8]:
            parts.extend(
                str(node.get(key, "") or "")
                for key in ("file", "type", "description", "entry_point", "sink", "callers")
            )
        return " ".join(part for part in parts if part)

    @classmethod
    def _build_semantic_context_from_strategy(cls, strategy: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "business_goal": str(strategy.get("business_goal", "") or ""),
            "input_role": str(strategy.get("input_role", "") or ""),
            "delivery_shape": str(strategy.get("delivery_shape", "") or ""),
            "trigger_condition": str(strategy.get("trigger_condition", "") or ""),
            "verification_signal_hint": str(strategy.get("verification_signal_hint", "") or ""),
            "business_context": str(strategy.get("business_context", "") or ""),
            "steps": cls._coerce_string_list(strategy.get("attack_steps_json")),
            "constraints": cls._coerce_string_list(strategy.get("constraints_json")),
        }

    @staticmethod
    def _build_generic_strategy_semantics(strategy: Dict[str, Any]) -> Dict[str, str]:
        exploit_family = str(strategy.get("exploit_family", "") or "").lower()
        target_path = str(strategy.get("target_path") or strategy.get("render_path") or strategy.get("import_path") or "/")
        parameter = str(strategy.get("parameter") or strategy.get("query_key") or strategy.get("field_name") or "input")
        method = str(strategy.get("method", "GET") or "GET").upper()
        transport = str(strategy.get("transport", "") or "").lower()

        if transport == "json":
            delivery_shape = "JSON 请求体"
        elif transport == "body":
            delivery_shape = f"{method} 请求体"
        elif transport == "param":
            delivery_shape = f"{method} 请求参数"
        elif strategy.get("field_name"):
            delivery_shape = "multipart/form-data 上传字段"
        else:
            delivery_shape = f"{method} 请求参数"

        if "sql" in exploit_family or "xpath" in exploit_family or "ldap" in exploit_family or "nosql" in exploit_family or "mongo" in exploit_family or "redis" in exploit_family or "hpp" in exploit_family:
            business_goal = "操控查询相关输入，验证业务层查询条件是否会被外部输入改写。"
            verification_signal_hint = "成功信号通常是基线响应与注入响应出现可解释差异，而不只是接口报错。"
        elif "xss" in exploit_family or "template" in exploit_family or "ssti" in exploit_family or "spel" in exploit_family or "ognl" in exploit_family:
            business_goal = "把攻击输入送入页面或模板渲染流程，验证服务端是否把不可信数据当成可执行模板或未转义输出。"
            verification_signal_hint = "成功信号通常是响应中出现未转义攻击片段或模板表达式执行结果。"
        elif "command" in exploit_family or "jndi" in exploit_family or "fastjson" in exploit_family or "jackson" in exploit_family or "xstream" in exploit_family:
            business_goal = "把外部输入送入高风险执行链，验证请求数据是否能触发命令执行或危险对象解析。"
            verification_signal_hint = "成功信号应落在执行副作用、回显差异或危险对象解析结果上。"
        elif "path" in exploit_family or "file_upload" in exploit_family or "file_delete" in exploit_family or "tomcat" in exploit_family or "xxe" in exploit_family:
            business_goal = "利用文件或资源处理流程，验证业务是否允许不可信输入突破预期访问边界。"
            verification_signal_hint = "成功信号是文件系统、副作用资源或回显内容出现可验证变化。"
        elif "jwt" in exploit_family or "auth" in exploit_family or "csrf" in exploit_family or "cookie" in exploit_family or "cors" in exploit_family:
            business_goal = "验证认证、会话或跨域控制是否会被可控输入绕过或削弱。"
            verification_signal_hint = "成功信号通常是权限边界被绕过、状态变更成功或安全头配置异常。"
        else:
            business_goal = "根据项目内的实际请求入口和参数角色，构造最短攻击链并验证关键业务效果。"
            verification_signal_hint = "成功信号应优先采用业务侧可解释的状态变化或响应差异。"

        attack_steps = [
            f"定位业务入口 {target_path}，确认 {parameter} 是当前攻击链里的可控输入。",
            "把输入替换为与该漏洞族匹配的攻击值，同时保持请求形态尽量贴近真实业务。",
            "根据响应差异、状态变化或副作用判断攻击是否真正生效。",
        ]
        constraints = [
            "请求需要保持业务可接受的参数形态，不能只做脱离上下文的 payload 投递。",
            "验证结论要落在可解释的业务结果上，而不是仅凭异常或日志猜测。",
        ]

        return {
            "business_goal": business_goal,
            "input_role": parameter,
            "delivery_shape": delivery_shape,
            "trigger_condition": "单次请求即可触发，除非业务链另有显式二次触发步骤。",
            "verification_signal_hint": verification_signal_hint,
            "business_context": f"当前 deterministic verifier 识别到入口 {target_path}，并将 {parameter} 视为该业务动作的关键输入。",
            "attack_steps_json": json.dumps(attack_steps, ensure_ascii=False),
            "constraints_json": json.dumps(constraints, ensure_ascii=False),
        }

    @classmethod
    def _ensure_strategy_semantics(cls, strategy: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        strategy = dict(strategy or {})
        if strategy.get("business_goal") and strategy.get("input_role") and strategy.get("delivery_shape"):
            return strategy
        inferred = cls._infer_business_semantics(
            str(strategy.get("exploit_family", "") or ""),
            target_path=str(strategy.get("target_path") or strategy.get("render_path") or ""),
            parameter=str(strategy.get("parameter") or strategy.get("query_key") or strategy.get("field_name") or ""),
            method=str(strategy.get("method", "GET") or "GET"),
            source_file=str(strategy.get("source_file", "") or ""),
            line_context="",
            import_path=str(strategy.get("import_path", "") or ""),
            trigger_path=str(strategy.get("trigger_path", "") or strategy.get("verify_path", "") or ""),
        )
        if not inferred:
            inferred = cls._build_generic_strategy_semantics(strategy)
        for key, value in inferred.items():
            if value and not strategy.get(key):
                strategy[key] = value
        return strategy

    @staticmethod
    def _read_strategy_source_excerpt(project_path: Path, strategy: Dict[str, Any], radius: int = 4) -> str:
        source_file = str(strategy.get("source_file", "") or "").strip()
        if not source_file or not project_path:
            return ""
        try:
            source_path = (project_path / source_file.replace("\\", "/")).resolve()
            if not source_path.exists():
                return ""
            lines = source_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            line_no = int(strategy.get("source_line", 0) or 0)
            if line_no <= 0:
                return "\n".join(lines[: min(len(lines), radius * 2 + 1)])
            start = max(0, line_no - radius - 1)
            end = min(len(lines), line_no + radius)
            return "\n".join(lines[start:end])
        except Exception:
            return ""

    def _derive_project_specific_semantics(self, project_path: Path, strategy: Dict[str, Any], vulnerability: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        exploit_family = str(strategy.get("exploit_family", "") or "")
        target_path = str(strategy.get("target_path") or strategy.get("render_path") or strategy.get("import_path") or "")
        parameter = str(strategy.get("parameter") or strategy.get("query_key") or strategy.get("field_name") or "")
        method = str(strategy.get("method", "GET") or "GET").upper()
        excerpt = self._read_strategy_source_excerpt(project_path, strategy)
        supporting_signal = self._supporting_node_signal(vulnerability)
        vuln_signal = " ".join(
            [
                str(vulnerability.get("type", "") if vulnerability else ""),
                str(vulnerability.get("sink", "") if vulnerability else ""),
                str(vulnerability.get("entry_point", "") if vulnerability else ""),
                target_path,
                parameter,
                excerpt,
                supporting_signal,
            ]
        ).lower()

        if not vuln_signal.strip():
            return {}

        if "csrf" in exploit_family:
            if any(token in vuln_signal for token in ("login", "signin", "auth", "session")):
                return {
                    "business_goal": "伪造跨站请求触发登录态相关状态变更，验证该接口是否缺少来源约束和令牌校验。",
                    "input_role": "登录态下的状态变更参数",
                    "delivery_shape": f"{method} 表单参数",
                    "trigger_condition": "受害者在已登录状态下单次跨站请求即可触发。",
                    "verification_signal_hint": "成功信号是状态变更被接受，而不是仅返回 200。",
                    "business_context": f"入口 {target_path or '/'} 的代码上下文带有认证或会话语义，这不是泛化的 CSRF 教科书场景。",
                    "attack_steps_json": json.dumps([
                        f"在受害者已有登录态的前提下，请求 {target_path or '/'}。",
                        "保持请求体与正常业务表单一致，仅从外部站点代发。",
                        "观察状态是否真的被修改或业务动作是否被执行。",
                    ], ensure_ascii=False),
                }
            return {
                "business_goal": "伪造跨站请求触发实际业务状态变更，验证该接口是否接受未携带来源防护的外部提交。",
                "input_role": "状态变更表单参数",
                "delivery_shape": f"{method} 表单参数",
                "trigger_condition": "受害者携带有效会话时单次跨站请求即可触发。",
                "verification_signal_hint": "成功信号是业务状态真的变化，而不是仅看到接口可访问。",
                "business_context": f"入口 {target_path or '/'} 是项目里真实的状态修改接口，语义来自源码中的 HTTP 映射而不是通用 fallback。",
            }

        if "java_auth_bypass" in exploit_family or "jwt" in exploit_family or "cookie" in exploit_family:
            if any(token in vuln_signal for token in ("admin", "debug", "manage", "role", "permitall")):
                return {
                    "business_goal": "绕过管理或调试接口的访问控制，验证项目是否把高权限入口暴露给了未授权请求。",
                    "input_role": "认证态 / 角色判定输入",
                    "delivery_shape": "HTTP 头、Cookie 或认证相关请求参数",
                    "trigger_condition": "单次请求即可验证权限边界是否失效。",
                    "verification_signal_hint": "成功信号是原本应受限的管理能力被未授权访问，而不是仅返回普通页面。",
                    "business_context": f"源码片段和路径 {target_path or '/'} 命中了 admin/debug/manage 等权限语义。",
                }

        if any(token in exploit_family for token in ("sqli", "xpath", "ldap", "nosql", "mongo", "redis", "hpp")):
            if any(token in vuln_signal for token in ("login", "user", "account", "auth", "quote", "search", "filter", "id", "name")):
                return {
                    "business_goal": "操控真实业务查询条件，验证项目在登录、搜索或详情读取流程中是否会把用户输入拼进查询表达式。",
                    "input_role": f"查询条件参数 {parameter or 'input'}",
                    "delivery_shape": f"{method} 请求中的查询输入",
                    "trigger_condition": "单次查询请求即可观察基线与注入响应差异。",
                    "verification_signal_hint": "成功信号是结果集合、返回内容或鉴权结果发生可解释变化。",
                    "business_context": f"入口 {target_path or '/'} 和源码片段命中了搜索/登录/详情读取语义，当前语义来自项目代码结构。",
                }

        if any(token in exploit_family for token in ("xss", "template", "spel", "ognl", "ssti")):
            if any(token in vuln_signal for token in ("view", "render", "preview", "message", "content", "template", "name", "q")):
                return {
                    "business_goal": "把攻击输入送入当前项目的渲染或回显链，验证页面输出是否把不可信数据当成模板或未转义内容处理。",
                    "input_role": f"页面渲染输入 {parameter or 'input'}",
                    "delivery_shape": f"{method} 请求中的渲染参数",
                    "trigger_condition": "单次渲染请求即可触发。",
                    "verification_signal_hint": "成功信号是响应中出现未转义片段、模板执行结果或恶意标签被原样输出。",
                    "business_context": f"路径 {target_path or '/'} 和源码片段显示该输入直接影响当前页面渲染流程。",
                }

        if any(token in exploit_family for token in ("path", "upload", "delete", "tomcat", "xxe")):
            if any(token in vuln_signal for token in ("file", "upload", "import", "download", "read", "export", "avatar", "xml")):
                return {
                    "business_goal": "利用当前项目的文件或资源处理流程，验证不可信输入是否能突破正常访问边界。",
                    "input_role": f"文件/资源定位输入 {parameter or strategy.get('field_name') or 'input'}",
                    "delivery_shape": strategy.get("field_name") and "multipart/form-data 上传字段" or f"{method} 请求中的资源参数",
                    "trigger_condition": "单次请求即可触发文件或资源处理逻辑。",
                    "verification_signal_hint": "成功信号是文件系统、副作用资源或返回内容出现可验证变化。",
                    "business_context": f"源码片段表明 {target_path or '/'} 正在处理文件、上传、下载或 XML 资源。",
                }

        return {}

    @staticmethod
    def _infer_business_semantics(
        exploit_family: str,
        *,
        target_path: str = "",
        parameter: str = "",
        method: str = "GET",
        source_file: str = "",
        line_context: str = "",
        import_path: str = "",
        trigger_path: str = "",
    ) -> Dict[str, str]:
        signal = " ".join(
            item for item in [target_path, parameter, source_file, line_context, import_path, trigger_path] if item
        ).lower()
        attack_steps: List[str] = []
        constraints: List[str] = []

        if "ssrf" in exploit_family:
            if any(token in signal for token in ("webhook", "callback", "notify", "hook")):
                business_goal = "伪造回调或 webhook 目标，让服务端替攻击者向指定地址发起请求。"
                input_role = "Webhook / 回调地址"
                business_context = f"入口 {target_path or '/'} 更像通知或回调场景，参数 {parameter or 'url'} 被当作服务端回连目标。"
            elif any(token in signal for token in ("avatar", "image", "img", "photo", "pic", "thumbnail", "logo")):
                business_goal = "把外部图片地址伪装成业务资源，让服务端在拉取头像或图片时访问攻击者指定地址。"
                input_role = "图片 / 头像资源地址"
                business_context = f"路由 {target_path or '/'} 和参数 {parameter or 'url'} 命中了图片抓取语义。"
            elif any(token in signal for token in ("preview", "report", "render", "pdf", "crawl", "fetch", "proxy")):
                business_goal = "借助预览、抓取或报表生成流程，让服务端在内容拉取阶段访问攻击者控制的地址。"
                input_role = "预览源地址 / 报表抓取地址"
                business_context = f"目标路径 {target_path or '/'} 更像服务端代取内容的业务动作。"
            else:
                business_goal = "控制服务端发起的出站请求目标，确认该业务真的按外部输入去访问远程资源。"
                input_role = "服务端请求目标地址"
                business_context = f"参数 {parameter or 'url'} 直接进入网络请求调用，更像项目内部的资源拉取入口。"
            delivery_shape = f"{method} 请求中的 URL 参数"
            trigger_condition = "单次请求即可触发服务端出站访问。"
            verification_signal_hint = "成功信号不是前端回显，而是服务端实际请求了目标地址，或响应内容出现被拉取资源特征。"
            attack_steps = [
                f"定位业务入口 {target_path or '/'}，确认参数 {parameter or 'url'} 控制服务端请求目标。",
                "把目标替换为可观测地址，验证请求是否由服务端发出。",
                "结合回显、状态码差异或探针确认是服务端访问，而不是客户端跳转。",
            ]
            constraints = [
                "需要保留业务期望的 URL 形态，不能只给随机字符串。",
                "验证时要证明请求来自服务端，而不是浏览器或日志伪迹。",
            ]
        elif "open_redirect" in exploit_family:
            if any(token in signal for token in ("login", "signin", "auth", "oauth", "sso", "callback", "returnto")):
                business_goal = "劫持登录后回跳目标，把认证完成后的用户重定向到攻击者指定地址。"
                input_role = "登录后回跳地址"
                business_context = f"路径 {target_path or '/'} 命中了认证或回跳语义，应该按登录完成后的 next/returnUrl 处理。"
            elif any(token in signal for token in ("pay", "payment", "checkout", "order", "billing", "success")):
                business_goal = "篡改支付完成后的返回页或订单跳转目标，让业务把用户带到攻击者控制的站点。"
                input_role = "支付完成返回地址"
                business_context = f"路径 {target_path or '/'} 带有支付或订单语义，属于交易完成后的业务回跳。"
            else:
                business_goal = "控制业务流程中的跳转目标，确认服务端会把外部地址原样写入 Location。"
                input_role = "业务跳转目标地址"
                business_context = f"参数 {parameter or 'next'} 被直接用于重定向，当前更像项目自己的 next/redirect 业务参数。"
            delivery_shape = f"{method} 请求中的跳转目标参数"
            trigger_condition = "单次请求即可触发 30x 跳转。"
            verification_signal_hint = "成功信号是响应头 Location 指向攻击者地址，而不是仅返回 200。"
            attack_steps = [
                f"请求业务入口 {target_path or '/'}，把 {parameter or 'next'} 替换成外部地址。",
                "观察响应是否返回 301/302/303/307/308。",
                "确认 Location 头是否保留攻击者地址而未被归一化到站内。",
            ]
            constraints = [
                "必须检查 Location 头，不能只看页面文本。",
                "payload 要符合该业务允许的回跳地址格式，否则会被正常校验挡住。",
            ]
        elif "deserialization" in exploit_family or "map" in exploit_family:
            if any(token in signal for token in ("import", "restore", "backup", "upload", "recover")):
                business_goal = "把恶意对象伪装成导入或恢复数据包，让业务先接收对象，再在后续流程中触发对象链。"
                input_role = "导入包 / 恢复包对象数据"
                business_context = f"入口 {import_path or target_path or '/'} 命中了导入或恢复语义，攻击链不是单次 payload。"
            elif any(token in signal for token in ("cache", "config", "processor")):
                business_goal = "把恶意对象伪装成缓存或配置对象，等待后续处理逻辑读取或写入时触发危险行为。"
                input_role = "缓存 / 配置对象数据"
                business_context = "代码上下文命中了 cache/config/processor 语义，说明项目里存在延迟触发的对象处理流程。"
            elif any(token in signal for token in ("session", "auth", "remember")):
                business_goal = "把恶意对象伪装成会话恢复数据，在状态恢复或鉴权续期时触发对象链。"
                input_role = "会话恢复对象数据"
                business_context = f"参数 {parameter or 'data'} 更像会话或鉴权状态载体。"
            elif any(token in signal for token in ("debug", "admin", "manage", "tool")):
                business_goal = "借助调试或管理接口导入对象，利用低防护运维路径把恶意对象送入系统。"
                input_role = "调试 / 管理接口导入对象"
                business_context = f"目标路径 {import_path or target_path or '/'} 命中了 debug/admin 语义，属于运维导入链。"
            else:
                business_goal = "让服务端把外部输入还原成对象，并在后续对象操作中触发危险行为。"
                input_role = "可被还原成对象的外部输入"
                business_context = f"参数 {parameter or 'data'} 被用于对象恢复，更像业务对象导入而不是单纯算法层漏洞。"
            delivery_shape = "表单或请求体中的序列化对象数据"
            trigger_condition = (
                f"先向 {import_path} 导入对象，再通过访问 {trigger_path} 触发后续对象处理。"
                if import_path and trigger_path
                else "先让系统接收对象，再观察后续对象处理是否触发危险行为。"
            )
            verification_signal_hint = "成功信号应落在对象导入后的副作用上，例如二次访问触发、容器内标记文件落地或业务状态变化。"
            attack_steps = [
                f"构造满足业务对象约束的输入，并投递到 {import_path or target_path or '/'}。",
                "不要只盯住导入接口返回值，要继续执行后续业务触发动作。",
                f"结合 {trigger_path or '后续处理入口'} 的执行结果确认对象链是否真正生效。",
            ]
            constraints = [
                "输入必须满足服务端期望的对象类型或编码格式。",
                "如果是延迟触发链，验证必须覆盖导入后的二次业务动作。",
            ]
        else:
            return {}

        return {
            "business_goal": business_goal,
            "input_role": input_role,
            "delivery_shape": delivery_shape,
            "trigger_condition": trigger_condition,
            "verification_signal_hint": verification_signal_hint,
            "business_context": business_context,
            "attack_steps_json": json.dumps(attack_steps, ensure_ascii=False),
            "constraints_json": json.dumps(constraints, ensure_ascii=False),
        }

    @staticmethod
    def _guess_business_goal(vulnerability: Dict, poc_type: str, strategy: Dict[str, Any], exploit_result: Dict[str, Any]) -> str:
        signal = " ".join([
            str(vulnerability.get("type", "")),
            str(vulnerability.get("entry_point", "")),
            str(vulnerability.get("sink", "")),
            str(vulnerability.get("callers", "")),
            str(strategy.get("target_path", "")),
            str(strategy.get("import_path", "")),
            str(strategy.get("trigger_path", "")),
        ]).lower()
        if "ssrf" in poc_type:
            return "让服务端按用户输入的目标地址主动发起请求，并通过回显或行为差异确认请求真实发生。"
        if "redirect" in poc_type:
            return "控制跳转目标，使业务流程把用户或浏览器重定向到攻击者指定的位置。"
        if "map-payload" in poc_type or "deserialize" in poc_type or "反序列化" in signal:
            if any(token in signal for token in ("import", "restore", "backup", "debug")):
                return "把恶意对象伪装成导入/恢复数据包，先让系统接收对象，再通过后续业务动作触发对象链。"
            if any(token in signal for token in ("cache", "processor")):
                return "把恶意对象伪装成缓存或配置对象，等待业务后续读取/写入时触发对象链。"
            return "让服务端把外部输入还原成对象，并通过后续对象操作触发危险行为。"
        if "csrf" in poc_type:
            return "构造跨站状态变更请求，确认业务在无防护情况下仍接受外部站点代发请求。"
        return "根据当前漏洞点和调用链，构造最短可复现的攻击请求并验证关键业务效果。"

    @staticmethod
    def _guess_input_role(vulnerability: Dict, poc_type: str, strategy: Dict[str, Any], exploit_result: Dict[str, Any]) -> str:
        parameter = strategy.get("parameter") or exploit_result.get("parameter") or ""
        signal = " ".join([
            parameter,
            str(vulnerability.get("type", "")),
            str(vulnerability.get("entry_point", "")),
            str(vulnerability.get("sink", "")),
        ]).lower()
        if "ssrf" in poc_type:
            return "外部资源地址 / 服务端抓取目标"
        if "redirect" in poc_type:
            return "跳转目标地址 / 回跳地址"
        if "map-payload" in poc_type or "deserialize" in poc_type or "反序列化" in signal:
            if any(token in signal for token in ("import", "restore", "backup")):
                return "导入包 / 恢复包对象数据"
            if any(token in signal for token in ("cache", "config")):
                return "缓存/配置对象序列化数据"
            return "可被服务端反序列化的对象数据"
        if "csrf" in poc_type:
            return "跨站触发的状态变更参数"
        return parameter or "业务输入参数"

    @staticmethod
    def _guess_delivery_shape(poc_type: str, strategy: Dict[str, Any], exploit_result: Dict[str, Any], raw_payload: Dict[str, Any]) -> str:
        attack_request = exploit_result.get("attack_request", {}) if isinstance(exploit_result, dict) else {}
        body = attack_request.get("body", "")
        headers = attack_request.get("headers", {}) if isinstance(attack_request.get("headers", {}), dict) else {}
        method = attack_request.get("method", strategy.get("method", "GET"))
        if "map-payload" in poc_type:
            return "Base64 编码对象，通过 form body 导入"
        if "redirect" in poc_type:
            return f"{method} 请求参数中的 URL/路径值"
        if "ssrf" in poc_type:
            return f"{method} 请求中可控 URL 参数"
        if headers.get("Content-Type", "").startswith("application/json"):
            return "JSON 请求体"
        if isinstance(body, str) and "=" in body:
            return "application/x-www-form-urlencoded"
        return "HTTP 参数"

    @staticmethod
    def _build_attack_steps(vulnerability: Dict, poc_type: str, strategy: Dict[str, Any], exploit_result: Dict[str, Any], raw_payload: Dict[str, Any]) -> List[str]:
        entry_path = strategy.get("target_path") or strategy.get("import_path") or exploit_result.get("attack_request", {}).get("url", "")
        parameter = strategy.get("parameter") or exploit_result.get("parameter") or strategy.get("query_key") or ""
        payload_value = (
            exploit_result.get("payload")
            or strategy.get("payload")
            or strategy.get("payload_value")
            or exploit_result.get("payload_value")
            or "<payload>"
        )
        steps = []
        if "map-payload" in poc_type:
            steps.append(f"准备满足服务端类型约束的序列化对象数据，并编码为 Base64。")
            steps.append(f"向 {strategy.get('import_path', entry_path) or entry_path} 提交导入请求，让系统先接收对象。")
            if strategy.get("trigger_path"):
                steps.append(f"随后访问 {strategy.get('trigger_path')} 触发后续对象操作，而不是只看导入接口本身。")
            steps.append("检查无害标记文件或对象链副作用，确认真正完成了延迟触发。")
            return steps
        if entry_path:
            steps.append(f"访问业务入口 {entry_path}。")
        if parameter:
            steps.append(f"将参数 {parameter} 替换为攻击值 {payload_value}。")
        else:
            steps.append(f"将请求中的关键业务输入替换为攻击值 {payload_value}。")
        if "redirect" in poc_type:
            steps.append("观察响应头中的 Location 是否被业务原样带到外部目标。")
        elif "ssrf" in poc_type:
            steps.append("观察服务端是否真的去请求了该地址，而不是只在前端回显。")
        else:
            steps.append("观察响应差异、业务状态变化或二次触发行为。")
        return steps

    def _build_attack_plan(
        self,
        vulnerability: Dict,
        result: VerificationResult,
        project_context: Dict,
        *,
        strategy: Optional[Dict[str, Any]] = None,
        understanding: Optional[Dict[str, Any]] = None,
        plan: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        exploit_spec = normalize_exploit_spec(
            getattr(result, "exploit_spec", None) or vulnerability.get("exploit_spec") or empty_exploit_spec()
        )
        strategy = strategy or {}
        raw_payload = self._parse_raw_output_payload(result.raw_output)
        exploit_result = raw_payload.get("exploit_result", {}) if isinstance(raw_payload, dict) else {}
        attack_request = exploit_result.get("attack_request", {}) if isinstance(exploit_result, dict) else {}
        semantic_context = raw_payload.get("semantic_context", {}) if isinstance(raw_payload.get("semantic_context", {}), dict) else {}
        entry_path = exploit_spec["entry"].get("route") or strategy.get("target_path") or strategy.get("import_path") or ""
        if not entry_path:
            request_url = attack_request.get("url", "")
            if request_url:
                try:
                    entry_path = urlparse(request_url).path
                except Exception:
                    entry_path = request_url
        method = attack_request.get("method") or exploit_spec["entry"].get("method") or strategy.get("method") or "GET"
        parameter = exploit_spec["entry"].get("parameter_name") or strategy.get("parameter") or exploit_result.get("parameter") or strategy.get("query_key") or ""
        if not parameter and "map-payload" in result.poc_type:
            parameter = "data"
        import_path = strategy.get("import_path") or raw_payload.get("import_path", "")
        trigger_path = exploit_spec["entry"].get("trigger_route") or strategy.get("trigger_path") or raw_payload.get("trigger_path", "")
        explicit_constraints = self._coerce_string_list(semantic_context.get("constraints")) or self._coerce_string_list(raw_payload.get("constraints")) or self._coerce_string_list(strategy.get("constraints_json"))
        explicit_steps = (
            self._coerce_string_list(semantic_context.get("steps"))
            or self._coerce_string_list(raw_payload.get("semantic_steps"))
            or self._coerce_string_list(strategy.get("attack_steps_json"))
            or list(exploit_spec["prerequisites"].get("ordered_steps", []))
        )
        # RAG+LLM 升级：当传入 LLM 生成的 plan 时，优先采用其字段作为强先验，
        # 仅在该字段为空时回落确定性推导。entrypoint（路由/方法/参数/文件/行）始终保留确定性值，
        # 不信任 LLM 改写具体路由——避免 LLM 臆造不存在的路由污染命中统计。
        _llm_plan = plan or {}
        business_goal = (
            semantic_context.get("business_goal") or raw_payload.get("business_goal") or strategy.get("business_goal")
            or _llm_plan.get("business_goal") or self._guess_business_goal(vulnerability, result.poc_type, strategy, exploit_result)
        )
        input_role = (
            semantic_context.get("input_role") or raw_payload.get("input_role") or strategy.get("input_role")
            or exploit_spec["entry"].get("parameter_name") or _llm_plan.get("input_role")
            or self._guess_input_role(vulnerability, result.poc_type, strategy, exploit_result)
        )
        delivery_shape = (
            semantic_context.get("delivery_shape") or raw_payload.get("delivery_shape") or strategy.get("delivery_shape")
            or exploit_spec["entry"].get("content_type") or _llm_plan.get("delivery_shape")
            or self._guess_delivery_shape(result.poc_type, strategy, exploit_result, raw_payload)
        )
        trigger_condition = (
            semantic_context.get("trigger_condition") or raw_payload.get("trigger_condition") or strategy.get("trigger_condition")
            or _llm_plan.get("trigger_condition") or ""
        )
        verification_signal = (
            semantic_context.get("verification_signal_hint") or raw_payload.get("verification_signal_hint") or strategy.get("verification_signal_hint")
            or "; ".join(exploit_spec["success_signal"].get("expected_indicators", [])) or _llm_plan.get("verification_signal")
            or result.reason or ""
        )
        if result.evidence:
            verification_signal = "; ".join(str(item) for item in result.evidence[:3] if item)
        constraints = explicit_constraints[:]
        if import_path:
            constraints.append("必须先完成对象导入，再通过后续业务动作触发。")
        if trigger_path:
            constraints.append(f"触发阶段依赖二次访问 {trigger_path}。")
        if "map-payload" in result.poc_type:
            constraints.append("输入不能只是普通字符串，必须满足服务端对象类型约束。")
        elif "redirect" in result.poc_type:
            constraints.append("成功信号不只是 200，而是 Location 真正指向外部目标。")
        elif "ssrf" in result.poc_type:
            constraints.append("必须证明请求由服务端发出，而不是前端或日志回显。")
        elif not constraints:
            constraints.append("需要满足实际业务输入约束，而不是只让 payload 到达代码片段。")
        # RAG+LLM 升级：LLM 计划携带的约束作为补充先验并入（去重后）。
        _llm_constraints = _llm_plan.get("constraints")
        if isinstance(_llm_constraints, list):
            for _c in _llm_constraints:
                if isinstance(_c, str) and _c and _c not in constraints:
                    constraints.append(_c)

        dedup_constraints = []
        for item in constraints:
            if item and item not in dedup_constraints:
                dedup_constraints.append(item)
        if not trigger_condition:
            trigger_condition = (
                f"先调用 {import_path}，再调用 {trigger_path}"
                if import_path and trigger_path
                else ("单次请求即可触发" if entry_path else "依赖运行时进一步确认")
            )
        notes = [item for item in (result.evidence or [])[:5] if item]
        business_context = semantic_context.get("business_context") or raw_payload.get("business_context") or strategy.get("business_context")
        if business_context:
            notes = [business_context] + notes

        return {
            "plan_version": "a3.v2",
            "source": "llm" if plan else "deterministic",
            "business_goal": business_goal,
            "entrypoint": {
                "path": entry_path,
                "method": method,
                "parameter": parameter,
                "file": vulnerability.get("file", ""),
                "line": vulnerability.get("line", ""),
            },
            "input_role": input_role,
            "delivery_shape": delivery_shape,
            "trigger_condition": trigger_condition,
            "constraints": dedup_constraints,
            "verification_signal": verification_signal,
            "steps": explicit_steps or (_llm_plan.get("steps") if isinstance(_llm_plan.get("steps"), list) and _llm_plan.get("steps") else None) or self._build_attack_steps(vulnerability, result.poc_type, strategy, exploit_result, raw_payload),
            "notes": notes,
            "project_language": project_context.get("language", "") if project_context else "",
            "framework": project_context.get("framework", "") if project_context else "",
            "understanding": understanding or {},
            "llm_plan": plan or {},
            "exploit_spec": exploit_spec,
        }

    def _ensure_attack_plan(
        self,
        result: VerificationResult,
        vulnerability: Dict,
        project_context: Dict,
        *,
        strategy: Optional[Dict[str, Any]] = None,
        understanding: Optional[Dict[str, Any]] = None,
        plan: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        if not result.attack_plan:
            result.attack_plan = self._build_attack_plan(
                vulnerability,
                result,
                project_context or {},
                strategy=strategy,
                understanding=understanding,
                plan=plan,
            )
        merged_exploit_spec = normalize_exploit_spec(empty_exploit_spec())
        for candidate in (
            vulnerability.get("exploit_spec"),
            result.attack_plan.get("exploit_spec"),
            result.exploit_spec,
        ):
            if has_meaningful_exploit_spec(candidate):
                merged_exploit_spec = merge_exploit_specs(merged_exploit_spec, candidate)
        result.exploit_spec = normalize_exploit_spec(merged_exploit_spec)
        result.contract_completeness = exploit_spec_completeness(result.exploit_spec)
        return result


