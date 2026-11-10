"""运行时事实接入（2026-10-02 发难清单 Q1 落地）。

把目标 JDK 版本作为一等的约束事实拿到手，使「CC 链挂 JDK 版本」「JNDI
trustURLCodebase 默认关」从猜版本区间变成拿实际运行时比。事实来源（按优先级）：

1. 环境变量 SAST_AI_TARGET_JAVA_VERSION（启动器/部署配置注入，如 "1.8.0_191"、"11.0.1"）；
2. 环境变量 SAST_AI_TARGET_JAVA_MAJOR（只有大版本号时，如 "8"）。

JDK 版本比较遵循 Java 版本语义：1.8 == 8（前导 1 剥离），"8u191" == 1.8.0_191。
事实缺失时一律 fail-open（check_depends 放行并记原因），绝不因事实未知误杀链路。
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def target_jdk_version() -> str:
    """读目标 JDK 版本事实；未配置返回空串。"""
    v = str(os.environ.get("SAST_AI_TARGET_JAVA_VERSION") or "").strip()
    if v:
        return v
    major = str(os.environ.get("SAST_AI_TARGET_JAVA_MAJOR") or "").strip()
    if major:
        # 归一成 major.0 形态参与统一比较
        return f"{major}.0"
    return ""


def jdk_parts(version: str) -> Optional[Tuple[int, ...]]:
    """把 JDK 版本串解析成可比较的数字元组；解析不了返回 None。

    "1.8.0_191" -> (8, 0, 191)；"8u191" -> (8, 0, 191)；"11.0.1" -> (11, 0, 1)；
    "21" -> (21, 0)。前导 1 剥离（Java 8 == 1.8）。
    """
    v = str(version or "").strip()
    if not v:
        return None
    m = re.match(r"^(\d+)u(\d+)$", v)
    if m:
        return (int(m.group(1)), 0, int(m.group(2)))
    segs = re.split(r"[._]", v)
    nums: List[int] = []
    for s in segs:
        m = re.match(r"^(\d+)", s)
        if not m:
            return None
        nums.append(int(m.group(1)))
    if not nums:
        return None
    if len(nums) > 1 and nums[0] == 1:
        nums = nums[1:]  # 1.8.x -> 8.x
    return tuple(nums)


def _cmp_tuples(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    pa = a + (0,) * (n - len(a))
    pb = b + (0,) * (n - len(b))
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


def jdk_in_range(version: str, rng: str) -> bool:
    """判断 JDK 版本是否落在区间内；区间为空或 '*' 恒真；版本解析不了时 fail-open 恒真。"""
    r = str(rng or "").strip()
    if not r or r == "*":
        return True
    parts = jdk_parts(version)
    if parts is None:
        return True
    for clause in r.split(","):
        clause = clause.strip()
        if not clause or clause == "*":
            continue
        m = re.match(r"^(>=|<=|>|<)?\s*(.+)$", clause)
        if not m:
            continue
        op = m.group(1) or "=="
        ref = jdk_parts(m.group(2))
        if ref is None:
            continue
        c = _cmp_tuples(parts, ref)
        if op == ">=" and not c >= 0:
            return False
        if op == "<=" and not c <= 0:
            return False
        if op == ">" and not c > 0:
            return False
        if op == "<" and not c < 0:
            return False
        if op == "==" and c != 0:
            return False
    return True


# ---------------------------------------------------------------------------
# 环境事实扩展（2026-10-03 Part2 M2）：jdk 之外再采五项 —— db_type / db_version /
# mw_type / mw_version / egress。
#
# 取值路径决策：**选甲，不动探针**。中间件/数据库/出网都不是探针能上报的东西
# （探针只看得到被插桩的 Java 方法调用），硬塞进探针等于为了取版本号去织桩
# Tomcat 内部类，代价大且易碎。改走两条静态路子 + 一条显式登记：
#   1. 依赖解析：pom.xml / build.gradle 里找构件与版本（与 SCA 同一路子，
#      参考 mechanism_library 里 fastjson 的 package+version_range 写法）；
#   2. 配置解析：application.properties/yml 的 spring.datasource.url 里
#      的 jdbc:<dialect>:// 直接给出方言，比依赖更贴近真实连接；
#   3. 环境变量登记兜底：SAST_AI_MW_TYPE / SAST_AI_DB_TYPE / ...（启动器注入）。
#
# 事实未知一律返回空串，由消费方（env_premise / check_depends）fail-open，
# 绝不因采不到就判「不满足」。
# ---------------------------------------------------------------------------

# 构件 → 中间件类型。Spring Boot 的 starter 只说明**用哪种**容器，不含版本
# （版本由 spring-boot-dependencies 的 BOM 决定），故版本留空由显式声明补。
_MW_ARTIFACT_TO_TYPE = {
    "org.springframework.boot:spring-boot-starter-web": "tomcat",      # 默认内嵌 tomcat
    "org.springframework.boot:spring-boot-starter-tomcat": "tomcat",
    "org.springframework.boot:spring-boot-starter-jetty": "jetty",
    "org.springframework.boot:spring-boot-starter-undertow": "undertow",
    "org.apache.tomcat.embed:tomcat-embed-core": "tomcat",
    "org.apache.tomcat:tomcat-catalina": "tomcat",
    "org.apache.tomcat:tomcat": "tomcat",
    "org.eclipse.jetty:jetty-server": "jetty",
    "io.undertow:undertow-core": "undertow",
    "org.glassfish:jakarta.el": None,
}

# 显式带版本的中间件构件（命中即可同时定类型与版本）
_MW_VERSIONED_ARTIFACTS = {
    "org.apache.tomcat.embed:tomcat-embed-core": "tomcat",
    "org.apache.tomcat:tomcat-catalina": "tomcat",
    "org.eclipse.jetty:jetty-server": "jetty",
    "io.undertow:undertow-core": "undertow",
}

_DB_ARTIFACT_TO_TYPE = {
    "mysql:mysql-connector-java": "mysql",
    "com.mysql:mysql-connector-j": "mysql",
    "org.postgresql:postgresql": "postgresql",
    "com.h2database:h2": "h2",
    "org.hsqldb:hsqldb": "hsqldb",
    "com.microsoft.sqlserver:mssql-jdbc": "mssql",
    "com.oracle.database.jdbc:ojdbc8": "oracle",
    "com.oracle.database.jdbc:ojdbc11": "oracle",
    "org.xerial:sqlite-jdbc": "sqlite",
    "org.apache.derby:derby": "derby",
    "org.mariadb.jdbc:mariadb-java-client": "mariadb",
}

# jdbc:<dialect>:// 前缀 → 方言
_JDBC_PREFIX_TO_TYPE = {
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "h2": "h2",
    "hsqldb": "hsqldb",
    "sqlserver": "mssql",
    "oracle": "oracle",
    "sqlite": "sqlite",
    "derby": "derby",
    "db2": "db2",
}

_ENV_FACT_KEYS = ("mw_type", "mw_version", "db_type", "db_version", "egress")


def _env_fact(name: str) -> str:
    return str(os.environ.get(f"SAST_AI_{name.upper()}") or "").strip()


def _iter_files(root: Path, names, suffixes, max_files: int = 400):
    """在项目根下找指定文件名/后缀的文件（跳过 target/build/node_modules 等产物目录）。

    2026-11-04：`.codeql-db` 的排除改为**前缀匹配**（`.codeql-db*`）——
    jsc 源码根下曾残留 5 个半成品库（`.codeql-db.partial2..5`），精确匹配排不掉，
    它们会被当源码扫进来（jsc 619 实测：CodeQL 复制时路径爆 MAX_PATH(260)）。
    """
    skip = {"target", "build", "node_modules", ".git", "dist", "out", "bin"}
    found = []
    if not root or not root.is_dir():
        return found
    for p in root.rglob("*"):
        if len(found) >= max_files:
            break
        if not p.is_file():
            continue
        if any(part in skip or part.startswith(".codeql-db") for part in p.parts):
            continue
        if p.name in names or p.suffix in suffixes:
            found.append(p)
    return found


def _parse_maven_deps(root: Path):
    """解析 pom.xml 的 (groupId:artifactId, version) 与 <properties>，返回 (deps, props)。

    轻量实现：只取 dependency / parent / properties，不做完整 Maven 模型解析。
    解析失败返回空 —— 采不到事实就采不到，不猜。
    """
    deps: Dict[str, str] = {}
    props: Dict[str, str] = {}
    try:
        import xml.etree.ElementTree as ET
    except Exception:
        return deps, props
    for pom in _iter_files(root, {"pom.xml"}, set()):
        try:
            tree = ET.parse(pom)
        except Exception:
            continue
        for el in tree.iter():
            tag = str(el.tag or "").split("}")[-1]
            if tag == "dependency":
                g = a = v = ""
                for ch in list(el):
                    ctag = str(ch.tag or "").split("}")[-1]
                    if ctag == "groupId":
                        g = (ch.text or "").strip()
                    elif ctag == "artifactId":
                        a = (ch.text or "").strip()
                    elif ctag == "version":
                        v = (ch.text or "").strip()
                if g and a:
                    deps.setdefault(f"{g}:{a}", v)
            elif tag == "parent":
                g = a = v = ""
                for ch in list(el):
                    ctag = str(ch.tag or "").split("}")[-1]
                    if ctag == "groupId":
                        g = (ch.text or "").strip()
                    elif ctag == "artifactId":
                        a = (ch.text or "").strip()
                    elif ctag == "version":
                        v = (ch.text or "").strip()
                if g and a:
                    deps.setdefault(f"{g}:{a}", v)
            elif tag == "properties":
                for ch in list(el):
                    props[str(ch.tag or "").split("}")[-1]] = (ch.text or "").strip()
            # <X.version>9.0.82</X.version> 也可能散落在 properties 之外，ET 的
            # iter 已覆盖全部元素，这里只补一层：直接吃 version 结尾的叶子
            elif tag.endswith(".version") and el.text:
                props.setdefault(tag, el.text.strip())
    return deps, props


def _resolve_prop(value: str, props: Dict[str, str], depth: int = 3) -> str:
    v = str(value or "").strip()
    for _ in range(depth):
        m = re.match(r"^\$\{([^}]+)\}$", v)
        if not m:
            break
        key = m.group(1)
        if key not in props:
            return ""
        v = str(props.get(key) or "").strip()
    # 仍含 ${} 说明解析不干净，返回空（不把占位符当版本号）
    return "" if "${" in v else v


def _parse_gradle_deps(root: Path) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    for g in _iter_files(root, {"build.gradle", "build.gradle.kts"}, set()):
        try:
            text = g.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for m in re.finditer(r"['\"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^'\"]+)['\"]", text):
            deps.setdefault(f"{m.group(1)}:{m.group(2)}", m.group(3))
    return deps


def _jdbc_dialect_from_config(root: Path) -> str:
    """从 application*.properties/yml 的 spring.datasource.url 读方言。

    这比依赖解析更贴近**真实连接**：有的项目引了多个驱动，但真正连的是 url 里那个。
    """
    files = _iter_files(root, set(), {".properties", ".yml", ".yaml"}, max_files=120)
    for f in files:
        if not f.name.startswith("application"):
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for m in re.finditer(r"jdbc:([a-z0-9]+)://", text):
            dialect = m.group(1).lower()
            if dialect in _JDBC_PREFIX_TO_TYPE:
                return _JDBC_PREFIX_TO_TYPE[dialect]
    return ""


def detect_middleware(target_path) -> Tuple[str, str, str]:
    """探测中间件类型与版本，返回 (mw_type, mw_version, source)。

    source 取值：env / deps / ""（未知）。未采到返回空串，由消费方 fail-open。
    """
    env_type = _env_fact("mw_type")
    env_ver = _env_fact("mw_version")
    if env_type:
        return env_type, env_ver, "env"
    root = Path(target_path) if target_path else None
    if not root or not root.is_dir():
        return "", "", ""
    deps, props = _parse_maven_deps(root)
    deps.update(_parse_gradle_deps(root))
    # 先找能给出版本的构件（信息量最大）
    for art, mw in _MW_VERSIONED_ARTIFACTS.items():
        if art in deps:
            ver = _resolve_prop(deps.get(art) or "", props)
            if ver:
                return mw, ver, "deps"
            return mw, env_ver, "deps"
    # 再看 starter（只定类型）
    for art, mw in _MW_ARTIFACT_TO_TYPE.items():
        if mw and art in deps:
            # tomcat.version / jetty.version 这类属性常显式覆盖内嵌容器版本
            for key in (f"{mw}.version", f"{mw}-embed.version"):
                ver = _resolve_prop(props.get(key) or "", props)
                if ver:
                    return mw, ver, "deps"
            return mw, env_ver, "deps"
    return "", env_ver, ""


def detect_database(target_path) -> Tuple[str, str, str]:
    """探测数据库方言与版本，返回 (db_type, db_version, source)。

    优先级：环境变量 > 配置文件里的 jdbc url > 依赖里的驱动构件。
    url 优先于驱动是因为项目常引多个驱动，真正连的是 url 里那个。
    """
    env_type = _env_fact("db_type")
    env_ver = _env_fact("db_version")
    if env_type:
        return env_type, env_ver, "env"
    root = Path(target_path) if target_path else None
    if not root or not root.is_dir():
        return "", "", ""
    deps, props = _parse_maven_deps(root)
    deps.update(_parse_gradle_deps(root))
    dialect = _jdbc_dialect_from_config(root)
    if dialect:
        # 方言来自 url（最贴近真实连接），但 url 不带版本 —— 版本仍回依赖里找对应驱动，
        # 否则 db_version 恒空、机制表的 version_range 永远判不了。
        for art, db in _DB_ARTIFACT_TO_TYPE.items():
            if db == dialect and art in deps:
                return dialect, _resolve_prop(deps.get(art) or "", props), "config+deps"
        return dialect, env_ver, "config"
    for art, db in _DB_ARTIFACT_TO_TYPE.items():
        if art in deps:
            ver = _resolve_prop(deps.get(art) or "", props)
            return db, ver, "deps"
    return "", "", ""


# ---------------------------------------------------------------------------
# M2 第二项「环境事实」补：XML 解析器配置。
#
# 为什么要采：XXE / 反序列化外的 XML 族（xstream、dom4j、SAX、JAXB）能不能真的
# 读出外部实体，**不看目标里有没有 XXE.java，看的是解析器怎么配的**。同一份
# 源码在这台机器读到 /etc/passwd、在另一台机器被 `disallow-doctype-decl` 直接
# 掐死，差别全在 setFeature 那几行 —— 而这恰恰是全项目之前**一处都没采**的事实
# （2026-10-03 全项目 grep setFeature / external-general-entities 零命中）。
#
# 取法：**只读源码里的解析器配置调用**，不做任何行为猜测：
#   1. setFeature(<name>, <true|false>)  —— 主信号，覆盖 disallow-doctype-decl /
#      external-general-entities / external-parameter-entities / load-external-dtd /
#      secure-processing / validation 等；
#   2. setXIncludeAware / setExpandEntityReferences —— 次信号（布尔即定值）；
#   3. setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD|_SCHEMA, "") —— 次信号。
# 值不是布尔字面量（走变量 / 配置文件）的一律记 raw 不入结论 —— 采不到就 unknown，
# 绝不拿「没看到」当「没开」。
#
# 冲突（同一事实既有 true 也有 false）取**不安全值**（见 _XML_FACT_UNSAFE）并记
# conflicts 供审计：代码库里有 anywhere 一个解析器开着的入口，就不该把它读成
# 「全局都关」，否则会在族层得出假阴性。
# ---------------------------------------------------------------------------

# feature 名（URL 末段 / 常量名）→ 事实名
_XML_FEATURE_TO_FACT = {
    "disallow-doctype-decl": "xml_dtd",
    "external-general-entities": "xml_external_entities",
    "external-parameter-entities": "xml_external_parameter_entities",
    "load-external-dtd": "xml_load_external_dtd",
    "external-stylesheets": "xml_external_stylesheets",
    "secure-processing": "xml_secure_processing",
    "validation": "xml_validation",
}

# 事实名 → (setFeature(true) 取值, setFeature(false) 取值)
_XML_FACT_VALUE_PAIR = {
    "xml_dtd": ("disallowed", "allowed"),
    "xml_external_entities": ("enabled", "disabled"),
    "xml_external_parameter_entities": ("enabled", "disabled"),
    "xml_load_external_dtd": ("enabled", "disabled"),
    "xml_external_stylesheets": ("enabled", "disabled"),
    "xml_secure_processing": ("on", "off"),
    "xml_validation": ("on", "off"),
    "xml_xinclude": ("enabled", "disabled"),
    "xml_expand_entity_refs": ("enabled", "disabled"),
    "xml_external_dtd_access": ("restricted", "open"),
    "xml_external_schema_access": ("restricted", "open"),
}

# 事实的「安全取值」：一个 XML 解析站点显式设成它，该站点对这条事实就收口了。
#
# 判据粒度是**站点级**，不是全库取一个值 —— 真实靶场逼出来的（2026-10-03）：
# java-sec-code 的 XXE.java 里，有的端点老老实实
# setFeature(disallow-doctype-decl,true) + external-general-entities,false，
# 有的端点只 setXIncludeAware(true) 什么都没关。全库取一个值（哪怕「冲突取不安全」）
# 也只会因为「所有显式配置都关着」得出 disabled，把后面那些端点洗出 L_exploit ——
# 那正是拿聚合口径造假阴性。正确语义：只要有一个 XML 站点没显式设安全值，
# 整个工作区这条事实就是不安全值（那个站点就能打）。
#
# 反向代价也可接受：判成 enabled/allowed 只会让条目留在分母里、略微抬高 miss 计数，
# 绝不会藏掉一个真漏洞。
_XML_FACT_SAFE_VALUE = {
    "xml_dtd": "disallowed",
    "xml_external_entities": "disabled",
    "xml_external_parameter_entities": "disabled",
    "xml_load_external_dtd": "disabled",
    "xml_external_stylesheets": "disabled",
    "xml_secure_processing": "on",
    "xml_xinclude": "disabled",
    "xml_expand_entity_refs": "disabled",
    "xml_external_dtd_access": "restricted",
    "xml_external_schema_access": "restricted",
}

# 不安全取值（与 _XML_FACT_SAFE_VALUE 配对；站点级判定时取它）
_XML_FACT_UNSAFE = {
    "xml_dtd": "allowed",
    "xml_external_entities": "enabled",
    "xml_external_parameter_entities": "enabled",
    "xml_load_external_dtd": "enabled",
    "xml_external_stylesheets": "enabled",
    "xml_secure_processing": "off",
    "xml_validation": "on",
    "xml_xinclude": "enabled",
    "xml_expand_entity_refs": "enabled",
    "xml_external_dtd_access": "open",
    "xml_external_schema_access": "open",
}

# 缺席（站点里压根没写这条配置）算不算「不安全」—— 取决于该特性的**默认开关**，
# 不能一刀切。判错的代价不对称：判成不安全 = 条目留在分母（无害）；判成安全 = 把
# 真能打的端点洗出 L_exploit（造假阴性）。所以这里只对「默认开放」的特性取 True。
_XML_FACT_ABSENT_UNSAFE = {
    "xml_dtd": True,                       # 默认允许 DOCTYPE
    "xml_external_entities": True,         # 默认可解析一般外部实体
    "xml_external_parameter_entities": True,
    "xml_load_external_dtd": True,         # SAX 默认去加载外部 DTD
    "xml_external_stylesheets": True,
    "xml_expand_entity_refs": True,        # DOM DocumentBuilder 默认展开实体引用
    "xml_external_dtd_access": True,       # 默认不限制 ACCESS_EXTERNAL_*
    "xml_external_schema_access": True,
    # 下面两条**默认就是安全的**，缺席不能算不安全，否则会得出
    # 「secure_processing=off」这种纯属猜的结论（JAXP 1.5 起默认 ON）。
    "xml_secure_processing": False,
    "xml_xinclude": False,                 # setXIncludeAware 默认 false，只有显式 true 才是风险
}

# 判定「这个源文件算不算 XML 解析站点」的 API 线索。
#
# 只认**真正拿到解析器**的形态，不认 import —— 光一个 `import javax.xml.parsers.*`
# 之类不算站点。否则站点会被注释/常量/无关工具撑到几十个，「全站点都安全才输出安全值」
# 这条规则直接退化成恒输出不安全值，事实就失去区分度了。
_XML_PARSER_API_HINTS = (
    "DocumentBuilderFactory", "SAXParserFactory", "XMLReaderFactory",
    "XMLInputFactory", "TransformerFactory", "SchemaFactory",
    "newDocumentBuilder", "newSAXParser", "createXMLReader", "newSAXBuilder",
    "new SAXReader", "SAXReader()", "XMLStreamReader",
)

_XML_ACCESS_ATTR_TO_FACT = {
    "accessexternaldtd": "xml_external_dtd_access",
    "accessexternalschema": "xml_external_schema_access",
}


def _split_call_args(body: str) -> List[str]:
    """把方法调用的括号体按**顶层**逗号切开（忽略字符串与嵌套括号里的逗号）。"""
    args: List[str] = []
    cur: List[str] = []
    depth = 0
    in_str = False
    esc = False
    for ch in str(body or ""):
        if in_str:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            cur.append(ch)
            continue
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        args.append(tail)
    return args


def _find_calls(text: str, name: str):
    """遍历文本里所有 ``name(...)`` 调用，逐个 yield 其括号**内部**文本。"""
    for m in re.finditer(re.escape(name) + r"\s*\(", str(text or "")):
        # 正则已经吃掉了开括号，故这里从 depth=1 起算；m.end() 指向体内第一字符，
        # 截出来的体不能多吃一个字符。
        depth = 1
        in_str = False
        esc = False
        for j in range(m.end(), len(text)):
            ch = text[j]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
                continue
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    yield text[m.end(): j]
                    break


def _clean_literal(raw: str) -> str:
    s = str(raw or "").strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def _bool_value(raw: str) -> Optional[bool]:
    """把 setFeature 第二参解析成布尔；解析不了返回 None（→ unknown，不猜）。"""
    s = re.sub(r"\s+", "", str(raw or "")).lower()
    if not s:
        return None
    negated = False
    while s.startswith("!"):
        negated = not negated
        s = s[1:]
    if s in ("true", "yes", "1"):
        return not negated
    if s in ("false", "no", "0"):
        return negated
    # XMLConstants.FEATURE_SECURE_PROCESSING / FEATURE_SECURE_PROCESSING 恒 true
    if s.endswith("feature_secure_processing"):
        return not negated
    return None


def _xml_feature_key(raw: str) -> str:
    name = _clean_literal(raw).strip()
    if not name:
        return ""
    # 三条形态都要归一到末段：URL（http://…/disallow-doctype-decl）、常量
    # （XMLConstants.FEATURE_SECURE_PROCESSING）、裸名（external-general-entities）。
    # 下划线→连字符必须做：常量写法是 FEATURE_SECURE_PROCESSING（下划线），
    # 事实表键是 secure-processing（连字符），不做这一步 strip 完只剩
    # secure_processing，会静默查不到 —— 正是最容易漏的那种错。
    key = re.split(r"[/.]", name)[-1].strip().lower().replace("_", "-")
    # XMLConstants.FEATURE_SECURE_PROCESSING → feature-secure-processing → secure-processing
    if key.startswith("feature-"):
        key = key[len("feature-"):]
    return _XML_FEATURE_TO_FACT.get(key, "")


def _aggregate_xml_facts(
    features: List[Dict[str, Any]],
    sites: Optional[List[str]] = None,
) -> Tuple[Dict[str, str], List[str]]:
    """站点级收敛：一条事实在全库取 unsafe 值，除非**每个** XML 站点都显式设成安全值。

    入参：
        features  扫描到的配置调用（每项带 file / fact / value / literal）；
        sites     XML 解析站点清单（含 XML API 但可能一条配置都没写的文件）。

    规则（对 _XML_FACT_SAFE_VALUE 里的每条事实）：
        - 没有站点 ⇒ 不产出该事实（未知，键缺席）；
        - 每个站点都显式设成安全值 ⇒ 输出安全值（如 disabled / disallowed）；
        - 否则 ⇒ 输出不安全值（如 enabled / allowed），并把「哪些站点没设」写进
          conflicts 供人复核。

    只吃字面量值（``literal`` 为真）；走变量/方法的形态按「没设」处理 —— 看不懂
    就是看不懂，不猜。
    """
    facts: Dict[str, str] = {}
    conflicts: List[str] = []
    site_list = list(sites or [])
    if not site_list:
        return facts, conflicts
    by_file: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for it in features:
        by_file.setdefault(str(it.get("file") or ""), {})[str(it.get("fact") or "")] = it
    for fk, safe in _XML_FACT_SAFE_VALUE.items():
        unsafe = str(_XML_FACT_UNSAFE.get(fk) or "")
        if not unsafe:
            continue
        absent_is_unsafe = _XML_FACT_ABSENT_UNSAFE.get(fk, True)
        explicit_seen = 0
        unsafe_sites: List[str] = []
        for s in site_list:
            item = (by_file.get(s) or {}).get(fk)
            if item is None or not item.get("literal"):
                # 这条站点没写（或写成了看不懂的变量）—— 只有「默认开放」的特性才算不安全
                if absent_is_unsafe:
                    unsafe_sites.append(_short_path(s))
                continue
            explicit_seen += 1
            if str(item.get("value") or "") != safe:
                unsafe_sites.append(_short_path(s))
        if unsafe_sites:
            facts[fk] = unsafe
            conflicts.append(f"{fk}={unsafe}:{len(unsafe_sites)}/{len(site_list)}_sites"
                             f"[{'|'.join(unsafe_sites[:3])}]")
            continue
        if not absent_is_unsafe and not explicit_seen:
            # 默认安全、且没人显式设过 ⇒ **未知**（键缺席）。不拿「JDK 默认」当结论：
            # 默认 secure-processing 是不是开，取决于解析器类型与 jaxp.properties，
            # 静态扫源码扫不出来，猜一个 on 同样是在编事实。
            continue
        facts[fk] = safe
    return facts, conflicts


def _short_path(p: str) -> str:
    """站点路径压成末两段，conflicts 里用来指认文件（全路径太吵）。"""
    parts = [x for x in str(p or "").replace("\\", "/").split("/") if x]
    return "/".join(parts[-2:]) if len(parts) > 2 else str(p or "")


def detect_xml_parser_config(target_path=None, max_files: int = 400) -> Dict[str, Any]:
    """扫描目标源码里的 XML 解析器配置，返回三态事实字典（未知即 absent）。

    返回：``{"facts": {...}, "features": [...], "conflicts": [...], "files_scanned": n}``。
    ``facts`` 里的键只能是 _XML_FACT_VALUE_PAIR 的键；采不到就是「键不存在」，
    由 env_premise / check_depends 按事实未知 fail-open。
    """
    root = Path(target_path) if target_path else None
    if not root or not root.is_dir():
        return {"facts": {}, "features": [], "conflicts": [], "files_scanned": 0}
    features: List[Dict[str, Any]] = []
    sites: List[str] = []
    scanned = 0
    for f in _iter_files(root, set(), {".java", ".jsp"}, max_files=max_files):
        try:
            if f.stat().st_size > 262144:  # 256KB 以上的单文件不扫（几乎不可能是解析器配置）
                continue
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        scanned += 1
        # 「站点」= 这个文件摸了 XML 解析 API。哪怕它一条 setFeature 都没写，
        # 它对外部实体能不能读出来也有发言权（默认就是开着的），不能不算进去。
        if any(hint in text for hint in _XML_PARSER_API_HINTS):
            sites.append(str(f))

        for body in _find_calls(text, "setFeature"):
            args = _split_call_args(body)
            if len(args) < 2:
                continue
            fk = _xml_feature_key(args[0])
            if not fk:
                continue
            val_bool = _bool_value(args[1])
            pair = _XML_FACT_VALUE_PAIR.get(fk)
            features.append({
                "fact": fk,
                "feature": _clean_literal(args[0]),
                "value": (pair[0] if val_bool else pair[1]) if val_bool is not None else "",
                "value_bool": val_bool,
                "literal": val_bool is not None,
                "raw_value": _clean_literal(args[1]),
                "call": "setFeature",
                "file": str(f),
            })

        for call in ("setXIncludeAware", "setExpandEntityReferences"):
            for body in _find_calls(text, call):
                args = _split_call_args(body)
                if len(args) < 1:
                    continue
                val_bool = _bool_value(args[0])
                if val_bool is None:
                    continue
                fk = "xml_xinclude" if call == "setXIncludeAware" else "xml_expand_entity_refs"
                features.append({
                    "fact": fk,
                    "feature": call,
                    "value": "enabled" if val_bool else "disabled",
                    "value_bool": val_bool,
                    "literal": True,
                    "raw_value": _clean_literal(args[0]),
                    "call": call,
                    "file": str(f),
                })

        for body in _find_calls(text, "setAttribute"):
            args = _split_call_args(body)
            if len(args) < 2:
                continue
            # XMLConstants.ACCESS_EXTERNAL_DTD → access_external_dtd → accessexternaldtd
            attr = _clean_literal(args[0]).replace("/", ".").replace("_", "").replace("-", "")
            attr = attr.rsplit(".", 1)[-1].strip().lower()
            fk = _XML_ACCESS_ATTR_TO_FACT.get(attr)
            if not fk:
                continue
            raw = _clean_literal(args[1]).strip().lower()
            if raw in ("", "none", "restricted"):
                val = "restricted"
            elif raw in ("all", "*", "file,jar", "file,http"):
                val = "open"
            else:
                continue  # 取值形态不认识 → 不进结论
            features.append({
                "fact": fk,
                "feature": _clean_literal(args[0]),
                "value": val,
                "literal": True,
                "raw_value": _clean_literal(args[1]),
                "call": "setAttribute",
                "file": str(f),
            })

    facts, conflicts = _aggregate_xml_facts(features, sites)
    return {
        "facts": facts,
        "features": features,
        "sites": sites,
        "conflicts": conflicts,
        "files_scanned": scanned,
    }


# 出网探测结果缓存（进程内，避免每次报告都发一次网络请求）
_EGRESS_CACHE: Dict[str, Any] = {"at": 0.0, "value": ""}
_EGRESS_TTL_SECONDS = 300.0


def probe_egress(timeout: float = 2.0, force: bool = False) -> str:
    """探测靶场侧出网能力，返回 full / dns_only / none / unknown。

    语义（只测**平台侧**的出网，不是靶场 JVM 的出网 —— 后者要投弹才知道）：
      full     DNS 解析成功且能连到公网 443
      dns_only 能解析但连不出去（典型：内网 DNS + 出网被墙）
      none     解析与连接都失败
      unknown  探测本身异常（不猜）

    结果缓存 5 分钟。带外通道（M3）能否投入，取决于这里是不是 full。
    """
    now = time.time()
    if not force and _EGRESS_CACHE["value"] and (now - _EGRESS_CACHE["at"]) < _EGRESS_TTL_SECONDS:
        return str(_EGRESS_CACHE["value"])
    value = "unknown"
    try:
        import socket
        dns_ok = False
        try:
            socket.getaddrinfo("example.com", 443)
            dns_ok = True
        except Exception:
            dns_ok = False
        tcp_ok = False
        try:
            with socket.create_connection(("93.184.216.34", 443), timeout=timeout):
                tcp_ok = True
        except Exception:
            tcp_ok = False
        if dns_ok and tcp_ok:
            value = "full"
        elif dns_ok:
            value = "dns_only"
        elif not dns_ok and not tcp_ok:
            value = "none"
    except Exception:
        value = "unknown"
    _EGRESS_CACHE["at"] = now
    _EGRESS_CACHE["value"] = value
    return value


def collect_facts(target_path=None, with_egress: bool = False) -> Dict[str, Any]:
    """收集当前已知的运行时事实；缺什么键就表示该事实未知（空串）。

    参数：
        target_path  项目源码根；给了才会做依赖/配置解析（pom/gradle/application.*）。
        with_egress  是否真发一次出网探测。默认 False —— collect_facts 会被报告
                     接口调用，默认不做网络 IO；带外通道需要时显式置 True。
    """
    mw_type, mw_version, _ = detect_middleware(target_path)
    db_type, db_version, _ = detect_database(target_path)
    out: Dict[str, Any] = {
        "jdk_version": target_jdk_version(),
        "mw_type": mw_type or _env_fact("mw_type"),
        "mw_version": mw_version,
        "db_type": db_type or _env_fact("db_type"),
        "db_version": db_version,
        "egress": probe_egress() if with_egress else _env_fact("egress"),
    }
    # M2 补：XML 解析器配置（三态）。未给 target_path 时键缺席 = 事实未知，
    # 由 env_premise / check_depends fail-open，不会因为没扫源码就判「不满足」。
    if target_path:
        try:
            xml_cfg = detect_xml_parser_config(target_path)
            out.update({k: v for k, v in (xml_cfg.get("facts") or {}).items()})
            if xml_cfg.get("conflicts"):
                out["xml_parser_conflicts"] = ";".join(xml_cfg["conflicts"])
        except Exception:
            pass
    for k in ("xml_external_entities", "xml_dtd", "xml_secure_processing"):
        if k not in out:
            env_v = _env_fact(k)
            if env_v:
                out[k] = env_v
    return out


# 按 workspace 缓存事实（M6）：D1 每 spec 都要问一次 db_type，而依赖解析要扫
# pom/gradle/application.*，逐条重扫会在千级 spec 上烧出可观的 IO。同一 workspace
# 的事实在一轮扫描内不变，缓存即可；缓存键带 target_path，路径变了自动失效。
_FACTS_CACHE: Dict[str, Dict[str, Any]] = {}


def facts_for_workspace(db: Any, workspace_id: Any) -> Dict[str, Any]:
    """按 workspace_id 取运行时事实（带缓存），拿不到返回空 dict。

    D1 侧（d1_service）只有 spec.workspace_id，没有源码根；这里补上
    「workspace_id → target_path → collect_facts」这一段。
    """
    if not workspace_id:
        return {}
    try:
        row = db.execute("SELECT target_path FROM workspaces WHERE id = ?", (workspace_id,), fetchone=True)
    except Exception:
        return {}
    if not row:
        return {}
    try:
        path = str(next(iter(row.values()), "") or "")
    except Exception:
        return {}
    if not path:
        return {}
    hit = _FACTS_CACHE.get(path)
    if isinstance(hit, dict):
        return hit
    try:
        facts = collect_facts(path)
    except Exception:
        facts = {}
    _FACTS_CACHE[path] = facts
    return facts


def check_depends(mech: Dict[str, Any], facts: Optional[Dict[str, Any]] = None) -> Tuple[bool, List[str]]:
    """按机制条目的 depends 校验运行时事实；事实未知时 fail-open（放行 + 记原因）。

    返回 (ok, reasons)。ok=False 表示事实明确不满足（如 JDK 版本落在条目区间外），
    调用方应跳过该条目；ok=True 但 reasons 非空表示事实未知、保守放行。
    """
    facts = facts if isinstance(facts, dict) else {}
    reasons: List[str] = []
    deps = mech.get("depends") if isinstance(mech.get("depends"), dict) else {}
    jdk_range = str(deps.get("jdk_range") or "*")
    jdk_version = str(facts.get("jdk_version") or "")
    if jdk_range not in ("", "*"):
        if not jdk_version:
            reasons.append("jdk_version_unknown")
        elif not jdk_in_range(jdk_version, jdk_range):
            reasons.append(f"jdk_version_mismatch: target={jdk_version} not in [{jdk_range}]")
            return False, reasons
    classes = [str(c) for c in (deps.get("classes") or []) if str(c)]
    if classes:
        known = facts.get("classes")
        if not isinstance(known, (list, tuple, set)) or not known:
            reasons.append("classpath_unknown")
        else:
            known_set = {str(c) for c in known}
            missing = [c for c in classes if c not in known_set]
            if missing:
                reasons.append(f"classpath_missing: {','.join(missing)}")
                return False, reasons
    return True, reasons
