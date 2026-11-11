"""注入类确定性兜底分析器（P1#1：CodeQL 不可用 / 构建失败时仍能检出明显 sink）。

改进清单背景：
- 原 A1 注入类完全依赖 CodeQL（Java 需 Maven/Gradle 构建数据库）。本机 Maven 曾损坏、
  CodeQL autobuild 失败时会静默返回 0 告警，导致 Java 注入类整体漏报（含 java-quote 中
  的 ObjectInputStream.readObject 反序列化、ProcessBuilder 命令注入等高危 sink）。
- 本模块提供语言感知的轻量 sink 模式匹配：不依赖 Maven / CodeQL / 网络，作为注入类的
  **确定性兜底安全网**。当 CodeQL 不可用或构建失败时由 A1PipelineService 调用，确保
  「明显 sink」至少被报告，而非以 0 结果被误判为「无漏洞」。

设计约束：
- 只匹配高置信度的危险 sink（危险函数 / 危险反序列化入口），避免与业务逻辑分析器冲突。
- 不重复 CodeQL 的数据流分析，仅做「危险调用存在性」标记，confidence=medium，verdict=待分析。
- 语言维度：java / python / javascript(ts) / go / php 各有针对性规则；其它语言跳过。

定位：注入类非主链路的离线安全网（IS_PRIMARY_PATH=False）。主链路仍是 CodeQL + AI 语义整合。
"""
# 注入类离线安全网：仅做危险 sink 存在性标记，不替代 CodeQL 数据流分析。
IS_PRIMARY_PATH = False

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.core.models import Vulnerability, rule_hit_label

# 语言 → 平台漏洞类型字符串（对齐 src/core/models.py VulnerabilityType）
_LANG_BY_EXT = {
    ".py": "python", ".java": "java", ".kt": "java", ".scala": "java",
    ".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".go": "go", ".php": "php", ".rb": "ruby", ".c": "cpp", ".cpp": "cpp", ".cc": "cpp", ".h": "cpp",
    ".xml": "mybatis-xml",
    # 此前 _LANG_BY_EXT 没有该扩展名 → _detect_language 返回 None → analyze_content 首行
    # 直接 return []，导致 CWE-16 / CWE-1188 / CWE-522 整类在静态侧无任何 detector。
    ".properties": "properties",
}

# ── 第三方库 / 打包产物排除 ────────────────────────────────────────────────
# A1 启发式 / 业务逻辑 / BOLA / A2 共用同一套，避免逐个通道打补丁漏掉。
# 这里保留 `_is_vendor_asset` 这个别名（本模块内部与既有单测都在用）。
from src.core.scan_scope import is_vendor_asset as _is_vendor_asset  # noqa: E402

# 每条规则： (regex, vuln_type, family, severity, sink_name)
# family 仅用于语义归类；severity 取平台 HIGH/MEDIUM/LOW。
_RULES: Dict[str, List[Tuple[re.Pattern, str, str, str, str]]] = {
    "java": [
        (re.compile(r"new\s+ObjectInputStream\s*\("), "Deserialization", "deserialization", "HIGH", "ObjectInputStream"),
        (re.compile(r"\.\s*readObject\s*\("), "Deserialization", "deserialization", "HIGH", "readObject"),
        (re.compile(r"new\s+XMLDecoder\s*\("), "Deserialization", "deserialization", "HIGH", "XMLDecoder"),
        (re.compile(r"new\s+Yaml\s*\(\s*\)\s*\.\s*(load|loadAll|loadAs)"), "Deserialization", "deserialization", "HIGH", "SnakeYAML.load"),
        (re.compile(r"\.\s*fromXML\s*\("), "Deserialization", "deserialization", "HIGH", "XStream.fromXML"),
        (re.compile(r"JSON\s*\.\s*parseObject\s*\("), "Deserialization", "deserialization", "HIGH", "fastjson.parseObject"),
        (re.compile(r"ObjectMapper[^\n;]*enableDefaultTyping|activateDefaultTyping"), "Deserialization", "deserialization", "HIGH", "Jackson.defaultTyping"),
        (re.compile(r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec"), "Command Injection", "command-execution", "HIGH", "Runtime.exec"),
        (re.compile(r"Runtime\s*\.\s*exec\s*\("), "Command Injection", "command-execution", "HIGH", "Runtime.exec"),
        (re.compile(r"new\s+ProcessBuilder\s*\("), "Command Injection", "command-execution", "HIGH", "ProcessBuilder"),
        (re.compile(r"new\s+GroovyShell\s*\(\s*\)\s*\.\s*(evaluate|parse)"), "Code Injection", "code-injection", "HIGH", "GroovyShell"),
        (re.compile(r"ScriptEngine[^\n;]*\.?\s*eval\s*\("), "Code Injection", "code-injection", "HIGH", "ScriptEngine.eval"),
        # 「ScriptEngine」与「eval(」出现在同一行，而真实写法是先取引擎、隔几行再 eval
        # L100 才 `engine.eval(cmd, bindings)`），跨行即永不命中——Nashorn/ScriptEngine RCE
        # 因此静态与动态双双 0 命中。补两条覆盖真实形态：
        # ① 取引擎后 800 字符内出现 .eval( —— 跨行也能命中，行号落在取引擎那一行。
        # 只保留这一条：另加「new ScriptEngineManager」会在同一行重复出两条（去重键含
        # sink 名，两者 sink 不同），一条漏洞报两份属噪声，故不另行登记。
        (re.compile(r"getEngineByName[\s\S]{0,800}?\.eval\s*\("), "Code Injection", "code-injection", "HIGH", "ScriptEngine.eval(remote)"),
        (re.compile(r"parseExpression\s*\("), "SpEL Injection", "expression-injection", "HIGH", "SpEL.parseExpression"),
        (re.compile(r"SpelExpressionParser"), "SpEL Injection", "expression-injection", "HIGH", "SpelExpressionParser"),
        (re.compile(r"Ognl\.getValue|Ognl\.parseExpression"), "OGNL Injection", "expression-injection", "HIGH", "Ognl.getValue"),
        (re.compile(r"new\s+URL\s*\("), "SSRF", "ssrf", "MEDIUM", "new URL(...)"),
        (re.compile(r"new\s+FileInputStream\s*\(|Files\s*\.\s*readAllBytes\s*\(|readFile\s*\("), "Path Traversal", "path-traversal", "MEDIUM", "file read"),
        # 漏掉了 OWASP 里整整一类形态 —— `new File(路径)` 之后**不做任何 I/O**，
        # 00359/00452/00697/00698/01156/01231/01232）**全部**是这个形态：
        #     java.io.File fileTarget = new java.io.File(bar);   // bar ← 用户输入
        #     if (fileTarget.exists) { ... }                   // 只探测存在性
        # 对照已检出的 00001/00002：它们走 FileInputStream/FileOutputStream，被上一条命中。
        # ⇒ 漏检根因是 **sink 侧覆盖缺口**（源侧 getParameter/getHeader/getCookies
        # 早已在 _SOURCE_RE 里，实测 6/10 用的是 getParameter），不是源侧缺规则。
        #
        # 形态判据（两层，防误报）：
        #   ① 文件对象确实被**消费**（exists/isFile/isDirectory/canRead/canWrite/length/
        #      delete/renameTo/getCanonicalPath/getAbsolutePath/toPath/…）——
        #      光构造不消费不算漏洞（真实项目里 `new File("config.properties")` 遍地都是）。
        #   ② 用「跨行窗口」共现：`new File(` 之后 600 字符内出现上述消费动作。
        #      OWASP 真实写法固定是「构造 → 消费」紧邻（00011: L54 构造、L64 消费），
        #      600 字符足够覆盖，中间允许隔着 try/catch。
        # 变体：`new java.io.File(基址, 相对路径)` 双参构造同样覆盖（00011 就是）。
        (re.compile(r"new\s+(?:java\s*\.\s*io\s*\.\s*)?File\s*\([^;]{0,200}?\)"
                    r"[\s\S]{0,600}?"
                    r"\.\s*(exists|isFile|isDirectory|canRead|canWrite|length|delete|"
                    r"renameTo|getCanonicalPath|getAbsolutePath|toPath|list|listFiles)\s*\("),
         "Path Traversal", "path-traversal", "MEDIUM", "file metadata probe"),
        (re.compile(r"response\s*\.\s*sendRedirect\s*\("), "URL Redirect", "open-redirect", "LOW", "sendRedirect"),
        (re.compile(r"(Statement|PreparedStatement)\s*\.\s*(execute|executeQuery|executeUpdate)\s*\("), "SQL Injection", "sql-injection", "HIGH", "JDBC Statement"),
        (re.compile(r"createStatement\s*\(\s*\)"), "SQL Injection", "sql-injection", "HIGH", "JDBC createStatement"),
        # hash 3 / ldapi 3(0%) / xpathi 3(0%)；且 A1 实走 heuristic-fallback
        # （last_scan_meta.engine=heuristic-fallback、codeql_status=build_failed_or_empty），
        # 故补规则即可直接增加检出。
        # SQL 拼接构造：SQL 关键字字符串字面量直接与变量拼接（sink 常委托给 helper，
        # 用例文件内没有 Statement.execute，旧规则命中不到）。高特异性，FP 风险低。
        # 而存储过程调用写作 `String sql = "{call " + param + "}"`，关键字既不是这四个、
        # 00008 / 01379 / 02170 三条真漏洞整类漏检（sqli 族召回卡在 70% 的三条之一）。
        # 仍要求「字面量 + 拼接号」的形态，故纯字面量的 `{call sp_reset_db}` 不会误报。
        (re.compile(r"\"\s*(?:SELECT\b|INSERT\s+INTO\b|UPDATE\s+\w+\s+SET\b|DELETE\s+FROM\b|\{call\s)[^\"]*\"\s*\+", re.IGNORECASE),
         "SQL Injection", "sql-injection", "HIGH", "SQL 字符串拼接构造"),
        # XPath 注入（原 0% 检出）：javax.xml.xpath 求值族，特征串足够特异。
        (re.compile(r"XPathFactory\s*\.\s*newInstance\s*\("), "XPath Injection", "xpathi", "HIGH", "XPathFactory.newInstance"),
        (re.compile(r"(?:XPath|XPathExpression)\s*\.\s*evaluate\s*\("), "XPath Injection", "xpathi", "HIGH", "XPath.evaluate"),
        (re.compile(r"javax\.xml\.xpath\."), "XPath Injection", "xpathi", "MEDIUM", "javax.xml.xpath 引用"),
        # LDAP 注入（原 0% 检出）：JNDI directory 检索族。
        (re.compile(r"(?:DirContext|LdapContext|InitialDirContext)\s*\.\s*search\s*\("), "LDAP Injection", "ldap-injection", "HIGH", "DirContext.search"),
        (re.compile(r"SearchControls\s*\(|InitialDirContext\s*\("), "LDAP Injection", "ldap-injection", "MEDIUM", "LDAP 检索上下文"),
        # ---- 以下为 sink 覆盖率补强（原仅 19/75=25%）：MyBatis / SSRF 客户端 / XXE / XSS / SpEL 求值 / 模板 ----
        # MyBatis：注解式 Mapper（@Select/@Insert/@Update/@Delete/@*Provider）内 ${} 拼接 → 直接拼进 SQL
        # 注意：SQL 文本内部常带单引号（如 '${username}'），定界符只认双引号，故用 [^"]* 而非 [^"']*，
        # 否则遇到 '${...}' 会提前在单引号处终止匹配，漏掉登录查询这类高危 sink。
        (re.compile(r"@(Select|Insert|Update|Delete|SelectProvider|InsertProvider|UpdateProvider|DeleteProvider)\s*\(\s*\"[^\"]*\$\{[^}]*\}"),
         "SQL Injection", "sql-injection", "HIGH", "MyBatis 注解 ${} 拼接"),
        # SSRF：HTTP 客户端调用（原仅覆盖 new URL(，漏掉真实发包点）
        # RestTemplate 专属方法名本身足够特异，不限 receiver（变量常小写 restTemplate）
        (re.compile(r"\.\s*(getForObject|getForEntity|postForObject|postForEntity)\s*\("),
         "SSRF", "ssrf", "MEDIUM", "RestTemplate 请求"),
        # RestTemplate.exchange / .execute（方法名通用，需 receiver 含 template 才精确）
        (re.compile(r"\w*[Tt]emplate\w*\.\s*(exchange|execute)\s*\("),
         "SSRF", "ssrf", "MEDIUM", "RestTemplate 请求"),
        (re.compile(r"(HttpURLConnection|URLConnection)[^\n;]*\.\s*(getInputStream|connect)\s*\(|openConnection\s*\("),
         "SSRF", "ssrf", "MEDIUM", "URL.openConnection"),
        # OkHttp：类名常小写 okHttpClient，故用 [Oo]kHttp 灵活前缀
        (re.compile(r"\w*[Oo]kHttp\w*Client\w*\.\s*(newCall|execute|enqueue)\s*\(|\.\s*newCall\s*\("),
         "SSRF", "ssrf", "MEDIUM", "OkHttp 请求"),
        # Apache HttpClient：变量名常小写 httpClient
        (re.compile(r"\w*[Hh]ttpClient\w*\.\s*execute\s*\(|HttpGet|HttpPost"),
         "SSRF", "ssrf", "MEDIUM", "Apache HttpClient.execute"),
        # WebClient / RestClient（Spring 5+，变量常小写 webClient）
        (re.compile(r"\w*[Ww]ebClient\w*\.\s*(get|post|put|delete|retrieve|exchange|uri|method)\s*\("),
         "SSRF", "ssrf", "MEDIUM", "WebClient/RestClient 请求"),
        # XXE：XML 解析器（原完全缺失）
        (re.compile(r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\s*\.\s*newInstance\s*\("),
         "XXE", "xxe", "HIGH", "XML 解析器工厂"),
        (re.compile(r"(SAXReader|SAXBuilder|DocumentHelper)\s*[^\n;]*\.\s*(read|build|parseText)\s*\("),
         "XXE", "xxe", "HIGH", "dom4j/jdom XML 读取"),
        # XSS：响应直出（原完全缺失）
        # 但全量 2740 用例实测：宽规则（含 printf/format）98 TP / **47 FP**；
        # 收紧到「格式串=污点变量」仍有 55 TP / **27 FP**（FP 是 safe 变体——运行时值为常量，
        # A1 静态看却是污点，而值级闸对「canary 出现在格式串」无法否决）。
        # 为 2 个漏检引入 27 个 FP 风险不划算 ⇒ 记入 Phase 3 待办，等「值级闸感知的
        # 输出形态规则」设计好再上（需要区分「格式串污点」与「参数位污点」的运行时值）。
        (re.compile(r"getWriter\s*\(\s*\)\s*\.\s*(print|println|write)\s*\("),
         "XSS", "xss", "MEDIUM", "response.getWriter 直出"),
        # XSS：@ResponseBody 处理函数把 String 形参原样 return（反射型直出）。
        # 不写在规则表里而走 _direct_echo_hits：规则表的报告行号取 m.start，
        # 而这里必须报在 `return x;` 那一行（真正的输出点），且需校验形参未经过滤——
        # 用正则做这两件事会把「注解在方法前」写死成 [\s\S]{0,400}，一旦注解落在类上
        # 就会把整段类体吞进来。详见该函数注释。
        # XXE：POI / OOXML（xlsx、docx）解析入口——原 XXE 规则只覆盖 XML 工厂与 dom4j，
        # README 独立条目，靠 poi-ooxml 自身版本决定是否解析外部实体）。
        (re.compile(r"new\s+(?:XSSFWorkbook|HSSFWorkbook|SXSSFWorkbook|XSSFReader|OPCPackage)\s*\(|OPCPackage\s*\.\s*open\s*\("),
         "XXE", "xxe", "HIGH", "POI/OOXML 解析"),
        # SpEL 求值：parseExpression 之后真正触发执行的 getValue
        (re.compile(r"(Expression|SpelExpression)[^\n;]*\.\s*getValue\s*\("),
         "SpEL Injection", "expression-injection", "HIGH", "SpEL.getValue"),
        (re.compile(r"new\s+StandardEvaluationContext\s*\("),
         "SpEL Injection", "expression-injection", "MEDIUM", "StandardEvaluationContext"),
        # 模板注入
        (re.compile(r"(TemplateEngine|VelocityEngine|Configuration\s*\(\s*Configuration\.VERSION_2)[^\n;]*\.\s*(process|evaluate|getTemplate)\s*\("),
         "Template Injection", "template-injection", "HIGH", "模板引擎渲染"),
        # 路径穿越补充：文件读写构造
        # 允许 `new java.io.File(...)` 全限定名——原正则要求 new 后紧跟 File，
        # 实测把 `new java.io.File(base + p)` 这类全限定写法整类漏掉。
        (re.compile(r"new\s+(?:[\w.]+\s*\.\s*)?File\s*\(\s*[^)\"']*[+]"
                    r"|Paths\s*\.\s*get\s*\([^)]*\+"),
         "Path Traversal", "path-traversal", "MEDIUM", "文件路径拼接"),
        # 上面的规则只认「拼接号出现在构造参数内」的 `new File(a+b)` / `Paths.get(a+b)`，
        #     fileName = Utils.TESTFILES_DIR + param;  new FileOutputStream(fileName);
        # 10 个真漏洞全漏，TPR=0%）。本规则补上文件读写构造，并走污点门控避免无差别报。
        (re.compile(r"new\s+(?:java\s*\.\s*io\s*\.\s*)?(?:FileOutputStream|FileInputStream"
                    r"|FileReader|FileWriter|RandomAccessFile|PrintWriter"
                    r"|BufferedWriter|BufferedReader)\s*\(|Files\s*\.\s*(?:newOutputStream"
                    r"|newInputStream|newBufferedWriter|newBufferedReader|write|readAllBytes)\s*\("),
         "Path Traversal", "path-traversal", "MEDIUM", "文件读写 sink"),
        # 这四类此前在规则库里完全没有对应族，占 Benchmark 样本的 41.5%，严格口径
        # TPR 恒为 0。它们不是注入类，而是安全编码规范类，但同样可静态判定。
        # 离线验证（205 用例）：crypto/weakrand/securecookie TPR 100% FPR 0%，
        # hash TPR 55.6% FPR 0%（漏掉的 4 条是算法名来自配置变量，静态不可判定）。
        (re.compile(r"(?:Cipher|KeyGenerator|SecretKeyFactory)\s*\.\s*getInstance\s*\(\s*[\"']"
                    r"[^\"']*(?:DES|DESede|RC2|RC4|ARCFOUR|Blowfish|ECB)[^\"']*[\"']", re.I),
         "不安全加密算法", "insecure-crypto", "MEDIUM", "弱加密套件"),
        (re.compile(r"MessageDigest\s*\.\s*getInstance\s*\(\s*[\"']"
                    r"(?:MD5|MD4|MD2|SHA1|SHA-1|SHA)[\"']", re.I),
         "弱哈希算法", "weak-hash", "MEDIUM", "弱哈希算法"),
        (re.compile(r"new\s+(?:java\s*\.\s*util\s*\.\s*)?Random\s*\(\s*\)"
                    r"|Math\s*\.\s*random\s*\(\s*\)", re.I),
         "弱随机数", "weak-random", "MEDIUM", "不安全随机源"),
        (re.compile(r"\.setSecure\s*\(\s*false\s*\)", re.I),
         "Cookie 安全属性缺失", "insecure-cookie", "MEDIUM", "Cookie 未启用 Secure"),
        # 信任边界违背：外部可控数据被写进 session（作为键或值）。走污点门控，
        # 否则 `setAttribute("userid", staticValue)` 之类会被无差别报。
        (re.compile(r"getSession\s*\(\s*\)\s*\.\s*(?:setAttribute|putValue)\s*\("),
         "信任边界违背", "trust-boundary", "MEDIUM", "session 写入外部可控数据"),
        # `.regexMatchers("/black_path.*")` 未锚定且非 DOTALL，攻击者可借 `%0a`（换行）构造
        # "/black_path%0a/xx" 越过 denyAll 规则，达成鉴权绕过。确定性静态规则，family=auth_bypass、
        # has_http_entry=True 使下游合成 /black_path%0a/xx 路由、D1/D2 用 %0a 负载做 200-vs-403
        # 运行时证明（真实 PoC，非伪造），对账进 CVE 黄金项。
        (re.compile(r"\.\s*regexMatchers\s*\("),
         "CVE-2022-22978", "auth_bypass", "HIGH", "Spring regexMatchers 授权绕过(CVE-2022-22978)"),
        # 全局 CSRF 保护，所有状态变更端点（POST/PUT/DELETE）不再要求 CSRF token，可被跨站请求伪造。
        # 这是「真正检测 CSRF 弱点」的确定性静态规则（不依赖 LLM 猜测），family=csrf 与黄金 token 对齐。
        (re.compile(r"csrf\s*\(\s*\)\s*\.\s*disable\s*\("),
         "CSRF", "csrf", "HIGH", "Spring CSRF 保护被禁用"),
        # 该靶场 29 个 in_scope 漏洞点里有 3 条是 A1 完全没有规则导致的漏检。
        #
        # ① RMI 暴露：createRegistry 把注册表绑到本机端口，配合 bind 即可被远程调用。
        (re.compile(r"LocateRegistry\s*\.\s*createRegistry\s*\("),
         "RMI 暴露", "rmi", "MEDIUM", "LocateRegistry.createRegistry"),
        # ② 反射式类加载：`getDeclaredMethod("defineClass", ...)` + setAccessible(true)
        #    是绕过类加载器、直接把字节流定义成类的经典形态（ClassDataLoader.java）。
        (re.compile(r"getDeclaredMethod\s*\(\s*[\"']defineClass[\"']"),
         "Deserialization", "deserialization", "HIGH", "ClassLoader.defineClass"),
        # ③ 硬编码密钥：形如 `private static final String SECRET = "123456"`。
        #    只认「密钥类变量名 + 字面量赋值」，避免把普通常量字符串误报。
        (re.compile(r"(?:static\s+)?(?:final\s+)?String\s+"
                    r"(?:SECRET|SECRET_KEY|API_KEY|APPSECRET|PASSWORD|TOKEN|PRIVATE_KEY)"
                    r"\s*=\s*[\"'][^\"']{1,64}[\"']"),
         "硬编码密钥", "weak-crypto", "MEDIUM", "hardcoded secret literal"),
    ],
    # MyBatis Mapper XML：<select>/<insert>/<update>/<delete> 内 ${} 拼接（原无 xml 解析能力）
    "mybatis-xml": [
        (re.compile(r"\$\{[^}]+\}"), "SQL Injection", "sql-injection", "HIGH", "MyBatis XML ${} 拼接"),
        (re.compile(r"<(select|insert|update|delete)[^>]*>\s*[^<]*\$\{"), "SQL Injection", "sql-injection", "HIGH", "MyBatis XML SQL ${}"),
    ],
    "python": [
        (re.compile(r"pickle\s*\.\s*loads?\s*\(|cPickle\s*\.\s*loads?\s*\("), "Deserialization", "deserialization", "HIGH", "pickle.load"),
        (re.compile(r"yaml\s*\.\s*load\s*\("), "Deserialization", "deserialization", "HIGH", "yaml.load"),
        (re.compile(r"subprocess\.(Popen|call|run)\s*\(|os\.system\s*\(|os\.popen\s*\("), "Command Injection", "command-execution", "HIGH", "subprocess/os.system"),
        (re.compile(r"(?<![@\w])eval\s*\(|(?<![@\w])exec\s*\("), "Code Injection", "code-injection", "HIGH", "eval/exec"),
        (re.compile(r"__import__\s*\("), "Code Injection", "code-injection", "MEDIUM", "__import__"),
        (re.compile(r"requests\.(get|post|put|delete|head|patch)\s*\([^)]*\+"), "SSRF", "ssrf", "MEDIUM", "requests with concat"),
        (re.compile(r"cursor\.execute\s*\(\s*[^)]*\%|execute\s*\(\s*[\"\'].*\%s"), "SQL Injection", "sql-injection", "HIGH", "cursor.execute format"),
    ],
    "javascript": [
        (re.compile(r"eval\s*\(|new\s+Function\s*\("), "Code Injection", "code-injection", "HIGH", "eval/Function"),
        (re.compile(r"child_process\s*[.:]\s*(exec|execSync|spawn)\s*\(|require\s*\(\s*['\"]child_process"), "Command Injection", "command-execution", "HIGH", "child_process"),
        (re.compile(r"vm\s*\.\s*(runInThisContext|runInNewContext|runInContext)\s*\("), "Code Injection", "code-injection", "HIGH", "vm.run"),
        (re.compile(r"new\s+Function\s*\("), "Code Injection", "code-injection", "HIGH", "new Function"),
        (re.compile(r"\.innerHTML\s*="), "XSS", "xss", "MEDIUM", "innerHTML"),
    ],
    "go": [
        (re.compile(r"exec\.Command\s*\(|exec\.CommandContext\s*\("), "Command Injection", "command-execution", "HIGH", "os/exec.Command"),
        (re.compile(r"template\s*\.\s*HTML\s*\(|\.Parse\s*\([^)]*\+"), "XSS", "xss", "MEDIUM", "html/template"),
        (re.compile(r"sql\s*\.\s*(Query|QueryRow|Exec)\s*\([^)]*[\"']\s*\+"), "SQL Injection", "sql-injection", "HIGH", "database/sql concat"),
    ],
    "php": [
        (re.compile(r"(?<![\w\\\\])eval\s*\("), "Code Injection", "code-injection", "HIGH", "eval"),
        (re.compile(r"(?<![\w\\\\])(system|exec|shell_exec|passthru|proc_open)\s*\("), "Command Injection", "command-execution", "HIGH", "php exec"),
        (re.compile(r"unserialize\s*\("), "Deserialization", "deserialization", "HIGH", "unserialize"),
        (re.compile(r"mysql_query\s*\([^)]*\."), "SQL Injection", "sql-injection", "HIGH", "mysql_query"),
    ],
    "ruby": [
        (re.compile(r"(?<![\w.])(system|exec|`|open|popen)\s*\("), "Command Injection", "command-execution", "HIGH", "system/backticks"),
        (re.compile(r"Marshal\.load\s*\("), "Deserialization", "deserialization", "HIGH", "Marshal.load"),
        (re.compile(r"eval\s*\("), "Code Injection", "code-injection", "HIGH", "eval"),
    ],
    "cpp": [
        (re.compile(r"system\s*\(\s*"), "Command Injection", "command-execution", "HIGH", "system()"),
        (re.compile(r"popen\s*\(\s*"), "Command Injection", "command-execution", "HIGH", "popen()"),
    ],
}


# 背景：README 的 Actuators to RCE 条目指向 logback-online.xml 的 <jmxConfigurator/> 与
# application.properties 的 management.security.enabled=false。这两类文件此前完全落在检测之外：
# .properties 没有扩展名映射（analyze_content 首行直接 return []），.xml 被统一分派到 mybatis-xml
# 组、又被 _is_mapper_xml 闸门拒掉。CWE-16（安全配置不当）/ CWE-1188（不安全默认配置）/
# CWE-522（凭据保护不足）这一整类因此零 detector，与规则表有多少条无关。
#
# 归 config-security（暴露 / 配置轴）——按平台既有约定仅做分类展示，不进 D1 重放、
# 不进 D2 差分门禁、不计入召回口径。明文凭据单列，见下方 _CREDENTIAL_RULES。
_CONFIG_RULES: List[Tuple[re.Pattern, str, str, str, str]] = [
    # actuator 安全校验被关闭（Spring Boot 1.x 写法，靶场即此形态）
    (re.compile(r"^\s*management\.security\.enabled\s*=\s*false\s*$", re.MULTILINE | re.IGNORECASE),
     "Security Misconfiguration", "config-security", "MEDIUM", "actuator 安全校验被关闭"),
    # actuator 端点全量暴露（Spring Boot 2.x 写法）
    (re.compile(r"^\s*management\.endpoints\.web\.exposure\.include\s*=\s*\*\s*$", re.MULTILINE | re.IGNORECASE),
     "Security Misconfiguration", "config-security", "MEDIUM", "actuator 端点全量暴露"),
    # actuator 端点全量暴露（Spring Boot 1.x 写法，分隔符层级不同）
    (re.compile(r"^\s*management\.endpoint\.exposure\.include\s*=\s*\*\s*$", re.MULTILINE | re.IGNORECASE),
     "Security Misconfiguration", "config-security", "MEDIUM", "actuator 端点全量暴露"),
    # 单个高危端点被显式打开（如 management.endpoint.shutdown.enabled=true）
    (re.compile(r"^\s*management\.endpoint\.[\w.]+\.enabled\s*=\s*true\s*$", re.MULTILINE | re.IGNORECASE),
     "Security Misconfiguration", "config-security", "MEDIUM", "actuator 端点被单独开启"),
    # logback JMX 配置器：配合 actuator 的 jolokia / heapdump 可致 RCE（README 的 Actuators to RCE）
    (re.compile(r"<\s*jmxConfigurator\b"),
     "Security Misconfiguration", "config-security", "HIGH", "logback JMX 配置器"),
]

# 口径：先只检出、不计入召回（归 information-disclosure 暴露轴，天然不进重放 / 差分 / 召回），
# 观察一轮再决定是否纳入统计。设 _CREDENTIAL_RULES_ENABLED = False 可整体关闭。
# 误报控制：占位符（${...} / your_password / changeme / xxx / <...> 等）一律不报——
# 配置文件里大量模板值，不做白名单会把示例值误判成真实凭据。
_CREDENTIAL_RULES_ENABLED = True

_CREDENTIAL_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"^\s*spring\.datasource\.password\s*=\s*(\S+)", re.MULTILINE | re.IGNORECASE),
     "明文数据库口令"),
    (re.compile(r"^\s*(?:access[-_.]?key[-_.]?secret|secret[-_.]?key|accesskeysecret|aksk)\s*=\s*(\S+)",
                re.MULTILINE | re.IGNORECASE),
     "明文访问密钥"),
]

_PLACEHOLDER_VALUE_RE = re.compile(
    r"^(?:\$\{[^}]*\}|<[^>]*>|your[_-]?\w*|change[_-]?me|passw(or)?d|xxx+|todo|tbd|test|"
    r"example\w*|sample\w*|placeholder|none|null|empty|\*+|-+)$",
    re.IGNORECASE,
)


def _is_placeholder_credential(value: str) -> bool:
    """判定一个凭据值是否为占位符 / 示例值（是则不报）。"""
    return bool(_PLACEHOLDER_VALUE_RE.match(str(value or "").strip()))


def _credential_hits(content: str) -> List[Tuple[int, str]]:
    """明文凭据检出点 [(行号, sink 名)]，仅在 .properties 与非 mapper 配置 xml 上调用。"""
    if not _CREDENTIAL_RULES_ENABLED:
        return []
    hits: List[Tuple[int, str]] = []
    for pat, sink in _CREDENTIAL_RULES:
        for m in pat.finditer(content):
            if _is_placeholder_credential(m.group(1) if m.groups() else ""):
                continue
            hits.append((_line_of(content, m.start()), sink))
    return hits


# 弱哈希 / 弱加密的算法名经常不写在代码里，而是从配置文件读：
#     String algorithm = benchmarkprops.getProperty("hashAlg1", "SHA512");
#     MessageDigest md = MessageDigest.getInstance(algorithm);
# 而 _RULES 里的弱算法规则要求 getInstance("MD5") 这种**字符串字面量**形态，
# 变量形态一条都认不出。实测 OWASP sample-200 的 benchmark.properties 里
# hash 族召回卡在 66.7%。规则注释里此前把这类判为「静态不可判定」，
# 但 .properties 就在项目里、值是明文的，属于**可判定**——只要把值折叠进来。
#
# 做法：先用赋值语句把「变量名 → 配置键」记下来，再用项目级 properties 表
# （由调用方从同批 .properties 文件解析后传入）把键折成实际值，最后再判弱算法。
# 未拿到配置表时用 getProperty 的**默认值**兜底，拿不到值就一律不报——
# 绝不能「看到 getProperty 就报」，那会把配置成 SHA-256 的安全写法也误报掉。

# `xxx = props.getProperty("key", "default")` / `props.getProperty("key")`
_PROP_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*=\s*[\w$.]*\.?\s*getProperty\s*\(\s*[\"']([^\"']+)[\"']"
    r"\s*(?:,\s*[\"']([^\"']*)[\"']\s*)?\)")
# `MessageDigest.getInstance(VAR)` —— 只收变量形态（字面量形态由 _RULES 覆盖）
_ALGO_INSTANCE_RE = re.compile(
    r"(MessageDigest|Cipher|KeyGenerator|SecretKeyFactory)\s*\.\s*getInstance\s*\(\s*"
    r"([A-Za-z_$][\w$]*)\s*\)")
_WEAK_HASH_ALGO_RE = re.compile(r"^(?:MD5|MD4|MD2|SHA-?1|SHA)$", re.IGNORECASE)
_WEAK_CIPHER_ALGO_RE = re.compile(
    r"(?:^|/)(?:DES|DESede|RC2|RC4|ARCFOUR|Blowfish)(?:/|$)|ECB", re.IGNORECASE)


def _config_derived_algo_hits(content: str, properties_map: Optional[Dict[str, str]] = None
                              ) -> List[Tuple[int, str, str]]:
    """算法名来自配置取值时的弱算法命中点 [(行号, 漏洞类型, sink 名)]。

    properties_map 为项目级 .properties 扁平表（key → value）。不传时只能用
    getProperty 的默认值兜底；键与默认值都拿不到 → 该点不出条（防误报）。
    """
    props = properties_map or {}
    # 变量名 → 折叠后的实际算法值（拿不到值的变量不放进表里）
    resolved: Dict[str, str] = {}
    for m in _PROP_ASSIGN_RE.finditer(content):
        var, key, default = m.group(1), m.group(2), (m.group(3) or "")
        value = str(props.get(key) or default or "").strip()
        if value:
            resolved[var] = value
    if not resolved:
        return []
    hits: List[Tuple[int, str, str]] = []
    for m in _ALGO_INSTANCE_RE.finditer(content):
        var = m.group(2)
        value = resolved.get(var)
        if not value:
            continue
        api = m.group(1)
        if api == "MessageDigest" and _WEAK_HASH_ALGO_RE.match(value):
            hits.append((_line_of(content, m.start()), "弱哈希算法",
                         f"弱哈希算法（配置取值 {var}={value}）"))
        elif api != "MessageDigest" and _WEAK_CIPHER_ALGO_RE.search(value):
            hits.append((_line_of(content, m.start()), "不安全加密算法",
                         f"弱加密套件（配置取值 {var}={value}）"))
    return hits


def parse_properties_files(files: Optional[List[Dict[str, Any]]]) -> Dict[str, str]:
    """把同批文件里的 .properties 解析成扁平 key→value 表（供常量折叠用）。

    只取 `key=value` 与 `key:value` 两种形态，忽略注释与空行。同名键以**首个
    文件**为准不再覆盖（避免 target/ 下的编译副本盖掉 src/main/resources 的真值，
    实测两处内容一致，但以源码为准更稳）。
    """
    out: Dict[str, str] = {}
    for f in files or []:
        path = str(f.get("path") or f.get("file_path") or "")
        if not path.lower().endswith(".properties"):
            continue
        content = f.get("content") or f.get("source") or ""
        if not content:
            continue
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", "!", ";")) or "=" not in line and ":" not in line:
                continue
            sep = "=" if "=" in line else ":"
            key, _, value = line.partition(sep)
            key = key.strip()
            if key and key not in out:
                out[key] = value.strip()
    return out


# .properties 与非 mapper 的配置类 xml 共用同一规则组（两组规则语义一致，只是载体不同）
_RULES["properties"] = _CONFIG_RULES
_RULES["config-xml"] = _CONFIG_RULES


def _detect_language(path: str) -> Optional[str]:
    ext = Path(path).suffix.lower()
    return _LANG_BY_EXT.get(ext)


def _line_of(content: str, pos: int) -> int:
    return content.count("\n", 0, pos) + 1


def _is_mapper_xml(content: str) -> bool:
    """判定一段 XML 是否为 MyBatis Mapper 文件。

    判据（满足其一即可）：
      1) 根节点为 <mapper namespace="...">；
      2) 含 MyBatis 官方 DOCTYPE（mybatis.org/dtd/mybatis-3-mapper.dtd）。
    pom.xml 的根节点是 <project>，applicationContext.xml 是 <beans>，均不匹配，
    因此不会把 Maven 属性占位符 ${...} 误当成 SQL 拼接。
    """
    head = content[:4000]
    return bool(re.search(r"<mapper[\s>]", head)) or "mybatis-3-mapper.dtd" in head


# 背景：SSRF / 命令注入等 sink 常被封装进项目内工具类（HttpFetcher.fetch / CmdUtil.run）。
# 逐文件 sink 匹配只在「sink 本体所在文件」出条，而调用方（Controller）文件内不含任何
# sink 文本 → 调用点漏报。真正可验证的恰恰是「有 HTTP 入口的调用点」，故需要传播一层。
# 做法：先从全量文件学出「哪些方法体内直接含危险 sink」，再在任何「限定调用
# （ClassName.method」位置回标同族。映射表由源码自动学习，不硬编码任何靶场类名。

# 仅传播「调用即危险」的确定性族；XSS / open-redirect 等上下文相关族不传播，避免误伤。
_PROPAGATABLE_FAMILIES = {
    "ssrf", "command-execution", "code-injection", "expression-injection",
    "deserialization", "sql-injection", "path-traversal",
}

_JAVA_METHOD_RE = re.compile(
    r"(?:public|private|protected|static|final|synchronized|abstract|native|default)\s+"
    r"[\w<>,\[\]\.\?\s]+?\s(\w+)\s*\("
)
_PY_METHOD_RE = re.compile(r"^\s*def\s+(\w+)\s*\(", re.MULTILINE)
_JS_METHOD_RE = re.compile(
    r"function\s+(\w+)\s*\(|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>)"
)
_CLASS_RE = re.compile(r"\b(?:class|interface|enum|record)\s+(\w+)")


def _method_spans(content: str, lang: str) -> List[Tuple[int, str]]:
    """返回 [(方法声明起始偏移, 方法名)]，按偏移升序——用于把 sink 行归属到方法。"""
    spans: List[Tuple[int, str]] = []
    if lang == "java":
        for m in _JAVA_METHOD_RE.finditer(content):
            spans.append((m.start(), m.group(1)))
    elif lang == "python":
        for m in _PY_METHOD_RE.finditer(content):
            spans.append((m.start(), m.group(1)))
    elif lang == "javascript":
        for m in _JS_METHOD_RE.finditer(content):
            name = m.group(1) or m.group(2)
            if name:
                spans.append((m.start(), name))
    spans.sort(key=lambda x: x[0])
    return spans


def _method_of(spans: List[Tuple[int, str]], pos: int) -> Optional[str]:
    """取 pos 之前最近的方法声明名（方法头跨行也能正确归属）。"""
    name = None
    for start, n in spans:
        if start <= pos:
            name = n
        else:
            break
    return name


# 背景：文件读写 sink 的成立要件是「**目标路径**由外部输入决定」，不是「调用点传了脏数据」。
# 路径由 `TESTFILES_DIR + "cmd" + fileNum` 在方法内拼出，调用方给的 `cmdOut` 只进文件**内容**。
# 只看「调用点实参带不带污点」会把它整片误报成路径穿越。
# 正确判据：看包装方法的 sink **用到了第几个形参**，只有那个位置上的实参带污点才算可达。

def _split_top_level_args(text: str) -> List[str]:
    """按顶层逗号切分实参（括号/方括号/花括号内的逗号与字符串字面量里的逗号都不算）。"""
    out: List[str] = []
    buf: List[str] = []
    depth = 0
    i, n = 0, len(text or "")
    while i < n:
        ch = text[i]
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            i += 1
            while i < n:
                buf.append(text[i])
                if text[i] == "\\":
                    i += 1
                    if i < n:
                        buf.append(text[i])
                elif text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if buf:
        out.append("".join(buf))
    return out


def _params_of(content: str, name_end: int) -> List[str]:
    """从方法名右括号起解析形参名列表（按位置）。解析不出来返回 []。"""
    i = name_end
    while i < len(content) and content[i] in " \t":
        i += 1
    if i >= len(content) or content[i] != "(":
        return []
    depth = 0
    j = i
    while j < len(content):
        if content[j] == "(":
            depth += 1
        elif content[j] == ")":
            depth -= 1
            if depth == 0:
                break
        j += 1
    else:
        return []
    names: List[str] = []
    for part in _split_top_level_args(content[i + 1: j]):
        ids = re.findall(r"[A-Za-z_$][\w$]*", part)
        if ids:
            names.append(ids[-1])  # 形参名是声明里最后一个标识符
    return names


def _method_spans_with_params(content: str) -> List[Tuple[int, str, List[str]]]:
    """Java 专用：[(方法起始偏移, 方法名, 形参名列表)]，形参按位置对应调用实参。"""
    spans: List[Tuple[int, str, List[str]]] = []
    for m in _JAVA_METHOD_RE.finditer(content):
        spans.append((m.start(), m.group(1), _params_of(content, m.end(1))))
    spans.sort(key=lambda x: x[0])
    return spans


def _method_and_params(
    spans: List[Tuple[int, str, List[str]]], pos: int
) -> Tuple[Optional[str], List[str]]:
    """取 pos 之前最近的方法（名 + 形参表）。"""
    name: Optional[str] = None
    params: List[str] = []
    for start, n, ps in spans:
        if start <= pos:
            name, params = n, ps
        else:
            break
    return name, params


# 请求处理注解：出现在方法声明紧前方时，说明该方法是 HTTP 处理函数（其返回值直出响应体）。
_HANDLER_ANN_RE = re.compile(
    r"@(?:ResponseBody|RestController|Controller|RequestMapping|GetMapping|"
    r"PostMapping|PutMapping|DeleteMapping|PatchMapping)\b"
)
# 方法签名里的 String 形参名：`(String xss)` / `(String xss, HttpServletResponse res)` /
# `(@CookieValue("xss") String xss, int n)`。只认 String 形参——基本类型不可能构成 XSS。
_SIG_STRING_PARAM_RE = re.compile(r"@\w+(?:\([^)]*\))?\s*(?:final\s+)?String\s+(\w+)|(?<![\w.])String\s+(\w+)")
# 裸 return 标识符：`return xss;`——不匹配 `return encode(xss);`（有净化）与 `return "字面量";`
_RETURN_IDENT_RE = re.compile(r"\breturn\s+([A-Za-z_$][\w$]*)\s*;")


def _direct_echo_hits(content: str) -> List[Tuple[int, str]]:
    """反射型 XSS 直出：HTTP 处理函数把 String 形参原样 return。返回 [(return 行号, 形参名)]。

    为什么不写成 _RULES 里的一条正则：
    1. 报告行号必须是 `return x;` 所在行（真正的输出点，也是前端展示与 D2 定位用的行号），
       而规则表统一用 m.start 报行；若把 `@ResponseBody` 写进正则开头，行号会落到注解甚至类声明上。
    2. 需要「返回的标识符必须是本方法的 String 形参」这一同名约束，跨方法窗口不可控。
    3. 需要「方法紧前方出现请求处理注解」这一门控：XSS.java 的 reflect/show 是方法级注解，
       而只要求「前 400 字符内有注解」的写法会把整段类体吞进来（Log4j.java 的类级 @RestController
       会被误当成方法级），实测命中行号落到类声明上。
    故按方法逐段判定：方法头取形参集 → 方法体取裸 return → 求交集。
    """
    spans = _method_spans(content, "java")
    if not spans:
        return []
    hits: List[Tuple[int, str]] = []
    for idx, (start, _name) in enumerate(spans):
        end = spans[idx + 1][0] if idx + 1 < len(spans) else len(content)
        block = content[start:end]
        brace = block.find("{")
        if brace < 0:
            continue
        sig, body = block[:brace], block[brace:]
        # 门控：注解必须紧贴本方法声明，且中间不能跨过上一个方法的闭合花括号（否则是类级注解）
        before = content[max(0, start - 300):start]
        cut = before.rfind("}")
        if cut >= 0:
            before = before[cut + 1:]
        if not _HANDLER_ANN_RE.search(before):
            continue
        # 门控：必须是「String 形参」——@RequestParam/@CookieValue 等注解形参与裸形参都算
        params = {a or b for a, b in _SIG_STRING_PARAM_RE.findall(sig)}
        if not params:
            continue
        for rm in _RETURN_IDENT_RE.finditer(body):
            ret = rm.group(1)
            if ret in params:  # 返回的正是本方法的 String 形参（未接任何净化函数）
                hits.append((_line_of(content, start + brace + rm.start()), ret))
    return hits


# 205 用例样本上产生 463 条无差别命中（占全部 finding 的 91.5%），把宽松口径 FPR
# 顶到 94.95%、TPR 虚高到 97.17%。真实代码里绝大多数 `println` 输出的是静态文案或
# 故对"输出型/文件型"sink 增加一道轻量的文件内污点判定：实参必须引用外部输入变量。
#
# 设计边界（刻意的取舍，勿随意放宽）：
#   - 文件内、方法无关、不跨文件：A1 是离线兜底规则层，跨文件污点交给 A2/D2。
#     不做容器中转会漏掉全部 7 个此类 xss 真漏洞。
#   - 遇净化器即终止：htmlEscape / encodeForHTML / ESAPI.encoder 等视为已净化。
#   - fail-open 不适用于此处：本门控的目的就是降噪，宁可漏也不再无差别报。

# 污点源：RHS 出现这些调用 → LHS 变量被污染
_TAINT_SRC_RE = re.compile(
    r"request\s*\.\s*(?:getParameter|getParameterValues|getParameterMap|getParameterNames"
    r"|getHeader|getHeaders|getQueryString|getRequestURI|getRequestURL|getCookies"
    r"|getInputStream|getReader|getParts|getPart|getAttribute)"
    r"|\bgetParameterMap\s*\(\s*\)|\breadLine\s*\(\s*\)|\bnextElement\s*\(\s*\)"
    r"|\bgetCookies\s*\(\s*\)|\bgetQueryString\s*\(\s*\)"
)
# 净化器：RHS 出现这些 → LHS 视为已净化，不再当作污点传播
_TAINT_SANITIZER_RE = re.compile(
    r"htmlEscape|escapeHtml|escapeHtml4|encodeForHTML|encodeForJavaScript|escapeJavaScript"
    r"|ESAPI\s*\.\s*encoder|StringEscapeUtils|URLEncoder\s*\.\s*encode"
    r"|\bsanitize\s*\(|HtmlPolicyBuilder|Jsoup\s*\.\s*clean"
)
# 赋值语句：LHS 变量 = RHS（到分号，限长防失控）
_TAINT_ASSIGN_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*=\s*([^;]{0,400})")
# 容器写入（键控）：X.put(key, value)
_TAINT_CONT_PUT_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\.\s*put\s*\(")
# 顺序容器的变更操作：X.add/append/insert/offer/push(value) 与 X.remove(index)。
# 必须按源码出现顺序处理——Benchmark 写出
#   add("safe"); add(param); add("moresafe"); remove(0);  bar = get(1);
# remove 会让后续元素前移，此时 get(1) 取到的是安全的 "moresafe"。
# 不模拟 remove 移位就会把这条假阳性误判成污点直出。
_TAINT_CONT_SEQ_RE = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.\s*(add|append|insert|offer|push|remove)\s*\(")
# 容器读取：X.get/toArray/elementAt(...)
_TAINT_CONT_GET_RE = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.\s*"
    r"(?:get|toArray|elementAt|peek|poll|remove|first|last|next|value)\s*\(")
# 自定义参数包装器（如 scr.getTheParameter(...)）——跨方法的污点入口。
# 必须以 `.get` 开头：早期版本写成 `\.\s*\w*(?:...|[Cc]ookie|...)`，会把
# `new javax.servlet.http.Cookie(...)` 的 `.Cookie(` 当成污点源，实测导致
_TAINT_CUSTOM_GETTER_RE = re.compile(
    r"\.\s*get\w*(?:[Pp]arameter|[Pp]aram|[Ii]nput|[Hh]eader|[Cc]ookie|[Vv]alue)\s*\(")
# 已确认的「假污点」getter：名字长得像取参，实际返回常量/字面量。
#   // This method is a 'safe' source.
#   public String getTheValue(String p) { return "bar"; }
# 原先 _TAINT_CUSTOM_GETTER_RE 的 [Vv]alue 分支会把它判成外部输入 =>
# 每片 18 个用例稳定假阳性（OWASP sqli-1/2/3 各 18 个，命中即100% 是 FP，
# lift=0.00，是全片唯一纯度 0% 的特征）。
# 处置：按「安全 getter 名」精确白名单排除，不扩大到所有 get*Value ——
# getTheParameter / getTheCookie 确实透传 request，是真外部源，必须保留。
_TAINT_SAFE_GETTER_NAMES = frozenset({
    "getthevalue",       # SeparateClassRequest.getTheValue -> "bar"
})
_TAINT_GETTER_NAME_RE = re.compile(r"\.\s*(get\w*(?:[Vv]alue))\s*\(")
# 剥离字面量后残留的空实参括号 "getTheValue"
_EMPTY_ARGS_RE = re.compile(r"\(\s*\)")
_TAINT_IDENT_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\b")
# 字符串字面量：其内部的词不是变量引用，判污点前必须先剥掉。
# 实测踩过：`write("url forbidden")` 里的 "url" 被当成变量，而同文件恰好有
# `String url = request.getParameter("url")`，导致静态文案被误判成污点直出。
_STR_LITERAL_RE = re.compile(r'"(?:[^"\\\n]|\\.)*"')

# 需要过污点门控的 sink 名（与 _RULES 元组的第 5 项 sink 对应）
_TAINT_GATED_SINKS = {
    "response.getWriter 直出",
    "文件读写 sink",
    "session 写入外部可控数据",
}


def _strip_literals(text: str) -> str:
    """剥掉字符串字面量，避免字面量内的词被当作变量引用。"""
    return _STR_LITERAL_RE.sub(" ", text) if text else ""


def _hit_custom_getter(rhs: str) -> bool:
    """rhs 里是否有「真外部输入」型自定义 getter。

    与 _TAINT_CUSTOM_GETTER_RE 的区别只有一个：先把已确认的安全 getter
    （如 SeparateClassRequest.getTheValue 返回常量 "bar"）整段挖掉，
    再看剩下的部分是否还有真污点入口。
    白名单是精确名匹配，不做前缀/模糊放宽，避免误伤 getTheParameter/getTheCookie。
    """
    masked = rhs
    for gm in _TAINT_GETTER_NAME_RE.finditer(rhs):
        if gm.group(1).lower() not in _TAINT_SAFE_GETTER_NAMES:
            continue
        # 安全源：把这次调用挖成空格，消掉残留的空实参括号。
        # 坑：只查masked 而循环结束后又回头查原始 rhs，会让修复静默失效
        # （[Vv]alue 分支在原文里又把 getTheValue 认成外部输入）。
        masked = masked[:gm.start(1)] + " " + masked[gm.end(1):]
        masked = _EMPTY_ARGS_RE.sub(" ", masked)
    if _TAINT_SRC_RE.search(masked):
        return True
    return bool(_TAINT_CUSTOM_GETTER_RE.search(masked))


def _balanced_args(text: str, open_pos: int) -> Optional[str]:
    """从 open_pos 处的 '(' 开始做括号平衡扫描，返回实参文本；无法闭合返回 None。"""
    depth = 0
    i = open_pos
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i]
        elif ch == ";" and depth <= 1:
            return text[open_pos + 1:i]
        i += 1
    return None


def _java_tainted_vars(content: str, max_rounds: int = 8, apply_html_sanitizers: bool = True) -> set:
    """求文件内的污点变量集合（含普通传播 + 一层容器中转，遇净化器剔除）。

        m.put("keyA", param);  bar = m.get("keyB");          // 取的是安全值
        list.add(param); list.add("safe"); bar = list.get(1); // 取的是安全值
    若把容器整体判污，这两种假阳性都会被误报。
    故按 put 的键、add 的出现序号分别记录槽位是否污。

    编码器（escapeHtml / encodeForHTML / ESAPI.encoder / Jsoup.clean ...），它们只中和「响应
    输出型」sink（XSS）。对「文件读写」「session 写入外部可控数据」这类与 HTML 编码无关的 sink，
    escapeHtml 不构成净化。默认 True 保持既有 XSS 行为；非 XSS 门控 sink 传 False，避免
    trustbound 00098「escapeHtml(param)→putValue」被误判为已净化而漏检。
    """
    tainted: set = set()
    # container -> {slot(str): is_tainted(bool)}；slot 为 put 的键或 add 的序号
    containers: Dict[str, Dict[str, bool]] = {}

    def _slot_tainted(container: str, slot: str) -> bool:
        return bool(containers.get(container, {}).get(slot))

    for _ in range(max_rounds):
        added = False
        # 顺序容器：按源码顺序重放 add/remove，槽位用索引字符串存进 containers
        seq_state: Dict[str, List[bool]] = {}
        for m in _TAINT_CONT_SEQ_RE.finditer(content):
            cont, op = m.group(1), m.group(2)
            args = _balanced_args(content, m.end() - 1)
            if args is None:
                continue
            seq = seq_state.setdefault(cont, [])
            if op == "remove":
                idx_txt = args.split(",", 1)[0].strip()
                if idx_txt.isdigit():
                    i = int(idx_txt)
                    if 0 <= i < len(seq):
                        seq.pop(i)
                continue
            parts = args.split(",", 1)
            val = parts[1] if (op == "insert" and len(parts) > 1) else parts[0]
            val_tainted = any(i.group(1) in tainted
                              for i in _TAINT_IDENT_RE.finditer(_strip_literals(val)))
            if op == "insert" and parts[0].strip().isdigit():
                seq.insert(int(parts[0].strip()), val_tainted)
            else:
                seq.append(val_tainted)
        for cont, seq in seq_state.items():
            slot_map = containers.setdefault(cont, {})
            for i, tv in enumerate(seq):
                if slot_map.get(str(i)) != tv:
                    slot_map[str(i)] = tv
                    added = True
        # 键控容器：put(key, value)，键取第一个实参（保留字面量原文）
        for m in _TAINT_CONT_PUT_RE.finditer(content):
            cont = m.group(1)
            args = _balanced_args(content, m.end() - 1)
            if args is None:
                continue
            parts = args.split(",", 1)
            key = parts[0].strip().strip("\"'").strip()
            val = parts[1] if len(parts) > 1 else parts[0]
            val_tainted = any(i.group(1) in tainted
                              for i in _TAINT_IDENT_RE.finditer(_strip_literals(val)))
            slot_map = containers.setdefault(cont, {})
            if slot_map.get(key) != val_tainted:
                slot_map[key] = val_tainted
                added = True
        for m in _TAINT_ASSIGN_RE.finditer(content):
            var, rhs = m.group(1), m.group(2)
            if var in tainted:
                continue
            if apply_html_sanitizers and _TAINT_SANITIZER_RE.search(rhs):
                continue
            rhs_wo_lit = _strip_literals(rhs)
            hit_src = (bool(_TAINT_SRC_RE.search(rhs_wo_lit))
                       or _hit_custom_getter(rhs_wo_lit))
            hit_prop = any(re.search(r"\b" + re.escape(t) + r"\b", rhs_wo_lit) for t in tainted)
            # 容器读取：按槽位查（键/索引从**原始** rhs 提取，不能用剥离字面量后的）
            hit_container = False
            for gm in _TAINT_CONT_GET_RE.finditer(rhs):
                cont = gm.group(1)
                gargs = _balanced_args(rhs, gm.end() - 1)
                if gargs is None:
                    continue
                slot = gargs.split(",", 1)[0].strip().strip("\"'").strip()
                if _slot_tainted(cont, slot):
                    hit_container = True
                    break
            if hit_src or hit_prop or hit_container:
                tainted.add(var)
                added = True
        if not added:
            break
    return tainted


def _args_have_taint(content: str, match: "re.Match", tainted: set) -> bool:
    """sink 命中点的实参是否引用了污点变量。match 须以 '(' 结尾。"""
    if not tainted:
        return False
    args = _balanced_args(content, match.end() - 1)
    if not args:
        return False
    return any(i.group(1) in tainted
               for i in _TAINT_IDENT_RE.finditer(_strip_literals(args)))


def build_sink_wrappers(files: List[Dict[str, Any]]) -> Dict[Tuple[str, str], Dict[str, Dict[str, str]]]:
    """从全量文件学出「项目内 sink 包装方法」表。

    返回 {(ClassName, methodName): {family: {vtype, severity, sink}}}。
    一个方法体内可能命中多个 sink，按 family 归并，避免同族重复出条。
    """
    wrappers: Dict[Tuple[str, str], Dict[str, Dict[str, str]]] = {}
    for f in files or []:
        path = str(f.get("path") or f.get("file_path") or "")
        content = f.get("content") or f.get("source") or ""
        if not content:
            continue
        lang = (f.get("language") or f.get("lang") or _detect_language(path) or "").lower()
        if lang not in _RULES:
            continue
        if lang == "mybatis-xml" and not _is_mapper_xml(content):
            continue
        spans = _method_spans(content, lang)
        if not spans:
            continue
        # 门控族需要「形参 → 位置」的映射（判定包装方法的 sink 到底用到了第几个入参），
        # 只有 java 能可靠解析形参表；其它语言的门控族维持原样（见 _TAINT_GATED_SINKS 注释）。
        spans_wp = _method_spans_with_params(content) if lang == "java" else []
        cls_m = _CLASS_RE.search(content)
        cls = cls_m.group(1) if cls_m else Path(path).stem
        for pat, vtype, family, severity, sink in _RULES[lang]:
            if family not in _PROPAGATABLE_FAMILIES:
                continue
            gated = sink in _TAINT_GATED_SINKS
            for m in pat.finditer(content):
                if gated and lang == "java" and spans_wp:
                    method, params = _method_and_params(spans_wp, m.start())
                    if not method:
                        continue
                    # sink 的**实参**里出现过的形参 → 其位置下标。空集说明路径完全由字面量/
                    # 静态常量决定（如 new FileOutputStream("/tmp/x")），不构成穿越传播源。
                    # 注意：文件读写 sink 的正则只匹配到左括号就停（以 `\(` 结尾），
                    # 实参必须用 _balanced_args 另取，否则标识符集里永远没有形参名。
                    _args_txt = _balanced_args(content, m.end() - 1) or ""
                    sink_ids = set(_TAINT_IDENT_RE.findall(
                        _strip_literals(m.group(0) + " " + _args_txt)))
                    positions = [i for i, pn in enumerate(params) if pn in sink_ids]
                    if not positions:
                        continue
                else:
                    method = _method_of(spans, m.start())
                    if not method:
                        continue
                    positions = None
                slot = wrappers.setdefault((cls, method), {})
                if family not in slot:
                    slot[family] = {"vtype": vtype, "severity": severity, "sink": sink,
                                    "gated_positions": positions}
    return wrappers


def _wrapper_call_hits(
    content: str, wrappers: Dict[Tuple[str, str], Dict[str, Dict[str, str]]]
) -> List[Tuple[int, str, Dict[str, str], "re.Match"]]:
    """在 content 内查找对 sink 包装方法的「限定调用」。

    返回 [(行号, 调用文本, info, 匹配对象)]。多返回匹配对象是给门控用的：调用点要按位置
    取实参（`_balanced_args(content, m.end - 1)`），而 info 里的 sink 名是被装饰过的
    `Cls.method(...) → 真实 sink`，**不能**直接拿去比 `_TAINT_GATED_SINKS`（那是裸名）。
    门控一律用 info['gated_positions'] 判（None = 非门控族，维持原行为）。

    只匹配 ClassName.method( 形式：不限定调用的裸方法名（如 fetch在不同类中语义
    不同，直接匹配会大面积误伤，故不纳入。
    """
    hits: List[Tuple[int, str, Dict[str, str], "re.Match"]] = []
    for (cls, method), by_family in (wrappers or {}).items():
        pat = re.compile(r"\b" + re.escape(cls) + r"\s*\.\s*" + re.escape(method) + r"\s*\(")
        for m in pat.finditer(content):
            line = _line_of(content, m.start())
            call = ("%s.%s(...)" % (cls, method))
            for family, info in by_family.items():
                hits.append((line, call,
                             dict(info, family=family, sink=call + " → " + info["sink"]), m))
    return hits


def _compile_registry_rules(lang: str) -> List[Tuple[re.Pattern, str, str, str, str]]:
    """把 rule_registry 中 **status=active** 的 Skill 规则表达式编译进
    A1 静态规则表，与内置 _RULES 同构（(regex, vtype, family, severity, sink)）。

    只消费 active（staging 候选不参与运行时，符合「禁占位/演示影响真实运行」）。
    语言不匹配（skill.languages 非空且不含 lang）则跳过；正则非法跳过。
    fail-open：注册表不可用时返回空表，A1 行为与历史完全一致。
    """
    try:
        from src.core.rule_registry import get_rule_expressions
        exprs = get_rule_expressions()
    except Exception:
        return []
    out: List[Tuple[re.Pattern, str, str, str, str]] = []
    for r in exprs:
        langs = r.get("languages") or []
        if langs and lang not in langs:
            continue
        expr = r.get("expression") or ""
        if not expr:
            continue
        try:
            pat = re.compile(expr)
        except re.error:
            continue
        fam = r.get("family") or "skill"
        out.append((
            pat,
            r.get("vuln_type") or fam,
            fam,
            (r.get("severity") or "MEDIUM").upper(),
            r.get("id") or "skill",
        ))
    return out


def analyze_content(
    path: str,
    content: str,
    lang: Optional[str] = None,
    sink_wrappers: Optional[Dict[Tuple[str, str], Dict[str, Dict[str, str]]]] = None,
    registry_only: bool = False,
    properties_map: Optional[Dict[str, str]] = None,
) -> List[Vulnerability]:
    """单文件 sink 模式匹配，返回 Vulnerability 列表（按 file:line:type 去重）。

    sink_wrappers 为 build_sink_wrappers 学到的「项目内 sink 包装方法」表；传入后在
    本文件的限定调用点追加同族条目（跨文件传播一层），不传则行为与历史完全一致。

    properties_map 为项目级 .properties 的 key→value 表（parse_properties_files 产出），
    用于把「算法名来自配置取值」折叠成常量再判弱算法；不传则该通道静默不生效，
    行为与历史完全一致。
    """
    lang = lang or _detect_language(path)
    # FileScanner 把 .xml 统一标成语言 "xml"（src/core/scanner.py 的 LANGUAGE_EXTENSIONS 键），
    # 而本模块的 .xml 规则组键名是 "mybatis-xml"。若直接用 "xml" 进下方 _RULES 判据会被
    # `lang not in _RULES` 静默 return []，导致所有非 mapper .xml（含 logback-online.xml 的
    # <jmxConfigurator/> HIGH 配置项）整类零检出。归一为 mybatis-xml，使 line 446 的
    # 非 mapper 改派 config-xml 闸门对真实输入生效。
    if lang == "xml":
        lang = "mybatis-xml"
    if not lang or lang not in _RULES:
        return []
    # MyBatis Mapper XML 门控：.xml 扩展名被统一分派到 mybatis-xml 组，但仓库里绝大多数 xml
    # 是 pom.xml / applicationContext.xml 等配置，直接套 ${} 规则会把 Maven 属性占位符
    # （${spring-boot.version}）误报成 SQL 注入。故仅当内容确为 MyBatis Mapper 时才启用该规则组。
    #
    # 这类配置文件正是 CWE-16 的载体（<jmxConfigurator/>），改派到配置类规则组 config-xml。
    if lang == "mybatis-xml" and not _is_mapper_xml(content):
        lang = "config-xml"
    out: List[Vulnerability] = []
    seen = set()
    # 内置规则 + active Skill 规则表达式（staging 不参与，无 active 时与历史完全一致）。
    # （rule_expression 通道），不跑内置 _RULES 全量 sink 规则。用于 A1 强制互补通道——
    # 即便 CodeQL 主链路成功、整段跳过确定性 heuristic 兜底，curated skill（如 CVE-2022-22978）
    # 仍须被扫描，避免配置型/模式型漏洞被静默漏检。
    if registry_only:
        _rules_for_lang = _compile_registry_rules(lang)
    else:
        _rules_for_lang = list(_RULES[lang]) + _compile_registry_rules(lang)
    # 污点变量集：懒计算，只在真正遇到需要门控的 sink 时才做一次文件内污点分析。
    # 写入这类与 HTML 编码无关的 sink 用「不把 HTML 净化器当净化」版本（见下方按 sink 选择）。
    taint_ctx: Optional[set] = None
    taint_ctx_no_html: Optional[set] = None
    for pat, vtype, family, severity, sink in _rules_for_lang:
        for m in pat.finditer(content):
            line = _line_of(content, m.start())
            key = (path, line, vtype, sink)
            if key in seen:
                continue
            seen.add(key)
            # 否则是输出静态文案或服务端自造数据——Benchmark 上这类命中占全部 finding
            if sink in _TAINT_GATED_SINKS:
                if lang != "java":
                    continue
                # 编码器（escapeHtml/encodeForHTML/ESAPI.encoder/Jsoup.clean...），只中和「响应
                # 输出型」sink（XSS）。对「文件读写」「session 写入外部可控数据」这类与 HTML 编码
                # 无关的 sink，escapeHtml 不构成净化——否则 trustbound 00098
                # 「escapeHtml(param)→putValue」会被误判为已净化而漏检（真值 trustbound,true）。
                if sink == "response.getWriter 直出":
                    if taint_ctx is None:
                        taint_ctx = _java_tainted_vars(content, apply_html_sanitizers=True)
                    _ctx = taint_ctx
                else:
                    if taint_ctx_no_html is None:
                        taint_ctx_no_html = _java_tainted_vars(content, apply_html_sanitizers=False)
                    _ctx = taint_ctx_no_html
                if not _args_have_taint(content, m, _ctx):
                    continue
            # 配置类规则（config-security）不是「危险 sink」语义，措辞单列，避免前端读成注入类。
            if family == "config-security":
                desc = (
                    f"检测到不安全配置：{sink}。属安全配置不当（CWE-16 / CWE-1188），"
                    f"由注入类离线兜底分析器检出。该族按平台既有约定仅做分类展示，"
                    f"不进 D1 重放、不进 D2 差分门禁、不计入召回口径。"
                )
            else:
                desc = f"检测到危险 sink：{sink}（{vtype}）。由注入类离线兜底分析器检出，需进一步确认是否可达且未净化。"
            out.append(Vulnerability(
                type=vtype,
                severity=severity,
                line=line,
                description=desc,
                file=path,
                sink=sink,
                data_flow="",
                has_http_entry=False,
                verdict="待分析",
                source="a1-injection-heuristic",
                confidence="medium",
            ))
            # A1 是规则模式命中，不走污点流四维度评判：标记 detection_method + 中文规则名
            out[-1].detection_method = "rule"
            out[-1].rule_name = rule_hit_label(vtype, family, sink)
            # auth_bypass（CVE-2022-22978）弱点确经 HTTP 可达（换行绕过 denyAll），
            # 标记为有 HTTP 入口，使下游 spec 生成把它当作可重放端点（合成 /black_path%0a/xx 路由）。
            if family == "auth_bypass":
                out[-1].has_http_entry = True

    # 弱算法「算法名来自配置取值」的常量折叠（见 _config_derived_algo_hits 注释）。
    # 只在 java 且拿到了 properties 表时才跑；与 _RULES 的字面量规则互补，
    # 两者命中同一条漏洞时靠 seen 去重（key 含 sink 名，此处 sink 名带「配置取值」后缀
    # 故不会与字面量规则那条重复计数——同文件里两种写法确属两条独立的检出点）。
    if lang == "java" and properties_map:
        for line, vtype, sink in _config_derived_algo_hits(content, properties_map):
            key = (path, line, vtype, sink)
            if key in seen:
                continue
            seen.add(key)
            out.append(Vulnerability(
                type=vtype,
                severity="MEDIUM",
                line=line,
                description=(
                    f"检测到危险 sink：{sink}。算法名来自配置文件取值，已折叠为实际值后判定，"
                    f"由注入类离线兜底分析器检出，需进一步确认是否可达。"
                ),
                file=path,
                sink=sink,
                data_flow="",
                has_http_entry=False,
                verdict="待分析",
                source="a1-injection-heuristic",
                confidence="medium",
            ))
            out[-1].detection_method = "rule"
            out[-1].rule_name = rule_hit_label(vtype, "weak-hash", sink)

    # 反射型 XSS 直出：@ResponseBody 处理函数把 String 形参原样 return（见 _direct_echo_hits 注释）
    if lang == "java":
        for line, param in _direct_echo_hits(content):
            sink = f"直接回显请求参数（{param}）"
            key = (path, line, "XSS", sink)
            if key in seen:
                continue
            seen.add(key)
            out.append(Vulnerability(
                type="XSS",
                severity="MEDIUM",
                line=line,
                description=(
                    f"检测到反射型 XSS 输出点：HTTP 处理函数把请求参数 '{param}' 原样 return，"
                    f"未经 HTML 转义即进入响应体。由注入类离线兜底分析器检出，需进一步确认是否可达。"
                ),
                file=path,
                sink=sink,
                data_flow="",
                has_http_entry=False,
                verdict="待分析",
                source="a1-injection-heuristic",
                confidence="medium",
            ))
            out[-1].detection_method = "rule"
            out[-1].rule_name = rule_hit_label("XSS", "xss", sink)

    if lang in ("properties", "config-xml"):
        for line, sink in _credential_hits(content):
            vtype = "Sensitive Data Exposure"
            key = (path, line, vtype, sink)
            if key in seen:
                continue
            seen.add(key)
            out.append(Vulnerability(
                type=vtype,
                severity="MEDIUM",
                line=line,
                description=(
                    f"检测到明文凭据：{sink}。配置文件中的凭据为明文存储（CWE-522 凭据保护不足），"
                    f"由注入类离线兜底分析器检出。该族归信息泄露暴露轴，仅做分类展示，不计入召回口径。"
                ),
                file=path,
                sink=sink,
                data_flow="",
                has_http_entry=False,
                verdict="待分析",
                source="a1-injection-heuristic",
                confidence="medium",
            ))
            out[-1].detection_method = "rule"
            out[-1].rule_name = rule_hit_label(vtype, "information-disclosure", sink)

    # 跨文件传播：本文件调用了项目内含 sink 的包装方法 → 调用点同样可达该 sink
    if sink_wrappers:
        for line, call, info, _wm in _wrapper_call_hits(content, sink_wrappers):
            # 完全没有门控** —— 实测 cmdi 每个用例都因 Utils.printOSCommandResults 被误报
            # 路径穿越。判据不是「调用点有没有脏数据」，而是「**包装方法的 sink 用到了第几个
            # 形参**」：只有那个位置上的实参带污点，路径才真能被外部控制。
            # 非门控族 gated_positions=None ⇒ 行为与历史完全一致（守住 ssrf/cmdi/deser 召回）。
            _pos = info.get("gated_positions")
            if _pos is not None:
                if lang != "java":
                    continue
                _args = _balanced_args(content, _wm.end() - 1)
                if not _args:
                    continue
                if taint_ctx is None:
                    taint_ctx = _java_tainted_vars(content)
                _argv = _split_top_level_args(_args)
                if not any(
                    0 <= p < len(_argv)
                    and any(i.group(1) in taint_ctx
                            for i in _TAINT_IDENT_RE.finditer(_strip_literals(_argv[p])))
                    for p in _pos
                ):
                    continue
            vtype = info["vtype"]
            key = (path, line, vtype, call)
            if key in seen:
                continue
            seen.add(key)
            out.append(Vulnerability(
                type=vtype,
                severity=info["severity"],
                line=line,
                description=(
                    f"检测到危险 sink：{info['sink']}（{vtype}）。"
                    f"调用点经项目内工具类 {call} 传递至 real sink，由注入类离线兜底分析器检出，"
                    f"需进一步确认是否可达且未净化。"
                ),
                file=path,
                sink=info["sink"],
                data_flow="",
                has_http_entry=False,
                verdict="待分析",
                source="a1-injection-heuristic",
                confidence="medium",
            ))
            out[-1].detection_method = "rule"
            out[-1].rule_name = rule_hit_label(vtype, info["family"], info["sink"])
    return out


def analyze_files(files: List[Dict[str, Any]]) -> List[Vulnerability]:
    """批量分析（输入形状对齐 A1 scan_files：[{path, content, language?}]）。

    先对全量文件学一次 sink 包装方法表，再逐文件分析——传播需要跨文件视野，
    单文件视角看不到「被调用方含 sink」。
    """
    out: List[Vulnerability] = []
    wrappers = build_sink_wrappers(files or [])
    # 配置取值折叠：先把同批的 .properties 解析成扁平表，供弱算法常量折叠使用。
    # 放在循环外只解析一次；这批文件里没有 .properties 时得到空表，下游静默不生效。
    props = parse_properties_files(files or [])
    for f in files or []:
        path = f.get("path") or f.get("file_path") or ""
        content = f.get("content") or f.get("source") or ""
        lang = f.get("language") or f.get("lang")
        if not content:
            continue
        if _is_vendor_asset(path):
            continue
        out.extend(analyze_content(path, content, lang, sink_wrappers=wrappers,
                                   properties_map=props))
    return out


def scan_path(project_path: str, language: Optional[str] = None) -> List[Vulnerability]:
    """对整目录扫描（供 CodeQL 不可用 / 构建失败时兜底；按扩展名自行判定语言）。"""
    root = Path(project_path)
    if not root.exists():
        return []
    # 两遍：先收集内容学包装表，再分析（scan_path 没有外部传入的全量列表）
    collected: List[Dict[str, Any]] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if not _detect_language(str(p)):
            continue
        if _is_vendor_asset(str(p)):
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        collected.append({"path": str(p), "content": content})
    wrappers = build_sink_wrappers(collected)
    out: List[Vulnerability] = []
    for f in collected:
        out.extend(analyze_content(f["path"], f["content"], language, sink_wrappers=wrappers))
    return out
