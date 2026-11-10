"""
Ground Truth 定义 - java-sec-code 已知漏洞
"""
from typing import Dict, List


# java-sec-code 项目中的真实漏洞
# 格式: {file_path: [漏洞类型列表]}
GROUND_TRUTH = {
    # SQL Injection
    'org/joychou/controller/SQLI.java': [
        'SQL Injection', 'SQL Injection', 'SQL Injection'
    ],
    'org/joychou/controller/Jdbc.java': [
        'SQL Injection', 'SQL Injection'
    ],
    'org/joychou/dao/UserMapper.java': [
        'SQL Injection'
    ],

    # Command Injection
    'org/joychou/controller/CommandInject.java': [
        'Command Injection', 'Command Injection'
    ],

    # XXE
    'org/joychou/controller/XXE.java': [
        'XXE'
    ],
    'org/joychou/controller/othervulns/ooxmlXXE.java': [
        'XXE'
    ],

    # SSRF
    'org/joychou/controller/SSRF.java': [
        'SSRF', 'SSRF'
    ],

    # Path Traversal
    'org/joychou/controller/PathTraversal.java': [
        'Path Traversal'
    ],

    # XSS
    'org/joychou/controller/XSS.java': [
        'XSS', 'XSS'
    ],

    # File Upload
    'org/joychou/controller/FileUpload.java': [
        'File Upload'
    ],

    # Deserialization
    'org/joychou/controller/Deserialize.java': [
        'Deserialization'
    ],
    'org/joychou/controller/Fastjson.java': [
        'Deserialization'
    ],

    # RCE
    'org/joychou/controller/Rce.java': [
        'Command Injection', 'Deserialization'
    ],
    'org/joychou/controller/Log4j.java': [
        'Log4j RCE'
    ],

    # URL Redirect
    'org/joychou/controller/URLRedirect.java': [
        'URL Redirect'
    ],

    # SpEL Injection
    'org/joychou/controller/SpEL.java': [
        'SpEL Injection'
    ],

    # SSTI
    'org/joychou/controller/SSTI.java': [
        'SSTI'
    ],

    # JSONP
    'org/joychou/controller/Jsonp.java': [
        'JSONP'
    ],

    # CRLF Injection
    'org/joychou/controller/CRLFInjection.java': [
        'CRLF Injection'
    ],

    # JWT
    'org/joychou/controller/Jwt.java': [
        'JWT Weak Secret'
    ],

    # XStream RCE
    'org/joychou/controller/XStreamRce.java': [
        'XStream RCE'
    ],

    # Shiro
    'org/joychou/controller/Shiro.java': [
        'Shiro'
    ],

    # QLExpress
    'org/joychou/controller/QLExpress.java': [
        'QLExpress Injection'
    ],
}


def get_ground_truth() -> Dict[str, List[str]]:
    """获取 Ground Truth"""
    return GROUND_TRUTH


def get_all_vulnerability_types() -> List[str]:
    """获取所有漏洞类型"""
    types = set()
    for vulns in GROUND_TRUTH.values():
        types.update(vulns)
    return sorted(list(types))


def count_total_vulnerabilities() -> int:
    """统计总漏洞数"""
    return sum(len(vulns) for vulns in GROUND_TRUTH.values())
