"""BOLA / RACE 路径正式落地（重构文档 §2.2 / §7.9 / §8.1）。

此前为占位；现已落地：SAST 业务逻辑策略分析（a1_bola_analyzer）产出 BOLA 假说，
D1 操作器做多身份重放（BOLA）与并发重放（RACE）的运行时影响验证。IAST 探针侧
authz/race 钩子属 Java 探针扩展（手册 3.11），不在 Python 侧实现，本模块只编排 Python 侧链路。
"""
from typing import Any, Dict, List, Optional

from src.agents.a1_bola_analyzer import analyze_sources as _analyze_bola
from src.application.d1_service import D1Service


def bola_race_status() -> Dict[str, Any]:
    """真实能力状态（取代占位）。"""
    return {
        "status": "delivered",
        "delivered": True,
        "bola": {
            "supported": True,
            "method": "SAST 策略分析(识别敏感操作+缺失归属校验) + D1 多身份重放验证",
        },
        "race": {
            "supported": True,
            "method": "DAST 并发重放(RACE 第二信号)，不变量由 spec 提供交 I2/人工判定",
        },
        "design_notes": [
            "SAST-seeded：BOLA 假说由 SAST 业务逻辑分析产出，D1 只做运行时影响验证",
            "关联键 (appName) + (resourceKey=entityType:id) + (principal)",
            "RACE 第二信号由 DAST 并发重放提供",
        ],
    }


def analyze_bola(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """SAST 业务逻辑策略分析：源文件 → BOLA 假说清单。"""
    return _analyze_bola(files)


def verify_bola(trigger_spec: Dict[str, Any], target: Dict[str, Any],
                accounts: Any = None, db: Any = None) -> Dict[str, Any]:
    """D1 多身份重放验证 BOLA 假说（运行时影响证明）。"""
    svc = D1Service(db=db)
    return svc.replay_bola(trigger_spec, target, accounts=accounts)


def verify_race(trigger_spec: Dict[str, Any], target: Dict[str, Any],
                concurrency: int = 5, accounts: Any = None, db: Any = None) -> Dict[str, Any]:
    """DAST 并发重放验证 RACE 假说（运行时影响证明）。"""
    svc = D1Service(db=db)
    return svc.replay_race(trigger_spec, target, concurrency=concurrency, accounts=accounts)
