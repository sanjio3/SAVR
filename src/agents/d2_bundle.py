"""
Shared D2 bundle/result helpers.
"""
import json
from pathlib import Path
from typing import Any, Dict


class D2BundleMixin:
    @staticmethod
    def _load_exploit_result_file(result_file: Path) -> Dict[str, Any]:
        if not result_file or not result_file.exists():
            return {}
        try:
            return json.loads(result_file.read_text(encoding="utf-8"))
        except Exception:
            return {}

    @staticmethod
    def _build_raw_output(payload: Dict[str, Any]) -> str:
        return json.dumps(payload, ensure_ascii=False)
