"""
Shared result normalization helpers for D2.
"""
import json
from typing import Any, Dict, List


class D2ResultNormalizerMixin:
    @staticmethod
    def _parse_raw_output_payload(raw_output: str) -> Dict[str, Any]:
        if not raw_output:
            return {}
        try:
            payload = json.loads(raw_output)
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def _coerce_string_list(value: Any) -> List[str]:
        if isinstance(value, list):
            return [str(item) for item in value if str(item).strip()]
        if isinstance(value, str) and value.strip():
            try:
                decoded = json.loads(value)
                if isinstance(decoded, list):
                    return [str(item) for item in decoded if str(item).strip()]
            except Exception:
                pass
            return [value]
        return []

