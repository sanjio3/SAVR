"""
Unified A2 facade.
"""
from typing import Dict, Optional

from .a2_intelligent_agent import A2SemanticAgent as _A2Implementation


class A2Agent(_A2Implementation):
    """Compatibility facade; prefer src.pipeline.a2.A2PipelineService for stage entry."""

    def __init__(self, config: Optional[Dict] = None, provider: str = "qwen"):
        super().__init__(config or {}, provider)
