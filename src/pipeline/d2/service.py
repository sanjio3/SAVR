from typing import Dict, Optional

from src.agents.d2_facade import create_d2_agent
from src.pipeline.d2.manifest import D2_MANIFEST
from src.pipeline.stage_contract import StageService


class D2PipelineService(StageService):
    stage_name = "d2"

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        super().__init__(manifest=D2_MANIFEST, factory=lambda: create_d2_agent(self.config))

    def verifier(self):
        return self.create()
