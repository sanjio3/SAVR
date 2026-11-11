from .a1 import A1_MANIFEST, A1PipelineService
from .a2 import A2_MANIFEST, A2PipelineService
from .d2 import D2_MANIFEST, D2PipelineService


STAGE_MANIFESTS = {
    "a1": A1_MANIFEST,
    "a2": A2_MANIFEST,
    "d2": D2_MANIFEST,
}


def get_stage_manifest(stage_name: str):
    return STAGE_MANIFESTS[stage_name]


__all__ = [
    "A1_MANIFEST",
    "A1PipelineService",
    "A2_MANIFEST",
    "A2PipelineService",
    "D2_MANIFEST",
    "D2PipelineService",
    "STAGE_MANIFESTS",
    "get_stage_manifest",
]
