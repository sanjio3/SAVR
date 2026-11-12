from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Sequence


@dataclass(frozen=True)
class StageSkill:
    name: str
    responsibility: str
    implementation: str


@dataclass(frozen=True)
class StageTool:
    name: str
    responsibility: str
    kind: str = "internal"
    path: Optional[str] = None


@dataclass(frozen=True)
class StageManifest:
    stage_name: str
    implementation: str
    skills: Sequence[StageSkill] = field(default_factory=tuple)
    tools: Sequence[StageTool] = field(default_factory=tuple)

    def resource_paths(self) -> List[Path]:
        paths: List[Path] = []
        for tool in self.tools:
            if tool.path:
                paths.append(Path(tool.path))
        return paths


@dataclass
class StageService:
    manifest: StageManifest
    factory: Callable[[], object]

    def create(self) -> object:
        return self.factory()
