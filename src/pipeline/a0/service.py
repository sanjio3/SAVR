from pathlib import Path
from typing import Dict
import shutil

from src.domain.models import Workspace


class A0PreprocessService:
    def build_output_dir(self, workspace: Workspace, task_id: int) -> str:
        safe_name = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in workspace.name).strip("_") or "workspace"
        return str(Path("data") / "workspaces" / safe_name / f"task-{task_id}")

    def validate_workspace_path(self, workspace: Workspace, strict: bool = True) -> Dict[str, str]:
        # strict=True（默认）：路径必须存在且为目录，用于扫描执行前的硬校验。
        # strict=False：允许先建项目、稍后补路径（路径可以暂不存在），用于创建/更新 workspace、创建 task。
        #   仅保留两类硬错误：① 路径为空（连目标都没填，无法扫描）；② 路径存在但不是目录（明显错填成文件）。
        #   路径不存在在 strict=False 时不拦截——真正的扫描执行阶段仍会以 strict=True 兜底校验。
        if not workspace.target_path:
            return {"status": "error", "message": "Workspace target path is required"}
        path = Path(workspace.target_path)
        if strict and not path.exists():
            return {"status": "error", "message": f"Workspace target path does not exist: {path}"}
        if path.exists() and not path.is_dir():
            return {"status": "error", "message": f"Workspace target path is not a directory: {path}"}
        return {"status": "ok", "message": str(path)}

    def reset_directory(self, path: Path) -> None:
        if path.exists():
            shutil.rmtree(path)
