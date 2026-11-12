from src.domain.models import Workspace
from src.infrastructure.repositories import WorkspaceRepository
from src.pipeline.a0.service import A0PreprocessService


class WorkspaceService:
    def __init__(self, repository: WorkspaceRepository, preprocess: A0PreprocessService):
        self.repository = repository
        self.preprocess = preprocess

    def list_workspaces(self, include_archived: bool = False):
        return self.repository.list(include_archived=include_archived)

    def get_workspace(self, workspace_id: int):
        return self.repository.get(workspace_id)

    def create_workspace(self, payload: dict):
        workspace = Workspace(
            id=None,
            name=payload["name"],
            target_path=payload["target_path"],
            description=payload.get("description", ""),
            settings=payload.get("settings", {}),
        )
        # 先建项目，路径可暂不存在（strict=False）；真正扫描时再严格校验。
        validation = self.preprocess.validate_workspace_path(workspace, strict=False)
        if validation["status"] != "ok":
            raise ValueError(validation["message"])
        return self.repository.create(workspace)

    def update_workspace(self, workspace_id: int, payload: dict):
        current = self.repository.get(workspace_id)
        if current is None:
            raise ValueError(f"Workspace {workspace_id} not found")
        merged = {
            "name": payload.get("name", current.name),
            "target_path": payload.get("target_path", current.target_path),
            "description": payload.get("description", current.description),
            "slug": payload.get("slug"),
            "settings": {**current.settings, **(payload.get("settings") or {})},
        }
        validation = self.preprocess.validate_workspace_path(
            Workspace(
                id=current.id,
                name=merged["name"],
                target_path=merged["target_path"],
                description=merged["description"],
                settings=merged["settings"],
            ),
            strict=False,
        )
        if validation["status"] != "ok":
            raise ValueError(validation["message"])
        return self.repository.update(workspace_id, merged)

    def archive_workspace(self, workspace_id: int):
        workspace = self.repository.get(workspace_id)
        if workspace is None:
            raise ValueError(f"Workspace {workspace_id} not found")
        settings = {**workspace.settings, "archived": True}
        return self.repository.update(workspace_id, {"settings": settings})

    def unarchive_workspace(self, workspace_id: int):
        workspace = self.repository.get(workspace_id)
        if workspace is None:
            raise ValueError(f"Workspace {workspace_id} not found")
        settings = {**workspace.settings, "archived": False}
        return self.repository.update(workspace_id, {"settings": settings})

    def delete_workspace(self, workspace_id: int):
        workspace = self.repository.get(workspace_id)
        if workspace is None:
            raise ValueError(f"Workspace {workspace_id} not found")
        self.repository.delete(workspace_id)
