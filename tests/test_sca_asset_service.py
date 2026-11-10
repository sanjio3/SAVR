
from pathlib import Path

from src.application.sca_asset_service import SCAAssetService
from src.infrastructure.db import Database


def test_sca_asset_service_discovers_persists_and_queries_impact(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("flask==2.0.0\nrequests>=2.31.0\n", encoding="utf-8")
    db = Database(str(tmp_path / "app.db"))
    service = SCAAssetService(db, output_root=str(tmp_path / "sca"))

    result = service.scan_project(str(project), workspace_id=1, task_id=7, run_tool=False, persist=True)

    assert result["status"] == "completed"
    assert result["component_count"] == 2
    assert Path(result["sbom_path"]).exists()
    components = service.list_components(workspace_id=1, name="flask")
    assert components[0]["ecosystem"] == "PyPI"
    assert components[0]["name"] == "flask"
    impact = service.impact_query({"workspace_id": 1, "component_name": "flask"})
    assert impact["affected_component_count"] == 1
