import json
import subprocess
import sys
from pathlib import Path

from src.cli.benchmark_cli import _decompile_jar_source_tree, _filter_framework_noise_files


def test_decompile_jar_source_tree_uses_local_cfr(tmpdir, monkeypatch):
    tmp_path = Path(str(tmpdir))
    target = tmp_path / "source"
    target.mkdir()
    (target / "app.jar").write_text("jar", encoding="utf-8")
    (target / "cfr-0.152.jar").write_text("cfr", encoding="utf-8")
    output_dir = tmp_path / "out"

    def fake_run(command, **kwargs):
        output_index = command.index("--outputdir") + 1
        decompiled_dir = Path(command[output_index])
        decompiled_dir.mkdir(parents=True, exist_ok=True)
        (decompiled_dir / "Example.java").write_text("class Example {}", encoding="utf-8")

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return Result()

    monkeypatch.setattr("src.cli.benchmark_cli.subprocess.run", fake_run)

    decompiled = _decompile_jar_source_tree(str(target), str(output_dir))
    assert decompiled is not None
    assert (decompiled / "Example.java").exists()


def test_scan_task_runner_no_files_returns_structured_error(tmpdir):
    tmp_path = Path(str(tmpdir))
    target = tmp_path / "empty"
    target.mkdir()
    output_dir = tmp_path / "out"
    repo_root = Path(__file__).resolve().parents[1]

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.cli.scan_task_runner",
            "--task-id",
            "321",
            "--target",
            str(target),
            "--output-dir",
            str(output_dir),
            "--output-format",
            "json",
        ],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        timeout=120,
    )

    assert proc.returncode != 0
    payload = json.loads((output_dir / "task_result.json").read_text(encoding="utf-8"))
    assert payload["task_id"] == 321
    assert "No files found to scan" in payload["error"]
    assert "NoneType" not in payload["error"]


def test_filter_framework_noise_files_skips_spring_boot_loader_classes():
    files = [
        {"rel_path": "org/springframework/boot/loader/net/protocol/nested/NestedLocation.java"},
        {"rel_path": "com/ctf/gateway/controller/GatewayController.java"},
    ]

    filtered = _filter_framework_noise_files(files)

    assert len(filtered) == 1
    assert filtered[0]["rel_path"] == "com/ctf/gateway/controller/GatewayController.java"
