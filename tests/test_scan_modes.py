from src.pipeline.a2.service import (
    SCAN_MODE_FILTER_FIRST,
    SCAN_MODE_HYBRID,
    SCAN_MODE_PURE_AI,
    A2PipelineService,
)


def _make_files(count: int) -> list[dict]:
    files = []
    for i in range(count):
        # A minority live under key directories with clear sink/source signals.
        if i % 10 == 0:
            files.append({
                "rel_path": f"src/api/controller/handler_{i}.py",
                "content": "value = request.args.get('id')\nos.system(value)\n",
            })
        else:
            files.append({
                "rel_path": f"src/util/plain_{i}.py",
                "content": f"# helper module {i}\nx = {i}\n",
            })
    return files


def test_pure_ai_focus_count_ge_filter_first():
    files = _make_files(600)  # exceeds default max_files=240
    pure = A2PipelineService._select_focus_files(files, scan_mode=SCAN_MODE_PURE_AI)
    filtered = A2PipelineService._select_focus_files(files, scan_mode=SCAN_MODE_FILTER_FIRST)
    assert len(pure) == 600
    assert len(filtered) == 240
    assert len(pure) >= len(filtered)


def test_hybrid_keeps_key_dir_files_and_caps_others():
    files = _make_files(600)
    hybrid = A2PipelineService._select_focus_files(files, scan_mode=SCAN_MODE_HYBRID)
    filtered = A2PipelineService._select_focus_files(files, scan_mode=SCAN_MODE_FILTER_FIRST)
    key_files = [f for f in files if A2PipelineService._is_key_dir(f)]
    hybrid_paths = {f["rel_path"] for f in hybrid}
    # Every key-directory file survives hybrid selection.
    for kf in key_files:
        assert kf["rel_path"] in hybrid_paths
    # Hybrid never exceeds the max budget and sits between filter_first and pure_ai.
    assert len(hybrid) <= 240
    assert len(hybrid) >= len(key_files)
    assert len(filtered) == 240


def test_small_repo_all_modes_return_everything():
    files = _make_files(50)  # below max_files
    for mode in (SCAN_MODE_FILTER_FIRST, SCAN_MODE_PURE_AI, SCAN_MODE_HYBRID):
        selected = A2PipelineService._select_focus_files(files, scan_mode=mode)
        assert len(selected) == 50


def test_estimate_cost_monotonic_with_scale():
    small = A2PipelineService.estimate_cost(_make_files(100), scan_mode=SCAN_MODE_PURE_AI, provider="qwen")
    large = A2PipelineService.estimate_cost(_make_files(300), scan_mode=SCAN_MODE_PURE_AI, provider="qwen")
    assert large["estimated_tokens"] > small["estimated_tokens"]
    assert large["estimated_cost"] >= small["estimated_cost"]
    assert small["focus_files"] == 100
    assert large["focus_files"] == 300


def test_estimate_cost_pure_ai_ge_filter_first():
    files = _make_files(600)
    pure = A2PipelineService.estimate_cost(files, scan_mode=SCAN_MODE_PURE_AI, provider="qwen")
    filtered = A2PipelineService.estimate_cost(files, scan_mode=SCAN_MODE_FILTER_FIRST, provider="qwen")
    assert pure["focus_files"] >= filtered["focus_files"]
    assert pure["estimated_tokens"] >= filtered["estimated_tokens"]


def test_unknown_mode_falls_back_to_filter_first():
    files = _make_files(600)
    fallback = A2PipelineService._select_focus_files(files, scan_mode="bogus")
    assert len(fallback) == 240
