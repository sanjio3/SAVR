"""IastService._resolve_workspace 的路径归一化回归锁。

背景（2026-10-06 实踩）：workspace 7 的 target_path 建档时写成正斜杠
`D:/Users/.../BenchmarkJava-master`，而探针 / Java 侧上报的必然是平台原生分隔符
`D:\\Users\\...`。原实现直接字符串比较，于是注册抛
「code_path 与该 workspace_id 已绑定到其他路径，拒绝跨 workspace 重绑」，
把一个纯分隔符差异报成"重绑"，指向完全错误的方向，靶场起不来且极难自查。

同一函数里还踩了第二个坑：项目的 Database.execute 把 fetchone/fetchall 做成
keyword-only 参数，不传时返回 None，`.fetchall()` 直接 AttributeError。

这里锁住：分隔符差异必须视为同一路径；真正的路径差异仍然必须拒绝。
"""

import os

import pytest

LOCAL_ROOT = os.environ.get("SAST_AI_SDL_ROOT", "")
pytestmark = [
    pytest.mark.external,
    pytest.mark.skipif(
        not LOCAL_ROOT,
        reason="external target sources required: set SAST_AI_SDL_ROOT to your local targets root",
    ),
]

import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.infrastructure.db import Database  # noqa: E402
from src.iast.service import IastService  # noqa: E402


def _svc(tmp_path) -> IastService:
    return IastService(Database(str(tmp_path / "app.db")))


def test_backslash_matches_forward_slash(tmp_path):
    """核心回归：正斜杠建档 + 反斜杠注册 => 必须复用同一个 workspace。"""
    svc = _svc(tmp_path)
    ws = svc._resolve_workspace(os.path.join(LOCAL_ROOT, "owasp-code", "BenchmarkJava-master"), None)
    assert ws["new"] is True
    again = svc._resolve_workspace(
        os.path.join(LOCAL_ROOT, "owasp-code", "BenchmarkJava-master"), None)
    assert again["new"] is False
    assert again["id"] == ws["id"]


def test_explicit_workspace_id_accepts_other_separator(tmp_path):
    """显式 workspace_id + 分隔符不同的 code_path => 不该抛「拒绝重绑」。"""
    svc = _svc(tmp_path)
    ws = svc._resolve_workspace("D:/repo/full", None)
    hit = svc._resolve_workspace("D:\\repo\\full", ws["id"])
    assert hit["id"] == ws["id"]
    assert hit["new"] is False


def test_explicit_workspace_id_rejects_real_mismatch(tmp_path):
    """真正的路径差异仍必须拒绝（归一化不能把防搬家守卫一起废掉）。"""
    svc = _svc(tmp_path)
    ws = svc._resolve_workspace("D:/repo/a", None)
    with pytest.raises(ValueError) as exc:
        svc._resolve_workspace("D:/repo/b", ws["id"])
    # 报错必须带上双方路径，否则又是"指向错误方向的老问题"
    assert "repo/a" in str(exc.value) and "repo/b" in str(exc.value)


def test_trailing_slash_is_not_a_difference(tmp_path):
    svc = _svc(tmp_path)
    ws = svc._resolve_workspace("D:/repo/full/", None)
    hit = svc._resolve_workspace("D:\\repo\\full", None)
    assert hit["id"] == ws["id"]


def test_case_insensitive_on_windows_paths(tmp_path):
    """Windows 上路径不区分大小写；否则换个盘符大小写就得重新建档。"""
    svc = _svc(tmp_path)
    ws = svc._resolve_workspace("D:/Repo/Full", None)
    hit = svc._resolve_workspace("d:\\repo\\full", None)
    assert hit["id"] == ws["id"]


def test_empty_code_path_does_not_match_everything(tmp_path):
    """入参为空时不能匹配到任意已有 workspace（否则静默串到别的资产上）。"""
    svc = _svc(tmp_path)
    ws = svc._resolve_workspace("D:/repo/full", None)
    fresh = svc._resolve_workspace("", None)
    assert fresh["id"] != ws["id"]
