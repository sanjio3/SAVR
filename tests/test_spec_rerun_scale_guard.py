"""闭环二次回灌「清库规模守卫」的回归锁（2026-10-07，r62 pathtraver-1 事故）。

背景：``auto_register_from_a2`` 在 second_pass 时先 ``DELETE FROM trigger_specs WHERE task_id=?``
再整体重登记。这条路径的正确性完全依赖「输入是全量」，但原先只校验了输入非空这一半。

实测后果：r62 的 pathtraver-1 分片清库前 156 条 spec、本轮只登记出 52 条，
未参与回灌的 104 条被永久清除，且不进任何 skipped 计数（静默丢失，含 33 条真值 TP，
召回 100%→54.2%，-45.8pp）。

本文件锁死「输入明显收窄时拒绝清库」这条不变式，防止守卫被删或判据写反。
判据实现在 ``_should_clear_specs_on_rerun``（抽成纯函数以便端到端之外也能单测）。
"""
import pytest

from src.iast.trigger_spec_registry import _should_clear_specs_on_rerun


# r62 pathtraver-1 的真实读数：清库前 156 条 spec、本轮登记输入 52 条。
BEFORE = 156
NARROW_INPUT = 52


def test_refuse_clear_when_input_is_narrow():
    """核心事故场景：输入 52 < 156 * 0.5 = 78 ⇒ 拒绝清库。"""
    assert _should_clear_specs_on_rerun(BEFORE, NARROW_INPUT, 0.5) is False


def test_allow_clear_when_input_is_full_scale():
    """输入是全量（甚至更多）⇒ 允许清库。"""
    assert _should_clear_specs_on_rerun(BEFORE, 156, 0.5) is True
    assert _should_clear_specs_on_rerun(BEFORE, 300, 0.5) is True


def test_allow_clear_when_no_history_specs():
    """首次登记（history=0）清库无损失 ⇒ 必须放行，否则首轮登记会被误拒。"""
    assert _should_clear_specs_on_rerun(0, 0, 0.5) is True
    assert _should_clear_specs_on_rerun(0, 10, 0.5) is True


def test_boundary_is_inclusive():
    """边界取「>=」：正好等于 50% 视为全量，放行。"""
    assert _should_clear_specs_on_rerun(BEFORE, 78, 0.5) is True
    assert _should_clear_specs_on_rerun(BEFORE, 77, 0.5) is False


def test_ratio_is_configurable():
    """比例可配（SAST_AI_SPEC_RERUN_MIN_RATIO）：收紧到 0.9 时 140/156 也会被拒。"""
    assert _should_clear_specs_on_rerun(BEFORE, 140, 0.9) is False
    assert _should_clear_specs_on_rerun(BEFORE, 141, 0.9) is True
    # 放宽到 0.1 时，连 52 条这种明显收窄的输入也放行（逃生口，不推荐）。
    assert _should_clear_specs_on_rerun(BEFORE, NARROW_INPUT, 0.1) is True


def test_ratio_zero_disables_guard():
    """ratio<=0 显式关守卫：无条件放行（保留运维逃生口）。"""
    assert _should_clear_specs_on_rerun(BEFORE, 1, 0.0) is True
    assert _should_clear_specs_on_rerun(BEFORE, 1, -1.0) is True


@pytest.mark.parametrize("before,input_rows", [("156", "52"), (156.0, 0), (156, None)])
def test_tolerates_dirty_types(before, input_rows):
    """脏入参（字符串 / 浮点 / None）不得抛异常，且必须落到「拒绝」这一安全侧。"""
    assert _should_clear_specs_on_rerun(before, input_rows, 0.5) is False


def test_unknown_history_defaults_to_allow():
    """before 取不到（None/0）按「无历史」处理：清库无损失，放行。

    这与上一条不矛盾——守卫只在**已知有历史 spec** 时才介入；取不到计数不应
    反过来把首轮登记也挡住。
    """
    assert _should_clear_specs_on_rerun(None, 0, 0.5) is True
    assert _should_clear_specs_on_rerun(None, 100, 0.5) is True


def test_default_ratio_matches_env_default():
    """生产侧 env 默认值是 0.5，函数默认参数必须与之对齐，否则 env 未设时行为漂移。"""
    import os

    env_default = float(os.environ.get("SAST_AI_SPEC_RERUN_MIN_RATIO", "0.5"))
    import inspect

    sig_default = inspect.signature(_should_clear_specs_on_rerun).parameters["min_ratio"].default
    assert sig_default == env_default == 0.5
