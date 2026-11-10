import pytest

from src.core import lifecycle


def test_normalize_defaults_to_open():
    assert lifecycle.normalize("") == lifecycle.OPEN
    assert lifecycle.normalize("bogus") == lifecycle.OPEN
    assert lifecycle.normalize("CONFIRMED") == lifecycle.CONFIRMED


def test_can_transition_rules():
    assert lifecycle.can_transition(lifecycle.OPEN, lifecycle.CONFIRMED)
    assert lifecycle.can_transition(lifecycle.RETESTING, lifecycle.FIXED)
    assert not lifecycle.can_transition(lifecycle.OPEN, lifecycle.FIXED)
    assert lifecycle.can_transition(lifecycle.CONFIRMED, lifecycle.CONFIRMED)


def test_ensure_transition_raises_on_illegal():
    assert lifecycle.ensure_transition(lifecycle.OPEN, lifecycle.CONFIRMED) == lifecycle.CONFIRMED
    with pytest.raises(ValueError):
        lifecycle.ensure_transition(lifecycle.OPEN, lifecycle.FIXED)


def test_status_for_human_decision():
    assert lifecycle.status_for_human_decision("true_positive") == lifecycle.CONFIRMED
    assert lifecycle.status_for_human_decision("false_positive") == lifecycle.FALSE_POSITIVE
    assert lifecycle.status_for_human_decision("uncertain") == ""


def test_status_for_retest_result():
    assert lifecycle.status_for_retest_result("fixed", lifecycle.RETESTING) == lifecycle.FIXED
    assert lifecycle.status_for_retest_result("still_vulnerable", lifecycle.RETESTING) == lifecycle.CONFIRMED
    assert lifecycle.status_for_retest_result("still_vulnerable", lifecycle.FIXED) == lifecycle.REOPENED
    assert lifecycle.status_for_retest_result("inconclusive", lifecycle.RETESTING) == lifecycle.RETESTING
