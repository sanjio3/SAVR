# -*- coding: utf-8 -*-
"""A1 污点源：安全 getter 白名单回归锁。

背景（OWASP sqli-1/2/3 精确率天花板根因）：
    `SeparateClassRequest` 有三个同族 getter，源码注释明写
        // This method is a 'safe' source.
        public String getTheValue(String p) { return "bar"; }
    但 _TAINT_CUSTOM_GETTER_RE 的 `[Vv]alue` 分支只按名字匹配，
    把 getTheValue 当成外部输入 => param 被污点 => SQL 拼接被误报。

    实测（tools/sqli_feature_lift.py，三片一致）：
        特征 src_wrapper_safe 命中 18/18/14 个，纯度 0%、lift 0.00，
        是全片唯一「命中即 100% FP」的特征；
        剔除后 sqli-1/2/3 精确率 +6.6/+6.5/+4.8pt（合计 54.0%->59.9%），
        召回 100% 不变（零代价）。

本测试的作用是把这个判据钉死，防止后续有人放宽白名单或改回按名字匹配。
"""
from __future__ import annotations

import pytest

from src.agents.a1_injection_heuristic import (
    _hit_custom_getter,
    _java_tainted_vars,
)

SAFE_SRC = """
package org.owasp.benchmark.testcode;
public class BenchmarkTest00052 {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = scr.getTheValue("BenchmarkTest00052");
        String sql = "SELECT * from USERS where USERNAME='" + param + "'";
    }
}
"""

# 同族的真外部源：getTheParameter / getTheCookie 确实透传 request，必须仍判污点
EXT_SRC = """
package org.owasp.benchmark.testcode;
public class BenchmarkTest00053 {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = scr.getTheParameter("BenchmarkTest00053");
        String sql = "SELECT * from USERS where USERNAME='" + param + "'";
    }
}
"""

SAFE_COOKIE_SRC = """
package org.owasp.benchmark.testcode;
public class BenchmarkTest00054 {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = scr.getTheCookie("BenchmarkTest00054");
        String sql = "SELECT * from USERS where USERNAME='" + param + "'";
    }
}
"""


class TestSafeGetterWhitelist:
    def test_get_the_value_not_taint(self):
        """getTheValue 返回常量 "bar"，param 不得被污点。"""
        assert "param" not in _java_tainted_vars(SAFE_SRC)

    def test_get_the_parameter_still_taints(self):
        """反向锁：白名单不得放宽到 getTheParameter（它真透传 request）。"""
        assert "param" in _java_tainted_vars(EXT_SRC)

    def test_get_the_cookie_still_taints(self):
        assert "param" in _java_tainted_vars(SAFE_COOKIE_SRC)

    def test_hit_custom_getter_rejects_safe(self):
        assert _hit_custom_getter("scr.getTheValue(") is False
        assert _hit_custom_getter("scr.getTheValue( )") is False

    def test_hit_custom_getter_accepts_real_sources(self):
        assert _hit_custom_getter("scr.getTheParameter( )") is True
        assert _hit_custom_getter("scr.getTheCookie( )") is True
        assert _hit_custom_getter('request.getHeader("x")') is True

    def test_mixed_rhs_keeps_real_source(self):
        """一行里既有安全源又有真源时，必须仍然判污点（不能整行一票否决）。"""
        rhs = 'scr.getTheValue( ) + request.getParameter("x")'
        assert _hit_custom_getter(rhs) is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))