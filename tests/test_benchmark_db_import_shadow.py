"""回归测试：禁止在 run_benchmark 函数体内使用 in-function `from ... import Database`。

历史事故（task-8 全空）：benchmark_cli.run_benchmark 内曾在 2675/2805 行用
`from src.infrastructure.db import Database`（同时模块顶部 line 83 已全局导入 Database）。
Python 会把函数体内的 `from ... import Database` 当作该函数的局部名，导致同一函数里
更早执行的 `Database(...)` 引用（如 2514 行的 IDOR 块、2871/2877 行的 reporting 块）
在那些 in-function import 尚未执行的代码路径上抛出
`UnboundLocalError: cannot access local variable 'Database' where it is not associated with a value`。

该 bug 只在「a1/a2 真实产出假说 → 触发 IDOR/reporting 路径」时复现，排查极难。
修复方式：删除 run_benchmark 内的 in-function `from ... import Database`，统一走模块级全局导入。

本测试静态断言 run_benchmark 函数体源码中不再出现该 in-function import，防止复发。
"""

import inspect

from src.cli.benchmark_cli import run_benchmark


def test_run_benchmark_has_no_in_function_database_import():
    src = inspect.getsource(run_benchmark)
    assert "from src.infrastructure.db import Database" not in src, (
        "run_benchmark 函数体内出现了 in-function `from ... import Database`，"
        "这会引发 Database 局部阴影 UnboundLocalError（见 2026-08-29 task-8 事故）。"
        "请删除该 in-function import，统一使用模块级全局导入。"
    )


def test_database_is_module_global_in_benchmark_cli():
    import src.cli.benchmark_cli as mod

    assert hasattr(mod, "Database"), (
        "benchmark_cli 模块级必须保留 `from src.infrastructure.db import Database` 全局导入，"
        "否则 run_benchmark 内的所有 Database(...) 引用都会 NameError。"
    )
