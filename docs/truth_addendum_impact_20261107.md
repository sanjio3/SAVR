# 影子真值口径影响面复算（只读）

> 口径：文中的数字是数据库里的运行轮次 ID，用于定位证据，不含工程流程编号。

主真值 `java_sec_code_truth_v2.csv`（in_scope 31 行）未修改；候选追加 `truth_addendum_l1_log4j_xss.csv` 共 1 行：
- log4j.java / xss（scope=in_scope，PROPOSED / NOT ADOPTED）

本报告是口径变更的决策依据，不是正式读数；`tools/jsc_four_tier.py` 不带 `--truth-addendum` 时的输出才是当前口径。

## jsc-r17k-final-20261106

- 主口径：静态族 30/31 · 动态分母 24 · 重放族 23/24 · 红线 0/57 · confirmed 误报 5/74
- 影子口径：静态族 31/32 · 动态分母 25 · 重放族 23/25 · 红线 0/57 · confirmed 误报 4/74
- 变化：真值行 +1、动态分母 +1、重放族命中 +0、重放率 -3.8pp、红线 0/57 → 0/57、confirmed 误报 5 → 4
- 主口径红线明细：无
- 影子口径红线明细：无（红线归零）

## jsc-r18-authguard-20261106

- 主口径：静态族 30/31 · 动态分母 24 · 重放族 23/24 · 红线 1/61 · confirmed 误报 7/81
- 影子口径：静态族 31/32 · 动态分母 25 · 重放族 23/25 · 红线 1/61 · confirmed 误报 6/81
- 变化：真值行 +1、动态分母 +1、重放族命中 +0、重放率 -3.8pp、红线 1/61 → 1/61、confirmed 误报 7 → 6
- 主口径红线明细：tomcatfiltermemshell.java/command_execution
- 影子口径红线明细：tomcatfiltermemshell.java/command_execution

## jsc-R0-redline-zero-20261106b

- 主口径：静态族 30/31 · 动态分母 24 · 重放族 24/24 · 红线 0/61 · confirmed 误报 6/78
- 影子口径：静态族 31/32 · 动态分母 25 · 重放族 24/25 · 红线 0/61 · confirmed 误报 5/78
- 变化：真值行 +1、动态分母 +1、重放族命中 +0、重放率 -4.0pp、红线 0/61 → 0/61、confirmed 误报 6 → 5
- 主口径红线明细：无
- 影子口径红线明细：无（红线归零）

## jsc-L1-blind-route-20261107

- 主口径：静态族 29/31 · 动态分母 24 · 重放族 21/24 · 红线 1/47 · confirmed 误报 5/59
- 影子口径：静态族 30/32 · 动态分母 25 · 重放族 22/25 · 红线 0/47 · confirmed 误报 4/59
- 变化：真值行 +1、动态分母 +1、重放族命中 +1、重放率 +0.5pp、红线 1/47 → 0/47、confirmed 误报 5 → 4
- 主口径红线明细：log4j.java/xss
- 影子口径红线明细：无（红线归零）
