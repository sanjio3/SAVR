# 历史复盘归档

本目录只保留发布前基准实验的两篇无效轮复盘。它们记录的是门禁漏检与靶场被并发会话抢占这两类真实缺陷，以及由此收紧的判定口径，属于工程复盘，不是当前验收读数。

- `l3_run2_invalid_round_postmortem.md`：一轮被并发靶场污染的无效轮，以及旧判定脚本为何把它误判为有效。
- `r0prime_invalid_round_postmortem.md`：早期无效轮的证据链与口径冲突。

当前权威读数见根目录 `README.md` 与 `README_zh.md` 的结果章节，复算所需的真值表随仓库分发。其余各轮对账文档已在开源整理时从发布树移除；`config/generalization.yaml` 里保留的 `reconciliation` 字段是当时的证据指针，作为历史索引存在，不指向现行文件。

新的测试结果不写入本目录：CI 的 JUnit XML 与运行页面摘要是唯一出口。
