# polyglot-audit 发布清单（RELEASE-CHECKLIST）

对应需求：DSR-051 / DSR-080 / SWR-012 / SWR-026。门禁定义来源：`docs/design/SOFTWARE_DESIGN_REVIEW.md` §3（GATE-01～07）与 `docs/design/SOFTWARE_DESIGN.md` §8（G0～G4）。

**使用规则**：全部开发完成后统一测试（`python3 tools/run_all_tests.py`），用实测结论填写下表"证据/结果"列；评估器入口为 `auditkit.app.release.ReleaseGateEvaluator`（每条 GATE 一个检查函数，输出 pass/fail/not_applicable + reason）。**任一必需能力为 unknown → 该组合不标受支持 / 阻止发布**。失败进入修复与重测，而不是宣称完成。

---

## 1. 运行内门禁 G0～G4（每次 run 由 finalize 自动评估）

| 门禁 | 内容 | 证据占位（统一测试后填写） | 结果 |
|---|---|---|---|
| G0 | 快照、清点与规划完整性（manifest/plan/revision 对账） | tests/snapshot + tests/ledger 结果：`____` | `pass / fail / not_applicable` |
| G1 | 任务/覆盖记账（units、overflow、incomplete 计数） | tests/ledger/test_service_finalize + tests/analysis 结果：`____` | `____` |
| G2 | 调度对账（submitted vs dispatched）与 finding 语义结构 | tests/analysis（verifier/dedup/guards）结果：`____` | `____` |
| G3 | 语义验证通过率记账与报告/账本对账 | tests/reporting 黄金报告对比：`____` | `____` |
| G4 | revision/产物一致性与导出脱敏 | tests/security（导出边界）结果：`____` | `____` |

每条门禁须有正常与必须失败两类测试；not_applicable 必须附明确理由（DSR-022）。

## 2. 发布门禁 GATE-01～07（统一测试后填写，ReleaseGateEvaluator 输入）

| 门禁 | 关闭证据要求 | 证据占位（文件/测试/矩阵） | 状态 |
|---|---|---|---|
| GATE-01 | 明确受支持的 Claude/Codex 版本，并在真实宿主验证结构化结果、配置加载、委派、只读/执行/网络和认证 | capability_matrix：`docs/evidence/gate01-capability-matrix.json`（占位）；实测记录：`____` | `unknown` |
| GATE-02 | 并发/崩溃/迟到提交及快照竞态夹具验证一致性；给出文件系统适用范围 | tests/ledger/test_atomicity、concurrency 夹具结果：`____`；适用范围说明：`____` | `unknown` |
| GATE-03 | 宿主证据证明 token/费用最坏上限与用量完整性，或只发布明确的软预算/任务预算模式 | 预算模式声明与宿主用量证据：`____` | `unknown` |
| GATE-04 | 逐语言评审 150 类公开依据、适用性与正反例；实际测量跨单元与留出语料 | 15×10 卡片评审记录：`____`；留出语料测量：`____` | `unknown` |
| GATE-05 | 规定机器、文件分布、预算与统计口径下测量性能/成本/覆盖；公布缺失数据 | tests/performance 结果：`____`；机器与口径说明：`____` | `unknown` |
| GATE-06 | 明确导出字段、敏感性、人工审核责任与失败关闭行为；合成反例测试 | tests/security 导出边界结果：`____`；合成回归记录：`____` | `unknown` |
| GATE-07 | 选定受支持 Python 下限、JSON Schema 子集与 CLI/MCP 接口版本并通过兼容测试 | Python 版本矩阵测试：`____`；CLI 冻结测试（tests/cli）：`____`；MCP 兼容：`____` | `unknown` |

> 上表状态默认 `unknown`：未填入实测证据前，`ReleaseGateEvaluator` 的结论为 **release_blocked**（不支持/阻止发布）。不满足时按 SOFTWARE_DESIGN_REVIEW §3"不满足时"列执行（不标受支持、名册保持草案、不得宣称硬预算等）。

## 2.1 发布说明必须列出的已知限制（来自 OPERATIONS.md §8）

发布时无论门禁状态如何，以下**需求明文规定的诚实降级与边界行为**必须在 Release Notes 中如实列出——它们是履约而非偏离（SWR-019/DSR-005 强制降级规则、SR-015/DSR-021 披露与阻断要求、§6.1 待评审规则、DSR-055 缺口保留规则、DSR-078 跳过单列规则；设计原则 8"能观测的不靠声明"）：

1. 隔离为应用层校验 + 用户知情同意，非 OS 级强制沙箱（GATE-01 未关闭）
2. token/费用预算为事后审计软模式，仅 tasks 维度是硬限制（GATE-03 未关闭）
3. 跨语言边界为启发式正则，深链分析留缺口而非伪造结论
4. E2 语义核验依赖模型推理，准确率属待评测假设
5. 提示注入防御为缓解（mitigation），不可宣称绝对免疫
6. 150 张卡片为草案，未经逐语言专家评审不得标"已评审"（GATE-04 未关闭）
7. 最低 Python 版本为 3.9（非 3.10）；真实宿主版本兼容矩阵待统一测试（GATE-07）

## 3. 发布前操作核验

| 项 | 核验方式 | 结果 |
|---|---|---|
| 统一测试全绿 | `python3 tools/run_all_tests.py` → ALL DOMAINS PASSED | `____` |
| CLI 冻结面（DSR-074） | `python3 -m unittest discover tests/cli` | `____` |
| Claude 宿主安装/卸载 | 按 docs/OPERATIONS.md §2.2 实装并回收 | `____` |
| Codex 宿主安装/卸载 | 按 docs/OPERATIONS.md §2.3 实装并回收 | `____` |
| 已支持版本定稿 | OPERATIONS.md §7 由本清单结论回填 | `____` |
| 评估器结论 | `ReleaseGateEvaluator().evaluate_all(evidence)` → `release_allowed` | `____` |

三处全部通过并回填后，方可移除各文档中的"候选——实际支持由统一测试决定"标注。
