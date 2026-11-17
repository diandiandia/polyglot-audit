# 设计对齐勘误记录（DESIGN_ALIGNMENT_NOTES）

只追加，不改写。本文件记录"实现与设计明文冲突、且经用户审计确认"的对齐修复背后暴露出的**设计层缺口**：每条给出设计出处、缺口描述、影响、本实现的补救决策与代码位置，以及留待下一轮设计审查确认的事项。格式仿[决策记录](./DECISIONS.md)。

> 背景 SR 编号对照：SR-012/026/DSR-076（终态语义）、SR-005/007/DSR-026/058（半链）、DSR-066（未验证候选）、DSR-073（task_spec 契约）、SR-003/SD-02（平台条件）。实现细节以 `skill/scripts/auditkit/app/service.py` 的需求追踪注释为准。

## 2026-11-15 首轮对齐修复

### DA-01 G1/G2 门禁公式存在"零派发盲区"，设计未定义计划覆盖不变量

| 项 | 内容 |
|---|---|
| 设计出处 | DDS-06（DETAILED_SOFTWARE_DESIGN.md §6）："G1 单元、溢出及未完成；G2 候选/裁决/锚点/定级"；SD-06 §5.1（SOFTWARE_DESIGN.md）："运行终态为 complete 或 incomplete(reason[])；前者只表示计划范围的处理与门禁完整"。绑定实现 DSR-022/026/051/076。 |
| 缺口描述 | DDS-06 的 G1/G2 可程序化公式只做"已派发任务的对账"：G2 以 `lost = dispatched − submitted − in_flight ≤ 0` 判 pass，G1 以"计划单元数 vs 已入队任务数"判 pass。**计划了但从未派发**（如 prepare 之后直接 finalize、或预算在第一次派发前耗尽）时，两式都满足——lost=0、任务数对账相等——门禁 pass，终态可判 complete。设计未定义"计划范围必须被处理"的不变量（计划覆盖不变量），公式层面存在结构性盲区。 |
| 影响 | prepare→finalize 直接得到 complete 终态与完整报告；零派发的 hunt/recon/verify 计划范围被静默掩盖。与 SD-06 §5.1 "complete 只表示计划范围的处理与门禁完整"明文冲突（SR-012/026 验收"不以门禁通过宣称完整性"被架空）。原实现中该路径确实产出 complete（回归测试 `test_prepare_then_finalize_is_incomplete_with_unprocessed_units` 固定了旧行为的对立面）。 |
| 补救决策 | 代码层补硬规则，不动 GATE 公式本身：① G1 的 DB 侧对账改为仅统计 `state='done'` 的 hunt 任务；② finalize 增加 `unprocessed_units` 硬规则——plan_units>0 且 hunt 从无 attempt 记录（零派发）、或 recon/verify 任务未达 done（verify 亦接受显式 quarantine），一律追加 `unprocessed_units` 不完整原因；③ finalize 开头增加在途硬门禁：有效租约内的 claimed/running attempt 数 >0 时抛 `InvalidStateError`（提示先 pause 或等租约过期后 reclaim），保证"计划范围处理完成"先于终态判定。`run_finalized` 事件携带完整对账明细。 |
| 代码位置 | `skill/scripts/auditkit/app/service.py`：`finalize()`（在途门禁、G1 done 对账、`UNPROCESSED_UNITS_REASON`、unprocessed_units 记账）；`skill/scripts/auditkit/app/service.py` 常量区（`UNPROCESSED_UNITS_REASON`）。测试：`tests/e2e/test_pipeline_closure.py::TestTerminalStateSemantics`、`tests/ledger/test_service_finalize.py`。 |
| 回填状态 | 已回填主文档：SD §5.1（终态判定前置计划覆盖不变量与在途租约阻断）、DDS-03 §3.2（finalizing 前在途阻断）、DDS-06（G1/G2 盲区说明与计划覆盖不变量硬规则）。待设计审查确认栏不变。 |
| 待设计审查确认 | ① 是否把"计划覆盖不变量"正式写入 DDS-06 的 G1 定义（建议：G1 增加"G2-0 同款的 never-dispatched 检查项"，而非依赖 service 层硬规则）；② 在途租约阻断 finalize 应作为 SD-06 §5.1 终态前置条件写明（当前是实现自行推导）；③ `unprocessed_units` 是否需要按 kind 细分为多个 reason code（当前合并为单一原因 + 事件明细）。 |

### DA-02 DSR-031/SD-09 未定义 MCP 线协议文本，"扁平简单"原则下实现走了自定义 JSON-RPC

| 项 | 内容 |
|---|---|
| 设计出处 | DSR-031（DETAILED_DEVELOPMENT_REQUIREMENTS.md）："实现 MCP 四工具候选适配，未验证前默认不声称支持"；SD-09（SOFTWARE_DESIGN.md）："两个执行引擎、可选 MCP、信任边界"；DR-011（DECISIONS.md）：M2 提供 `audit mcp`，只暴露四个工具。 |
| 缺口描述 | 设计只规定了 MCP 工具面（四个工具）与信任边界，未定义线协议文本：标准 MCP 客户端要求的 `initialize` / `tools/list` / `tools/call` 握手、协议版本协商与能力宣告在 DSR-031/SD-09/IFC 契约中均无对应条目。"扁平简单"的实现原则下，首版走了自定义（扁平方法名直连）JSON-RPC，导致与标准 MCP 客户端不互通——MCP 适配的验收（"宿主可挂载四工具"）实际不可达。 |
| 影响 | 任何标准 MCP 客户端无法与 `audit mcp` 建立会话；DSR-031 的验收不可达；四工具能力"声称存在但无法被宿主消费"。 |
| 补救决策 | 实现标准 `initialize` → `tools/list` → `tools/call` 握手与协议版本协商，同时保留旧直连方法以兼容已发布的会话内路径。该修复由并行工作流（MCP/CLI 工作流）实施于 hosts 层；本工作流在 finalize 语义上的变更（在途租约阻断、终态硬规则）是 MCP 工具调用 finalize 路径的共享前置条件。 |
| 代码位置 | hosts 层（并行工作流范围：`skill/scripts/hosts/**`、`skill/scripts/audit.py` 的 `mcp` 子命令）；本工作流相关接口：`AuditAppService.finalize`（其 INVALID_STATE 语义会经 MCP finalize 工具透出为错误信封）。 |
| 回填状态 | 已回填主文档：IFC §6（`mcp` 行标准线协议说明）、SD §7（MCP 段标准线协议句）、DDS-01（MCP 传输标准线协议句）。待设计审查确认栏不变。 |
| 待设计审查确认 | ① IFC/DSR 契约需补充 MCP 线协议条目（协议版本、握手顺序、四工具的 JSON-RPC 形状、错误信封映射）；② "扁平简单"原则与协议兼容性的优先级需要在设计文中显式排序；③ 旧直连方法的废弃窗口与版本演进策略（DSR-073 的版本演进条款是否覆盖传输层）。 |

### DA-03 SR-003/SD-02 要求平台条件化，但未规定平台检测机制

| 项 | 内容 |
|---|---|
| 设计出处 | SR-003（SYSTEM_REQUIREMENTS.md）："其他基座关系仅在适用平台生效……语言映射不把所有 Kotlin/Scala 目标误判为 JVM"；SD-02（SOFTWARE_DESIGN.md）："知识与适用性……平台条件"；DR-014（DECISIONS.md）：基座语言同时加载推广到 Kotlin、Scala→Java。 |
| 缺口描述 | 设计要求 Kotlin/Scala 的 Java 基座索引"仅在 JVM 平台适用"且未知时"说明不确定"，但没有规定平台如何判定：检测时点（prepare/claim）、证据来源（构建脚本？运行时探测？）、三态语义（JVM/非 JVM/未知）与未知时的呈现方式均未定义。首版实现因此默认 `is_jvm=True`——恰是 SR-003 验收明文禁止的"把所有 Kotlin/Scala 目标误判为 JVM"。 |
| 影响 | 非 JVM 的 Kotlin/Scala 目标（如 Kotlin/Native、Scala.js、Android 部分场景）被注入不适用的 Java 基座行；未知平台被静默当作 JVM，违反设计原则 8（能观测的不靠声明）与 SD-02"平台未知则说明不确定"。 |
| 补救决策 | 构建标识启发式 + honest unknown：① `get_applicable_indices(lang, is_jvm)` 升级为三态（True/False/None=未知）；None 时不展开 Java 基座索引，并在返回的 packet 行中附"platform unknown"说明（披露而非假设），默认值即 None；② prepare 时从冻结快照 manifest 扫描 JVM 构建标识（pom.xml、build.gradle、build.gradle.kts、settings.gradle、settings.gradle.kts、*.sbt、.mvn/），有标识→True，无标识→None（未知）；证据与依据写入 plan.json 的 `platform_evidence`；③ 两个调用点（recon 入队、hunt 包渲染）都传入检测结果。设计审查可改用更强的检测（如解析构建脚本内容、检测 Kotlin/Native 目标声明），本实现只主张"无证据时不得假设 JVM"。 |
| 代码位置 | `skill/scripts/auditkit/knowledge/catalog.py`：`get_applicable_indices`（三态 + unknown 说明行）；`skill/scripts/auditkit/app/service.py`：`detect_jvm_build_evidence_files`、`prepare`（`platform_evidence` 入 plan）、`_snapshot_platform_is_jvm`（claim 包渲染侧）。测试：`tests/e2e/test_platform_conditioning.py`。 |
| 回填状态 | 已回填主文档：SD §2（平台判定机制：构建标识证据清单 + honest unknown 披露）、DDS-05（packet 侧三态展开与 unknown 披露）。待设计审查确认栏不变。 |
| 待设计审查确认 | ① SD-02 需补充平台判定机制条目（证据清单、时点、三态语义、未知呈现）；② Android 目标（Kotlin + Android SDK、无 JVM 构建脚本但 ART 运行时）按本启发式会落入"未知"——是否需要 Android 专属判定（gradle 文件存在即 True 已覆盖多数场景）；③ `platform_evidence` 是否升格为 snapshot manifest / 计划契约的正式字段（当前为 plan.json 内的披露字段）。 |

### DA-04 IFC-02 的 task_spec 形状与实现演化脱节（schema 从未被验证）

| 项 | 内容 |
|---|---|
| 设计出处 | IFC-02（INTERFACE_CONTRACTS.md）：交换对象；DSR-073（DETAILED_DEVELOPMENT_REQUIREMENTS.md）："定义所有 schema 的嵌套字段、上限、条件约束及版本演进策略……与 CLI、MCP、DB 引用使用同一来源"；DR-015（DECISIONS.md）："schema 仍然是 JSON 文件……同一份文件要直接交给宿主 CLI 做结构化输出"。 |
| 缺口描述 | task_spec.schema.json 描述的是一套假想形状（`kind`/`unit_ids`/`packet_digest`/`priority`/`limits`），与三个入队点的真实构造（hunt：`unit`+`snapshot_id`；recon：`task_kind`+`role`+索引+`knowledge_hints`；verify：`verify_task_id`+`candidate_id`+`output_contract`+`input`[+second opinion 字段]）完全脱节，且 schema 里的 `kind` 枚举值与实现的 `task_kind` 字段名不一致。该 schema 从未被执行校验路径消费——fixture 里的"有效样例"永远不会被任何真实入队产生，属于"从未被验证"的死契约。 |
| 影响 | DSR-073 "同一来源"不成立：宿主 CLI 若按 schema 生成结构化输出会被服务拒绝；契约测试给出虚假信心（假形状通过校验、真形状反而失败）；版本演进无从谈起（演进的不是真实契约）。 |
| 补救决策 | schema 反向对齐真实契约为唯一来源：① 重写 task_spec.schema.json 为 `oneOf` 三分支（hunt/recon/verify，`task_kind` const 判别；second-opinion 字段并入 verify 分支），公共 required 收敛为所有入队点实际保证的字段（`schema_version` + `task_kind`）；② hunt 入队 spec 补齐 `schema_version`+`task_kind`（使其与 recon/verify 同构，可被统一判别）；③ service 三个入队点（hunt/recon/verify fan-out/second-opinion）以 SchemaValidator 校验 spec，无效 spec 拒绝入队（InvalidInputError；verify fan-out 路径记 `verify_task_spec_rejected` 事件后跳过，避免提交中途崩溃）；④ tests/contracts fixtures 全部替换为真实形状的正反例，并新增"已废弃假形状必须被拒绝"的回归断言。 |
| 代码位置 | `skill/schemas/task_spec.schema.json`（重写）；`skill/scripts/auditkit/app/service.py`：`_validated_task_spec`、三个入队点；`tests/contracts/fixtures/task_spec/*`、`tests/contracts/test_schema_fixtures.py`、`tests/e2e/test_integration_wiring.py::TestTaskSpecEnqueueGate`。 |
| 回填状态 | 已回填主文档：IFC §2（TaskSpec 行改为 oneOf 三分支真实契约并注明演进出处）、DDS-04（入队 spec schema 校验句）。待设计审查确认栏不变。 |
| 待设计审查确认 | ① IFC-02 文档需按新 schema 改写 task_spec 条目（字段表、三分支形状、判别字段）；② hunt spec 补齐 `schema_version`/`task_kind` 是对既有 run 目录内旧 spec 的不兼容变更——旧 run 只读重渲染是否需要兼容读取路径（DSR-072 版本检查目前只覆盖 DB 格式，不覆盖 spec_json 形状）；③ `unit`/`input` 子对象的上限与条件约束（DSR-073 要求"嵌套字段、上限、条件约束"）当前只约束实际保证的标识字段，完整收紧需在下一轮契约冻结时统一处理。 |

### DA-05 IFC-04 未规定无头 worker 进程的流契约（stdin/stdout/stderr 与 runner 的关系）

| 项 | 内容 |
|---|---|
| 设计出处 | IFC-04（INTERFACE_CONTRACTS.md）"CLI 与会话内传输"与"driver 走相同服务接口并管理本地进程"；SD-07（SOFTWARE_DESIGN.md §5）；DSR-002（"实现 Claude 无头、结构化输出……探测"）。 |
| 缺口描述 | 设计从未明文规定 driver 拉起的无头 worker 进程与 runner 之间的流关系。实测发现两个宿主 CLI 都会读 stdin（codex：`Reading additional input from stdin...`；在管道驱动下可能阻塞或吞入 runner 输入流），而同一修复模式（`stdin=DEVNULL`）最初只落在 Codex 适配器、未同步到 Claude 适配器——契约缺失导致该不对称无人拦截，且宿主 mock 测试与统一套件全绿无法发现。 |
| 影响 | `audit run --host claude` 在脚本重定向/非交互管道驱动下可能挂起或污染 runner 的 stdin；两宿主实现违反 SR-022 的引擎等价语义（同一 claim 协议下行为应一致）。 |
| 补救决策 | ① 两宿主适配器统一 `stdin=subprocess.DEVNULL` 并加同源注释；② IFC-04 回填明文一句（worker 进程不得继承 runner 的标准输入流）；③ real_cli 探测测试增加"调用形态错误≠合法 unknown"的区分断言（与 DA-02 的探针修正配套）。 |
| 代码位置 | `skill/scripts/auditkit/hosts/claude_adapter.py`（Popen stdin=DEVNULL）、`hosts/codex_adapter.py`（既有，同步注释）、`hosts/probes.py`、`tests/hosts/fake_hosts.py`、`tests/hosts/test_real_hosts.py`。 |
| 回填状态 | 已回填主文档：IFC-04（无头 worker 流契约句，[DA-05] 标注）。 |
| 待设计审查确认 | ① stdout/stderr 是否也需要明文契约（当前实现两侧均为 PIPE 捕获，未见分歧，暂不入条款）；② 超时取消时的流关闭顺序（killpg 与管道 EOF 的竞态）是否需要 DDS-06 增补。 |

### DA-06 DSR-066/DSR-020 定义了验证预算保留，但未定义停止序列的任务维度感知语义

| 项 | 内容 |
|---|---|
| 设计出处 | DSR-066（"验证预算保留、候选优先顺序和停止序列；hunt 不得占用保留"）、DSR-020（"验证预留单独保护"）、SD §5.2。 |
| 缺口描述 | 设计规定了 hunt 不得消费验证保留，但未明文规定驱动循环在 hunt 预算耗尽后的行为：实测（真实运行 run-008，目标名称按 SR-016 不记录）driver 在 hunt 预算耗尽（BudgetExhausted）时全局停止派发，验证保留底座中的验证任务从未被领取——"单独保护"保护了额度却没有让验证任务消费它。max_tasks 会话上限也未区分维度（hunt+verify 共用同一计数）。 |
| 影响 | 有界审计（budget 优先用于 hunt）必然以"验证任务全部未执行"收场，所有候选只能进 unverified/NEEDS-VALIDATION——与 SR-008"独立验证"的核心承诺矛盾。 |
| 补救决策 | ① run_dispatch_loop 的停止序列改维度感知：hunt 领取被 BudgetExhausted 阻断后，仍继续领取 verify/second-opinion 任务（消费验证保留底座），直至验证预算也耗尽或队列清空；② stop_reason 细分 budget_exhausted（hunt 侧）/verification_complete 或 verification_reserve_exhausted；③ max_tasks 计数仅约束 hunt 派发，验证任务不受其限制（验证是 SR-008 的必要闭环）。 |
| 代码位置 | `skill/scripts/auditkit/app/service.py` run_dispatch_loop（维度感知 claim 与停止判定）；`audit.py` run 子命令透传。 |
| 回填状态 | 待回填主文档（DDS-03 §3.2 / DDS-06 停止序列段）。 |
| 待设计审查确认 | ① 验证保留底座耗尽后是否允许验证任务降级使用剩余 hunt 额度（当前决策：不允许，如实 incomplete）；② max_tasks 是否需要对 verify 单独设置上限。 |

## 与并行工作流的接口确认（本文件随实现更新）

| 接口 | 变更 | 消费方 |
|---|---|---|
| `ReportGenerator.generate_all` | 未新增必需参数；未连接半链从既有 `events` 入参提取（`unpaired_half_chain`/`connector_paired` 事件对账），未验证候选从 `findings` 入参提取。`audit.py` 不直接调用 `generate_all`（只经 `AuditAppService.finalize` 与已发布产物），无调用方改动。 | `audit.py report`（只读，无签名依赖） |
| `AuditAppService.finalize` | 新增 InvalidStateError 语义：有效租约内 claimed/running attempt >0 时拒绝 finalize。`tests/cli/test_cli.py::test_prepare_run_next_start_hostfail_submit_finalize` 现会命中该门禁（finalize 前需先 pause 或排空在途 claim）——该文件属 MCP/CLI 并行工作流，需同步更新。 | `audit.py finalize`、MCP finalize 工具、tests/cli |
| `KnowledgeCatalog.get_applicable_indices` | `is_jvm` 升级为三态（默认 None=未知）。`audit.py`/hosts 层不直接调用。 | service 两处调用点、tests/knowledge |
| 事件账本新增事件类型 | `frontier_recorded`、`sink_probe_recorded`、`connector_paired`、`unpaired_half_chain`、`verify_task_spec_rejected`；`run_finalized` payload 新增 `unprocessed_units` 明细。 | MCP/CLI 工具面若透传事件列表，属只读追加，向后兼容 |
