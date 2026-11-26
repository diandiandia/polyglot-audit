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
| 回填状态 | 已回填主文档：IFC-04（无头 worker 流契约句，[DA-05] 标注）。修订句已回填（见下行）。 |
| 修订（大载荷传递路径） | 实跑发现大体积 review 包（完整单元源码 + 审计上下文）经命令行参数传递触达 OS 单参数长度上限，两宿主适配器的 worker 路径改为 `stdin=subprocess.PIPE`：prompt 由 runner 独占写入、`communicate()` 写完即关——worker 不继承 runner 交互 stdin、不阻塞、不吞入 runner 输入，IFC-04 不变量保持；原决策记录的"DEVNULL 绑定"从唯一手段降级为两个合法绑定方式之一（不传 stdin 的调用形态仍可 DEVNULL）。探测路径（probes）prompt 极小，保留位置参数形态，两种形态均为真实 CLI 语法。配套：`tests/hosts/fake_hosts.py` 同步记录 `<name>.stdin.log` 并同时建模两种形态；适配器测试改为断言"argv 不含 prompt + stdin 收到完整 prompt"；packet 预算 `max_chars` 恢复 16000（临时减半仅为 argv 限制缓解，stdin 化后前提消失；溢出仍以 packet_overflow 事件如实记账）。 |
| 待设计审查确认 | ① stdout/stderr 是否也需要明文契约（当前实现两侧均为 PIPE 捕获，未见分歧，暂不入条款）；② 超时取消时的流关闭顺序（killpg 与管道 EOF 的竞态）是否需要 DDS-06 增补。 |

### DA-06 DSR-066/DSR-020 定义了验证预算保留，但未定义停止序列的任务维度感知语义

| 项 | 内容 |
|---|---|
| 设计出处 | DSR-066（"验证预算保留、候选优先顺序和停止序列；hunt 不得占用保留"）、DSR-020（"验证预留单独保护"）、SD §5.2。 |
| 缺口描述 | 设计规定了 hunt 不得消费验证保留，但未明文规定驱动循环在 hunt 预算耗尽后的行为：实测（真实运行 run-008，目标名称按 SR-016 不记录）driver 在 hunt 预算耗尽（BudgetExhausted）时全局停止派发，验证保留底座中的验证任务从未被领取——"单独保护"保护了额度却没有让验证任务消费它。max_tasks 会话上限也未区分维度（hunt+verify 共用同一计数）。 |
| 影响 | 有界审计（budget 优先用于 hunt）必然以"验证任务全部未执行"收场，所有候选只能进 unverified/NEEDS-VALIDATION——与 SR-008"独立验证"的核心承诺矛盾。 |
| 补救决策 | ① run_dispatch_loop 的停止序列改维度感知：hunt 领取被 BudgetExhausted 阻断后，仍继续领取 verify/second-opinion 任务（消费验证保留底座），直至验证预算也耗尽或队列清空；② stop_reason 细分 budget_exhausted（hunt 侧）/verification_complete 或 verification_reserve_exhausted；③ max_tasks 计数仅约束 hunt 派发，验证任务不受其限制（验证是 SR-008 的必要闭环）。 |
| 代码位置 | `skill/scripts/auditkit/app/service.py` run_dispatch_loop（维度感知 claim 与停止判定）；`audit.py` run 子命令透传。 |
| 回填状态 | 已回填主文档：DDS-03 §3.2（维度感知派发停止序列句，`[DA-06]` 标注）。回填句采用实现实际 stop_reason 词表（`budget_exhausted`/`verification_reserve_exhausted`/`queue_drained`/`paused_or_blocked`）：补救决策②中的 `verification_complete` 对应实现的 `queue_drained`（队列清空）。**修订（2026-11-20）**：补救决策③已实现——`run_dispatch_loop` 的 `max_batches` 现仅约束计划侧（hunt/recon）派发；verify（含 second-opinion）豁免于该 cap 继续派发（peek-then-claim 按 claim 排序判族、竞态由领取后守卫释放回队，预算安全）；stop_reason 归因修正（cap 生效且队列仍有剩余工作时归因为调用方上限而非管道原因）。待设计审查项②已回答：新增 `max_verify_batches`（CLI `--max-verify-tasks`），**默认不设限**（决策③原意：验证是 SR-008 的必要闭环），需要会话上界的调用方显式设置。返回契约新增 `dispatched_plan`/`dispatched_verify` 族计数（`batches` 仍为两族总数）。测试：`tests/e2e/test_concurrent_dispatch.py`（cap 语义改写 + 两个决策③回归）。DDS-06 门禁公式段未改动（停止序列语义落在 DDS-03 §3.2）。 |
| 待设计审查确认 | ① 验证保留底座耗尽后是否允许验证任务降级使用剩余 hunt 额度（当前决策：不允许，如实 incomplete）；② ~~max_tasks 是否需要对 verify 单独设置上限~~ 已回答：`max_verify_batches` 默认不设限，可显式收緊。 |

## 2026-11-17 run 卷宗目录形态对齐（路径 B）

### DA-07 实现采用扁平文件形态承载 §10.1 同源信息，且真实运行暴露 per-task 结果未落盘缺口

| 项 | 内容 |
|---|---|
| 设计出处 | SYSTEM_DESIGN.md §10.1（run 目录十条目）、§9.3（报告集）、§10.2/10.3（证据链与审计轨迹）、§11.4（自审可移植边界）；DSR-072（版本兼容检查只覆盖 DB 格式，未覆盖目录形态）。 |
| 缺口描述 | 实现原以扁平文件承载与 §10.1 同源的信息：无 run.json（运行元数据只散落在 config.json 与 DB runs 行）、计划写在 run 根（plan.json 而非 plan/plan.json）、无 inventory/summary.json、无 recon/ 与 candidates/ 目录、自审混在 report/ 里（report/SKILL-REVIEW.md 与 report/skill-review.json）。功能等价但形态不一致——卷宗消费者无法按 §10.1 形态导航。真实运行（真实目标项目，名称不记录；真实运行 run-001~011）进一步暴露真缺口：① tasks/<task-id>/ 只有提示包与 recon 的守卫基线汇总，hunt/verify 的 worker 结果从未按任务落盘（结果只活在账本投影与 findings/verified-*.json 聚合文件里，任务级"提示包+结果+校验日志+用量同目录"的追溯不成立）；② schema 拒绝的校验日志（DSR-018）无落盘形态；③ 用量对象未按任务落盘。 |
| 影响 | §10.1 的目录契约对宿主/审计者不可导航；任务级证据链断裂（提交内容与账本投影之间无逐任务工件可对账）；旧卷宗（§10.1 之前的布局）的读取路径未定义，存在被误迁移的风险。 |
| 补救决策 | 按路径 B 对齐 §10.1 全部十条目，不引入新依赖：① prepare 发布 run.json（不可变元数据：target、snapshot_id、root_hash、skill_version、skill_payload_sha256——对 skill 资产树计算确定性摘要、dossier_version="1.0"、整份冻结 config、profile、budgets、created_at；写入后任何阶段不得改写，prepare 入口拒绝非空 run 目录保证不可覆盖）、plan/plan.json、inventory/summary.json；② submit 对三类任务统一发布 tasks/<id>/result.json（内容=提交的 worker 结果）与 tasks/<id>/usage.json（有用量时），schema 拒绝发布 tasks/<id>/validation.json（拒绝原因+字段路径），recon 另发布 recon/recon-result.json（守卫基线汇总）；③ finalize 发布 candidates/final.json（去重后代表候选池，含 provenance/dedup 账本引用）与逐条 findings/<finding_id>/record.json + history.json（状态变迁历史自事件账本提取，无事件则空数组如实）；④ 自审移出 report/：skill-review/SKILL-REVIEW.md 常驻、可移植导出为 skill-review/portable.json（语义不变：默认关、白名单校验），report/ 只保留 §9.3 七件套（findings.json 与 findings/<id>/ 双形态并存）；⑤ 读取回退（DSR-072 只读容错）：plan 读取点优先 plan/plan.json、回退旧 plan.json；对旧卷宗禁止任何写迁移。 |
| 代码位置 | `skill/scripts/auditkit/app/service.py`（prepare 的 run.json/plan/plan.json/inventory 发布、submit 的 result/usage/validation 发布、_on_recon_result 的 recon/recon-result.json、finalize 的 _publish_dossier_records、_load_plan 回退、_compute_skill_payload_sha256）；`skill/scripts/auditkit/reporting/generator.py`（自审输出目录 skill-review/）。测试：`tests/e2e/test_dossier_layout.py`（新增，§10.1 十条目 + report/ 无自审 + run.json 不可变 + 校验日志 + 旧布局只读回退）、`tests/swr/test_swr_012.py`、`tests/swr/test_swr_013.py`、`tests/reporting/`、`tests/e2e/test_pipeline_closure.py`。 |
| 回填状态 | 待回填主文档：SD §10.1 增补 run.json 字段清单与 dossier_version 语义；§9.3 报告集表格移出 SKILL-REVIEW.md（与 §10.1 的自相矛盾需设计裁决）；§11.4 可移植部分文件名（设计写 skill-review.json，实现为 skill-review/portable.json）。 |
| 待设计审查确认 | ① 形态差异是否需要版本化（dossier_version）处理更老的布局：当前 run.json 记录 dossier_version="1.0" 只标识新布局，旧扁平布局无版本标记、依赖读取点回退（plan.json 回退已实现）——是否需要给旧布局定义显式版本值或提供一次性受控迁移工具；② report/ 与 skill-review/ 的边界：§9.3 把 SKILL-REVIEW.md 列入报告集而 §10.1 将自审独立成目录——**实现决议：自审归 skill-review/（按 SYSTEM_DESIGN §10.1），report/ 七件套不含自审**；SYSTEM_DESIGN §9.3 历史正文的处置（改写或标注）待设计审查，本轮不改历史文档正文；③ §10.1 tasks/<task-id>/ 中的"工具调用摘要"（工具名/路径/行范围）目前无宿主数据源，卷宗中如实缺席——需要设计定义宿主上报契约；④ run.json 中 skill_payload_sha256 的口径（本实现：资产树逐文件内容摘要、排序拼接、排除生成字节码缓存）是否需要升格为契约。 |

### DA-08 SR-028 准入备案：机制批修复的两次独立运行佐证（包溢出跟进、快照卫生、预算-计划前瞻、coverage 空缺记账、候选率校准、测试文件分层）

| 项 | 内容 |
|---|---|
| 设计出处 | SYSTEM_REQUIREMENTS.md SR-028（机制级修复需两次独立运行佐证或记录在案的阻断性例外）；SYSTEM_DESIGN.md §预算（预留量按实测校准、预算预估首批任务后校准）；SOFTWARE_DESIGN_REVIEW.md SR-005（大文件/跨单元区间待实测）；DSR-059（溢出留痕）、DSR-056（tier 策略）、DSR-034（覆盖登记）、设计原则 8（能观测的不靠声明）。 |
| 佐证来源 | 两个相互独立的目标运行系列的账本（事件库只读复核；目标名称按 SR-016 不记录）：运行系列 A 含 11 次 run，运行系列 B 为 1 次 run。以下失败形态在**两个系列中均出现**，构成 SR-028 意义上的机制级佐证：① packet_overflow 且溢出范围无任何后续供给（系列 A 多数 run 1~84 起，系列 B 5 起）——unit 尾部永久欠覆盖；② 清单收录二进制负载（系列 A 每 run 约 200 个 decode_failure gap，系列 B 1076 个），二进制独自耗尽信号扫描 cap 并派生垃圾单元；③ 任务预算远小于计划单元仍照常 finalize（系列 A run-009b 5 起 budget_exhausted，系列 B 33 起阻塞同一任务，覆盖率收于个位数百分比）；④ worker 结果 coverage 块全空且无任何受理点记账（系列 B 全部结果为空数组，review 维度全零）；⑤ per-unit 候选率与设计估算（0.2）显著偏离且无处记录偏差。 |
| 补救决策 | 全部为通用机制，不携带目标信息：① packet 溢出记录遗留范围并自动入队 continuation 任务（行分块保证每跳严格收缩、深度封顶，超限如实记 packet_overflow 不循环）；② 清单层面二进制负载不生成计划单元（留清单、不留工作项）；universal include 不再短路绕过卫生排除链（VCS 内部目录/二进制扩展名永不因 include 范围豁免）；③ prepare 记录 budget_coverage_forecast（预算/计划单元比），自审对 <0.5 显著预警——决策点前置到开工前；④ submit 对空 coverage 块记 coverage_unreported 事件（一次每 attempt，幂等防重），自审显式呈现"工作已发生但无法主张 observed_read"的缺口；⑤ finalize 以观测候选率对设计估算做校准记录，偏差 ≥50% 写入自审（SYSTEM_DESIGN §预算"首批任务后校准"的第一期落地）；⑥ 测试文件 tier 封顶 T2（通用命名约定检测，不检内容/不携带目标布局知识）。 |
| 代码位置 | `analysis/packets.py`（溢出遗留范围）、`app/service.py`（continuation 入队、forecast、coverage_unreported、校准）、`inventory/rules.py`（universal include 语义修订）、`inventory/slicer.py`（二进制跳过、测试文件封顶）、`reporting/self_review.py`（三个 stats 级检测）。测试：`tests/e2e/test_run_lessons_mechanisms.py`（新增，9 用例全合成 fixture）、`tests/snapshot/test_include_scope.py`（语义修订）。 |
| 回填状态 | 已实现并全量测试通过（1008+9）；本条目即 SR-028 备案记录。系列 A/B 的逐 run 账本复核数据在运行侧 RUN-LESSONS 归档，不入 skill 仓库。 |
| 待设计审查确认 | ① continuation 的任务预算语义（当前如实消耗 tasks 预算——溢出 unit 的完整覆盖因此是"花预算买覆盖"的显式权衡）是否需要独立的预算维度；② coverage 契约的受理点强制（当前只记缺口事件，不拒收结果）是否应升级为 DSR-018 有界修正路径；③ 测试文件检测的命名约定集合是否需要按语言卡片扩展。 |

### DA-09 跨单元连接器的假设边配对过松（RUN-LESSONS O-06：双向子串匹配）

| 项 | 内容 |
|---|---|
| 设计出处 | SOFTWARE_DESIGN.md SD-04（"机械连接使用具名符号、参数、边界元数据生成假设边"）；RUN-LESSONS O-06（"`lib.encrypt` ~ `encrypt` 即配对，可能误配"，收紧策略原记为待设计审查）。 |
| 缺口描述 | connector 的亲和判定是双向原始子串包含：boundary 或 symbol 任一字段 `a in b or b in a` 即生成假设边并合成联动候选，消耗独立验证预算。真实运行表明共享一个宽松词元（`encrypt` 内含于 `encryption_utils`、`lib.encrypt` 含 `encrypt`）即可配对，误配率在大仓库不可控。 |
| 补救决策 | 亲和判定改为**词元感知**三级：`exact`（全名相等）、`component`（两侧共享至少一个完整分隔词元，分隔符为非字母数字/下划线序列）、`None`（原始子串不再构成任何因子）。成边充分条件：任一字段 `exact`，或 boundary 与 symbol **同时** `component`（双独立因子互证）；单一宽松 component 因子不配对，记录留在 unresolved 并附原因。签名/参数 arity 兼容层不变（DSR-026），配对上限与预算记账不变。 |
| 代码位置 | `analysis/connector.py`（`_name_affinity` + 成边判定）；测试：`tests/analysis/test_analysis.py`、`tests/analysis/test_connector_disposition.py`（既有 exact-fixture 全部兼容）。 |
| 回填状态 | 已实现；本条目即 O-06 收紧的实现备案。误配率的真实数据量化仍待下一次真实运行的自审统计（OPEN）。 |
| 待设计审查确认 | ① component 词元的最低长度/停用词策略（当前不过滤短词元，靠双因子门槛兜底）；② 双 component 因子成边是否需要再要求路径同目录或同包前缀。 |

### DA-10 产品决议：审计即全量覆盖（预算职能重定义，抽样语义退役）

| 项 | 内容 |
|---|---|
| 决议来源 | 所有者产品决议（2026-11-21）：只要进行审计，就是项目全量审计；不抽样、不小范围。系统/软件设计中所有"预算约束覆盖"语义按本决议对齐，代码实现随后对齐设计。 |
| 决议内容 | ① **覆盖语义**：审计 = 全量覆盖。计划覆盖全部纳入清单的单元（T1～T4 一律 analyze），tier 仅作为派发优先级排序，不再门控"是否被审读"（DSR-056 的"T3 仅分诊且 T4 仅清点"退役）。② **预算职能重定义**：预算从"覆盖规划工具"改为"记账 + 失控保护"——prepare 按"计划单元数 × (1 + 验证倍率) + 1"自动设定任务预算（`verify_budget_multiplier` 默认 2.0，配置可调）；操作者显式给出的预算仅在 ≥ 全量需求时被采纳，低于需求时自动提升至全量并记 `budget_autosized_full_coverage` 事件（不静默、不抽样）。③ **诚实语义不变**：进程崩溃/用户中止/宿主失效导致的未覆盖仍如实 incomplete + 缺口清单；验证预留（DSR-020）保留——它保护的是验证份额，不再可能因预算规划而截断覆盖。④ **token 诚实降级不变**（SR-019：token/费用仍不可硬承诺，GATE-03 语义不受影响）。⑤ **档位语义变更**：quick/standard/deep 不再改变覆盖广度（一律全量），差异仅保留在复核冗余上（第二意见范围、复核波次）。⑥ 规模分区（XL 按组件多次运行）保留为运维并行手段，但每个分区内部仍然全量。 |
| 设计出处（被修订条款清单） | SYSTEM_DESIGN.md：前言 L15"受预算约束"、目标 L36"不承诺逐行读完…预算内最大有效覆盖"、原则 4 L46"预算先行…预算不够时缩小覆盖"、unit/candidate 状态机 `deferred(budget)`/`unverified(budget)`、G0"计划在预算内或部分覆盖"、§5.10 规模档位"预算内依次处理/必须给预算"、§6.2 预算与分配及三档位覆盖广度、L901 用户预算前提。DETAILED_DEVELOPMENT_REQUIREMENTS.md：DSR-056"T3 仅分诊且 T4 仅清点"。SYSTEM_REQUIREMENTS.md：SR-019 语义重定义（记账与失控保护，非覆盖规划）。docs/LESSONS-TEMPLATE.md（skill/references/lessons-template.md）：不变量"预算内按风险排序取得最大有效覆盖"。 |
| 代码对齐范围 | `inventory/slicer.py`（处置门控退役）、`app/service.py`（prepare 全量预算自动设定 + 显式预算提升事件）、后续对齐：DSR-056 相关注释/文档串、测试（处置门控断言改写）。 |
| 回填状态 | 主文档修订随本决议落稿（各处 [DA-10] 标注）；DSR-056/SR-019/SWR-019 条款正文以 [DA-10] 修订注记回填，需求基线编号不变。 |
| 待设计审查确认 | ① `verify_budget_multiplier` 默认值（2.0）是否需要随真实候选率数据再校准（O-14 校准偏差 250% 提示默认 0.2 候选率估算已失效，倍率需覆盖观测上界）；② token/费用维度未来若可强制，是否恢复为覆盖规划输入（当前决议：不恢复，覆盖只由计划定义）；③ 档位（quick/standard/deep）是否整体退役（当前保留为复核冗余旋钮）。 |

### DA-11 攻击面可达性分级（surface_class：排序与卷宗标注，非覆盖过滤）

| 项 | 内容 |
|---|---|
| 决议来源 | 所有者需求（2026-11-21）：测试代码与用户不可达的内部逻辑应被自动评估区分。测试目录默认排除（既有 include_tests 语义）与散落测试文件 T2 封顶（既有）之外，**用户可达性此前不参与优先级排序**——可达性只在 verify 阶段逐 finding 记录前提，属事后评估。 |
| 决议内容 | ① 单元规划时按入口信号派生 `surface_class`：`remote`（命中 `src_http*` 网络入口信号）> `local`（命中其它 `src_*` 本地入口信号）> `internal`（无入口信号）——信号 ID 是工具包自身的跨语言分类（SR-003 无语言特化）。② `surface_class` 作为 tier 之内的次级派发排序键（tier 主序不变：T1→T4），同 tier 内 remote 先于 local 先于 internal。③ 派发优先级公式：tier 基分 {T1:24, T2:20, T3:16, T4:10} + surface 调整 {remote:+3, local:+1, internal:0}，全部低于 verify 优先级（30）——验证优先于任何 hunt 的既有承诺不变。④ `surface_class` 写入单元与计划卷宗；**不构成覆盖过滤**——DA-10 全量语义不变，internal 单元仍然被审，只是排在队列尾部（DA-10 待审③的档位退役使 T3/T4 亦被审读，本分级回答"同预算下谁先审"）。 |
| 设计出处 | SR-020（低自耗：稀疏输出与扇出控制——排序属低自耗范畴）、SD-03 第 4 条（风险信号仅排序）、SR-003（平台/语言条件判定——信号 ID 为工具包分类，无语言特化）。 |
| 代码位置 | `inventory/slicer.py`（surface_class 派生与单元字段）、`app/service.py`（派发优先级公式）。测试：`tests/snapshot/test_signals_slicer_boundaries.py`（surface 分级断言）。 |
| 回填状态 | 已实现；SYSTEM_DESIGN L36 排序语义句同步更新（tier 与攻击面类别共同决定派发优先顺序）。 |
| 待设计审查确认 | ① 入口信号种类随语言卡片扩展时的映射维护（当前三类映射表在 signals.py 常量区）；② 认证入口（login_required/admin 角色信号）未来是否细分为 `remote_auth` 子级（当前 verify 阶段前提记录已覆盖认证事实，排序不细分）。 |

### DA-12 宿主失败分类的证据规则（证据缺失默认可重试 + 限流感知退避）

| 项 | 内容 |
|---|---|
| 决议来源 | 有界真实运行暴露的宿主形态（所有者批准中途修复，2026-11-21）：真实宿主 CLI 对 API 层失败（如 HTTP 429 形态）可能以"非零退出 + 双流无诊断签名"退出，而原分类器只读 stderr 且对无签名失败一律判不可重试——每个此类失败使分析单元被立即永久隔离（零重试缓冲），属于"分类需要证据，证据缺失被当作永久性证据"的语义颠倒。 |
| 决议内容 | ① `classify_exit_failure` 的分类证据扩展为 stderr ∪ stdout 双流（真实宿主在任一流打印 API 错误）；双流均无识别签名且非零退出的失败默认判**可重试**（隔离是永久损失分析单元，重试只耗分钟——"无永久性证据"不得充当永久性证据）；双流有签名按既有规则（rate_limit 可重试、auth_error 不可重试）；有证据但无识别签名仍不可重试。② 失败消息保留双流有界尾部（stderr 为空时仍可诊断）。③ 限流类重试改用分钟级退避日程（默认 30/60/120s 封顶，构造器可调）——限流窗口为分钟级，原亚秒级日程会把全部重试烧在窗口内；其他类别维持原日程。④ HostFailureError 实例附加 `category` 属性（适配器侧附加，冻结契约文件不改）。 |
| 设计出处 | DSR-029（退出分类）、DSR-064（限流退避）、设计原则"诚实展示"与"记账交给程序"——分类错误是程序侧记账错误，不是模型侧声明问题。 |
| 代码位置 | `hosts/retry.py`（classify_exit_failure 双流签名 + backoff_delay_for_failure）、`hosts/claude_adapter.py` 与 `hosts/codex_adapter.py`（双流分类调用、category 附加、限流感知退避、rate_backoff_* 构造参数）。测试：`tests/hosts/test_adapters.py`（证据缺失默认可重试、stdout 侧限流签名、限流日程纯函数、限流日程接线）。 |
| 回填状态 | 已实现；版本 0.1.0 → 0.1.1（minor；DSR-072 版本门仅查 major，进行中 run resume 兼容，账本 meta 如实记录漂移前后版本）。 |
| 待设计审查确认 | ① 有证据但无识别签名的失败维持不可重试——是否需要"连接类瞬态签名"（如 ECONNRESET）白名单；② 限流退避默认日程（30/60/120s）是否随真实宿主窗口分布再校准；③ category 属性若未来进契约层，需走契约变更流程（当前留在适配器侧）。 |

### DA-13 适配器级有界格式重试（worker 输出不可解析 = 可重试，非永久隔离）

| 项 | 内容 |
|---|---|
| 决议来源 | 有界真实运行暴露的第二类宿主形态（所有者批准中途修复，2026-11-21）：真实 worker 偶发产出不可解析输出（纯散文 / 开头合法但中途截断畸形的 JSON），实测频率 ≈6%；原适配器解析失败抛 InvalidInputError（不可重试）→ 驱动直接永久隔离分析单元。两类失败共同点：重新执行一次通常即产出契约输出（模型方差），永久隔离与"预算内最大有效覆盖"目标相悖。 |
| 决议内容 | ① 适配器 JSON 解析失败（鲁棒提取——围栏/花括号回退——之后仍无合法 JSON）改为抛 `HostFailureError(retryable=True)` 并附加 `category="format"`（新增 `CATEGORY_FORMAT` 常量，适配器级类别，非 classify_exit_failure 产物）。② 重试走既有机制散热：适配器内 max_retries + 队列层 generation 重排（各上限不变），真实无法产出契约输出的单元在重试上限处照旧隔离并记 coverage gap——有界，非无限重试。③ 与 DSR-018 的关系：DSR-018 是提交层 schema 校验的有界格式纠正（worker_result dict 形状）；本条是提交之前的适配器层解析失败，两者分层互补。 |
| 设计出处 | DSR-018（有界格式重试，分层适用）、DSR-065（失败重排与隔离）、DA-10（全量覆盖语义——单元损失必须真实不可恢复而非可重试形态）。 |
| 代码位置 | `hosts/retry.py`（CATEGORY_FORMAT 常量）、`hosts/claude_adapter.py` 与 `hosts/codex_adapter.py`（解析失败 → 可重试 HostFailureError + category 附加）。测试：`tests/hosts/test_adapters.py`（散文输出 / 畸形 JSON / codex 同型，各断言 retryable + category）。 |
| 回填状态 | 已实现；版本 0.1.1 → 0.1.2（minor；进行中 run 二次 resume，账本如实记录版本轨迹 0.1.0 → 0.1.1 → 0.1.2）。 |
| 待设计审查确认 | ① format 重试的上限组合（适配器 3 次 × 队列 3 代 = 至多 9 次执行）对系统性截断（token 上限导致的确定性畸形）是否过长；② 截断类畸形是否应触发 packet 再分页（DSR-059 溢出机制的下游联动）而非盲目重试；③ format 类别与 rate_limit 一样属适配器侧扩展类别，DSR-029 正文的类别清单是否收编。 |

### DA-14 候选 provenance 形状守卫 + submit 路径任务级兜底（驱动循环不可因单点形状死亡）

| 项 | 内容 |
|---|---|
| 决议来源 | 有界真实运行击穿的第四个真实形状缺陷（L-07/O-01/L-12 同族）：真实 worker 将候选 `provenance` 写为裸字符串，`verifier.build_verify_task` 的无守卫 `.get` 链抛 AttributeError；该异常沿 submit → `_on_result_accepted` → `_enqueue_verify_tasks` 逃逸——submit 块只捕 InvalidInputError（DSR-018）与 StaleAttemptError（DDS-06），**无兜底**，异常穿透 worker future 击杀整个 dispatch 循环，审计停摆。 |
| 决议内容 | ① **形状守卫**（verifier 层）：`provenance` 非契约 dict 时抛 InvalidInputError（进入 DSR-018 有界重试族，任务局部containment），与 dedup 池守卫同一语义族——契约违反映射为显式拒绝，永不 AttributeError。② **任务级兜底**（service 层）：execute_one_task 的 submit 块补 `except Exception` 最后防线——意外异常降级为任务级可重试失败（重排 generation+1，失败计数 + AIMD 减半 + 退避），确定性肇事者在上限处照旧隔离并记诚实 gap；**任何单点意外形状不得击杀驱动循环**（L-06 任务级隔离纪律补全到 submit 全路径）。③ KeyboardInterrupt/SystemExit（BaseException）不受兜底影响，中断语义不变。 |
| 设计出处 | L-06（任务级异常隔离）、DSR-018（有界格式重试）、DSR-065（失败重排与隔离）、设计原则"诚实展示"——兜底路径的失败原因完整入账。 |
| 代码位置 | `analysis/verifier.py`（provenance 形状守卫）、`app/service.py`（submit 块兜底 except）。测试：`tests/analysis/test_real_shape_regressions.py`（provenance 三形状：字符串拒绝/缺失拒绝/契约 dict 通过）、`tests/e2e/test_concurrent_dispatch.py`（submit 抛 RuntimeError → 循环存活、任务重排后完成、零隔离）。 |
| 回填状态 | 已实现；版本 0.1.2 → 0.1.3（minor；run-001 三次 resume，版本轨迹 0.1.0 → 0.1.1 → 0.1.2 → 0.1.3 如实入账）。 |
| 待设计审查确认 | ① 兜底 except 是否应附带 traceback 到 stderr（L-05 惯例）以区分"意外形状"与"代码 bug"；② verifier 其余候选字段访问链（title/source/sink）的同族审计——L-12 已防御 packet 渲染层，spec 构建层是否还有无守卫链；③ "形状守卫 → InvalidInputError → 有界重试 → 隔离" 是否对信封级字段（非 worker 输出而是程序拥有的卷宗数据）语义过重——程序侧数据错误或许应记 analysis_gap 而非消耗重试。 |

### DA-15 熔断触发安全暂停（breaker → pause，替代级联隔离）+ 退避指数钳制

| 项 | 内容 |
|---|---|
| 决议来源 | 有界真实运行两次命中同一数据丢失级缺陷（2026-11-23 与 11-26）：宿主瞬时故障窗口 → 适配器熔断（3 连败）→ 熔断实例**永不复位**（触发点在尝试之前，成功无从发生）→ 后续每个被触达任务按不可重试上报 → **连环 mass-quarantine**（一次 1012 单元、一次 +29）——L-02 模式在熔断语义下的复活。熔断契约（DSR-064/SWR-022"失败驱动降速"）显然不含"销毁在途工作"。另同窗口暴露：compute_backoff_delay 以累计失败计数为指数 → `2**1000` 浮点溢出击杀 worker 线程（长跑必然）。 |
| 决议内容 | ① **熔断安全暂停**：execute_one_task 的 AuditError 处理器识别 `breaker_tripped` 标记（适配器附加，冻结契约不改）→ 调 pause 使 run 进入 paused（幂等 best-effort，在途租约如实保留）→ 该任务按**可重试**上报重排（generation+1 有界）→ dispatch 循环经 blocked-drain 退出；新驱动 resume 即全新熔断状态。瞬时宿主故障从此降级为"暂停+无损重排"，不再产生任何隔离。② **退避指数钳制**：compute_backoff_delay 指数 `min(attempt-1, 16)`——调用方可传累计计数器，max_delay 本就封顶结果，钳制不改变可达日程。③ 熔断异常本身（retryable=False、消息、复位条件）不变——改变的只是 dispatch 层对它的响应。 |
| 设计出处 | DSR-064（熔断退避：目的为降速非销毁）、DSR-065（失败重排）、SWR-022（暂停切换）、RUN-LESSONS L-02（mass-quarantine 根因）。 |
| 代码位置 | `hosts/claude_adapter.py` 与 `hosts/codex_adapter.py`（breaker_tripped 标记）、`hosts/retry.py`（指数钳制）、`app/service.py`（AuditError 处理器熔断分支 → pause + 可重试上报）。测试：`tests/hosts/test_adapters.py`（双适配器标记断言）、`tests/e2e/test_concurrent_dispatch.py`（熔断注入 → run paused / 任务重排 gen+1 / 零隔离 / 暂停原因含 fail-safe）。 |
| 回填状态 | 已实现；版本 0.1.4 → 0.1.5。真实 run 缺口事实不变：11-23 的 1012 个隔离为终态诚实 gap（恢复需 finalize 后 scoped follow-up run）；11-26 的 +29 个同。 |
| 待设计审查确认 | ① 熔断触发是否应自动 resume（当前设计为人工/监督方 resume——保守优先）；② 熔断阈值（3 连败）在分钟级退避日程下的适配性；③ paused 事件的 reason 长度上限（256）与多 worker 并发触发的幂等性已按 best-effort 处理，是否需要显式去重。 |

## 与并行工作流的接口确认（本文件随实现更新）

| 接口 | 变更 | 消费方 |
|---|---|---|
| `ReportGenerator.generate_all` | 未新增必需参数；未连接半链从既有 `events` 入参提取（`unpaired_half_chain`/`connector_paired` 事件对账），未验证候选从 `findings` 入参提取。`audit.py` 不直接调用 `generate_all`（只经 `AuditAppService.finalize` 与已发布产物），无调用方改动。 | `audit.py report`（只读，无签名依赖） |
| `AuditAppService.finalize` | 新增 InvalidStateError 语义：有效租约内 claimed/running attempt >0 时拒绝 finalize。`tests/cli/test_cli.py::test_prepare_run_next_start_hostfail_submit_finalize` 现会命中该门禁（finalize 前需先 pause 或排空在途 claim）——该文件属 MCP/CLI 并行工作流，需同步更新。 | `audit.py finalize`、MCP finalize 工具、tests/cli |
| `KnowledgeCatalog.get_applicable_indices` | `is_jvm` 升级为三态（默认 None=未知）。`audit.py`/hosts 层不直接调用。 | service 两处调用点、tests/knowledge |
| 事件账本新增事件类型 | `frontier_recorded`、`sink_probe_recorded`、`connector_paired`、`unpaired_half_chain`、`verify_task_spec_rejected`；`run_finalized` payload 新增 `unprocessed_units` 明细。 | MCP/CLI 工具面若透传事件列表，属只读追加，向后兼容 |
| 自审输出与卷宗工件路径（DA-07） | `ReportGenerator` 自审输出移至 `skill-review/SKILL-REVIEW.md`（常驻）与 `skill-review/portable.json`（可移植导出，开启时；原 `report/skill-review.json`），`report/` 只保留 §9.3 七件套；service 新增卷宗工件：`run.json`、`plan/plan.json`、`inventory/summary.json`、`recon/recon-result.json`、`tasks/<id>/{result,usage,validation}.json`、`candidates/final.json`、`findings/<finding_id>/{record,history}.json`；plan 读取点回退旧 `plan.json`（只读）。`audit.py report` 只读 `report/REPORT.md`，不读自审，无破坏。 | `audit.py report`（确认无影响）、tests/reporting、tests/swr/test_swr_010、test_swr_012、test_swr_013、test_swr_016、tests/e2e |
