# 接口与数据契约基线

> 状态：供并行开发评审的 v1 候选，尚未作为可执行 schema 发布。CON 为唯一契约维护者；所有变更经 INT 与受影响所有者评审并记录，未完成评审前不得各自扩展字段。上位约束见[详细软件设计](./DETAILED_SOFTWARE_DESIGN.md)，实现任务见[详细开发需求](./DETAILED_DEVELOPMENT_REQUIREMENTS.md)。

## 1. IFC-01 通用规则

- 所有外部 JSON 为 UTF-8，无重复键；顶层必须是对象，含 `schema_version: "1.0"`。字段默认必填，明确标 `?` 的字段才允许省略；除非标记 `null`，null 不是缺失。未声明字段拒绝。示例用的占位值不包含真实目标信息。
- 整数不是布尔值，禁止 NaN/Infinity；持久时间为 UTC RFC 3339 字符串，时钟可靠性由 runtime 检查。IDs 是非空 ASCII 字符串，前缀标识类型；客户端不得指定数据库递增序号。SHA-256 为 64 个小写十六进制字符。
- `path` 是快照内 `/` 分隔的规范相对路径，无空分段、`.`、`..`、绝对路径、NUL；路径在文件系统层做实际安全校验。`line_start`、`line_end` 为 1-based 闭区间，且 start ≤ end ≤ 对应文件行数。
- 不通过静态结构校验时不得产生成功结论；安全语义由专门校验函数检查。schema 文件为唯一字段/枚举源，本文提供**必要基线而不是完整机器可执行 schema**；CON 必须在实现依赖任务之前提供具体 schema、限制和正反例，经过协调评审后冻结。不得因本文未穷举正文长度而无限读入：CON 应确定与宿主能力一致的协议上限及分页机制；超出返回 `LIMIT_EXCEEDED` 与缺口记录，不截断后假装成功。
- API 返回显式的 `Result[T]`：成功携带 `value`；失败携带 `error.code`、`error.message`、`error.retryable`、`error.details`（不得含 token 或秘密）。机器键为英文，用户报告文本使用所选语言；时间、随机 ID 不参与业务结果等价比较。

## 2. IFC-02 交换对象

下表字段类型记法：`s` 字符串、`i` 整数、`b` 布尔、`A<T>` 数组、`O` 对象、`?` 可省略、`null` 可为空值；所有对象另含版本。引用必须在相同 run/snapshot 内存在；时间、ID、状态和来源由程序生成，不接受模型自定持久主键。完整 schema 须约束所有嵌套对象，而不是只检查这些顶层字段。

| 对象 | 最低必需字段 | 条件和约束 |
|---|---|---|
| `RunConfig` | target、run_dir、report_language、profile、scope、budgets、safety_acceptance | 三根路径分离；安全降级须明确批准及记录；profile 仅影响覆盖，不能降低证据标准。 |
| `Capability` | adapter、adapter_version、checked_at、features | 每项为 `{state: enforced|not_enforced|unknown, evidence?, reason?}`；未知时 reason 必填。能力证据不可包含认证凭据。 |
| `SnapshotManifest` | snapshot_id、hash_algorithm、root_hash、files、excluded、collection_assumptions | 文件含 path、sha256、bytes、line_count、encoding、component、language；不可读及链接需有原因；规模大时使用可顺序读取的分页工件，根摘要覆盖排序后的全量清单。 |
| `Anchor` | snapshot_id、path、line_start、line_end、file_sha256、symbol? | 快照与摘要须一致；只能证实位置存在，不能证明语义。 |
| `Unit` | unit_id、snapshot_id、component、language、ranges、risk_factors | ranges 为 Anchor 的行范围集合；风险分数和规则版本可重算；拆分/重叠不重复覆盖计数。 |
| `TaskSpec` | schema_version、task_kind；其余字段按 `oneOf` 三分支（hunt/recon/verify，`task_kind` const 判别） | hunt 携带 `snapshot_id` 与 `unit`；recon 另带 `role`、语言索引与 `knowledge_hints`；verify 携带 `verify_task_id`、`candidate_id`、`output_contract`、`requires_new_attempt`，引用待验证对象（`input.candidate`）并受 attempt 闸门字段约束，second-opinion 字段并入 verify 分支；packet 绑定当前快照与契约。**[DA-04]**（旧形状 task_id/kind/unit_ids/packet_digest/priority/limits 为早期草案：实现按任务角色分化，schema 已反写为唯一契约来源并经 DESIGN_ALIGNMENT_NOTES DA-04 对齐，旧形状必须被所有分支拒绝。） |
| `Claim` | run_id、task_id、attempt_id、generation、claim_token、expires_at、packet_ref | token 仅返回执行者，不进入持久明文日志；worker 不得将 packet_ref 当任意文件写入口。 |
| `WorkerResult` | task_id、attempt_id、kind、coverage、records、overflow | 与 claim 和任务 kind 对应；records 中允许的类型由 kind 决定；超出时分页或显式 overflow（范围与数量下界）而不是静默裁剪。 |
| `Guard` | guard_id、status、mechanism、anchors、applicability、exceptions | status 为 observed/not_found/unknown；observed 要有锚点，unknown 要有原因；模型声明不自动构成实际保护。 |
| `Candidate` | candidate_id、source、sink、steps、guard_analysis、impact_claim、open_questions、provenance | source/sink 为含锚点的说明；steps 为有序边；open_questions 可为空但决定性未知不可标 confirmed。 |
| `Frontier` | frontier_id、source、boundary、steps、open_questions、provenance | 表示源端半链；boundary 标识符、调用点和参数位置无法确定时标 unknown。 |
| `SinkProbe` | probe_id、sink、boundary、steps、guard_analysis、open_questions、provenance | 不要求 source 或局部无守卫的断言；缺失不应伪造。 |
| `Connection` | connection_id、frontier_id、probe_id、matching_factors、status | status 为 hypothesized/verified/rejected/unresolved；hypothesized 不直接视为实际路径。 |
| `Finding` | finding_id、candidate_refs、verdict、evidence_level、provenance | confirmed 需 source/sink、完整逐跳依据、守卫、影响、前提、rating、remediation；needs_validation 需 blockers 和 validation_plan；rejected 需反证锚点；unverified 需原因。 |
| `Rating` | impact、exploitability、factor_reasons、calculated_severity、calculated_urgency、final_severity、final_urgency、adjustment? | 两因子整数 1～4；调整需 `{operator, reason, direction}`，最多一档且 final urgency 重新计算；待验证只用验证优先级。 |
| `CoverageObservation` | snapshot_id、unit_id、dimension、source、ranges、confidence | dimension 为 inventoried/signal_scanned/context_supplied/observed_read/review_claimed；工具日志缺失时单独标 unknown。 |
| `Usage` | attempt_id、dimension、availability、value、unit、source | availability 为 exact/estimated/unavailable；unavailable 的 value 为 null 且需原因；费用币种和精度明示。 |
| `Budget` | dimension、mode、limit、settled、reserved、availability | mode 为 enforced/observed/unavailable；enforced 需已验证的单次最坏上限；各数字整数，账务事务更新。 |
| `GateResult` | gate_id、status、checks、revision | status pass/fail/not_applicable；每项有解释和证据引用，not_applicable 需理由。 |
| `Error` | code、message、retryable、details | 不得输出 token、认证材料及已知凭据；details 可以为空对象。 |

`Finding` 中 `unverified` 是队列结果而非 verifier 对真伪的裁决；E2 仅适用于符合静态独立验证条件的 confirmed，E1 表示不完整的静态证据，不暗示已经证实。首版不接受 E3。schema 条件和语义校验必须对四种处置给出正反例。

### 2.1 边界示例

以下是**逻辑请求示例**，用于说明字段，直到正式 schema 和安全传输确定前不是可直接执行命令：

```json
{
  "schema_version": "1.0",
  "run_id": "run-example",
  "task_id": "task-example",
  "attempt_id": "attempt-example",
  "generation": 2,
  "claim_token": "<secret>",
  "result_digest": "<sha256>",
  "result": {"kind": "hunt", "records": [], "overflow": [], "coverage": []}
}
```

运行端必须在实际协议中加入 WorkerResult 的全部必填字段；示例中 `<secret>` 与 `<sha256>` 为占位符，不符合生产 schema。不得将提交凭证以命令行参数、环境变量或日志明文传播；会话内传输通过 stdin 或宿主受限工具，具体保密程度取决于宿主。

## 3. IFC-03 应用服务操作

以下为内部语义契约，调用签名的 Python 类型在 CON 与各模块联合冻结后写入代码。任何写操作必须是单个可审计事务，跨文件提交按 DDS-04 的工件发布协议进行。

| 操作 | 输入 → 输出 | 幂等和副作用 |
|---|---|---|
| `doctor` | host selection → Capability[] | 不创建 run、不修改目标或载荷；探测是否启动宿主、消费预算需在执行前告知。 |
| `prepare` | RunConfig → run_id、snapshot_id、plan_summary | 新 run 不读取历史 run；失败保留诊断，不能伪装成 ready；重复请求只有明确提供相同 idempotency key 才可返回既有 run。 |
| `activate` | run_id → revision | ready/paused → active；无能力或配置前置条件返回错误。 |
| `next` | run_id、batch_size、engine_id → Claim[] | 每个 claim 原子预留；零任务区分无可执行工作和预算/暂停，batch 可小于请求但必须说明原因。 |
| `start` | claim credentials → attempt 状态 | 同 attempt 重放返回已有状态；非法代际失败。 |
| `submit` | claim credentials、完整 WorkerResult、digest、可信宿主 usage? → receipt | DDS-04 幂等语义；schema/语义失败不终结 claim，可按限额修正。usage 不由模型自报。 |
| `pause` | run_id、reason → revision | 不再派发；已有 attempt 是否停止单独记录，不能假装完成。 |
| `status` | run_id → 状态、阶段、计数、预算及限制 | 只读；未知字段不可表现为 0。 |
| `finalize` | run_id、reason? → generation/终态或错误 | 参照 DDS-03，未处理和未知必须进入 incomplete；只在工件及门禁对账后提交终态。 |
| `resume` | run_id → 状态及恢复结果 | 检查版本、DB 与工件摘要；不覆盖快照、并发拒绝重复恢复。 |
| `host-fail` | run_dir、claim（run/task/attempt/generation/token）、错误原因与 retryable 分类、max_retries → requeued 或 quarantined 结果 | 可重试失败在限额内回队列：新 attempt generation+1 并重新预留；不可重试或超限转 quarantined 并记 coverage_gap；终止不确定的失败保留预算预留并成为 incomplete 原因；错误结果不得归一为成功（绑定 DSR-065）。 |
| `read_artifact` | run_id、artifact_id → 内容/引用 | 查询范围受 run 限制；不接受调用者自定义绝对路径，鉴权及传输依赖宿主。 |

`run` 挂载的 driver 循环（`run_dispatch_loop`）为内部操作而非新增契约：消费同一服务的 `next → start → submit` 协议并施加 AIMD 并发控制；其行为由 IFC-06 的 `run` 行约束。

### 3.1 错误分类

`INVALID_INPUT`、`UNSUPPORTED_SCHEMA`、`CAPABILITY_UNAVAILABLE`、`SAFETY_APPROVAL_REQUIRED`、`SNAPSHOT_INCONSISTENT`、`PATH_UNSAFE`、`STORAGE_ERROR`、`CORRUPT_RUN`、`INVALID_STATE`、`STALE_ATTEMPT`、`IDEMPOTENCY_CONFLICT`、`BUDGET_EXHAUSTED`、`USAGE_UNKNOWN`、`LIMIT_EXCEEDED`、`HOST_FAILURE`、`GATE_FAILED`。每种错误在契约测试覆盖机器码、是否可重试、无部分提交；同一错误可以带不同 details，但不得依赖易变的人类文字判断。

## 4. IFC-04 CLI 与会话内传输

CLI 是应用服务的包装；命令清单（以 IFC-06 表为准）：`doctor`, `prepare`, `run`, `next`, `start`, `submit`, `status`, `pause`, `resume`, `finalize`, `report`, `mcp`, `guide`, `host-fail`。具体标志名须在 CON 冻结后实现，禁止各引擎自行解释同名参数。对于 `submit`，输入从 stdin 读取含 claim 的 JSON，请勿把 token 放在进程参数。stdout 输出单个机器对象或明确选择的人类格式，进度和诊断走 stderr；非零退出码表示失败，不依赖文本判定。默认不自动运行目标代码；无强制安全能力须显式批准或停止。

driver 拉起的无头 worker 进程不得继承 runner 的标准输入流（stdin 以 DEVNULL 绑定），避免阻塞或吞入 runner 输入；两宿主适配器同契约。**[DA-05]** in-session 的逻辑顺序为 `activate → next → start → 执行 → submit`；driver 走相同服务接口并管理本地进程。子 agent 不可用时可主会话有限顺序运行并披露差异。MCP 是可选适配，初版目标四个工具 `next`, `submit`, `status`, `read_artifact`；若宿主不支持限制 caller/读取权限，应禁止该部署组合或经用户确认风险，不能声称工具数构成安全隔离。MCP 版本、初始化、取消、帧协议和连接安全由 P0 验证；能力不足时可不支持该组合，不能声称 MCP 已完成。

## 5. IFC-05 生命周期与事件投影

每次事件含 `event_id`, `run_id`, `revision`, `event_type`, `occurred_at`, `actor`, `payload_version`, `payload`；revision 在单 run 内递增，event_id 唯一，读侧根据 revision 重建。事件类型由 CON 与 LED 共同在 schema 冻结，至少覆盖 snapshot_published、task_enqueued、attempt_claimed/started/submitted/expired、usage_settled、run_paused/finalized、gate_evaluated；不能只记录最终投影。实现当前实际发射的事件类型（按服务与队列发射点核对）：`run_prepared/activated/paused/resumed/finalized/corrupted`；`task_enqueued`、`attempt_claimed/started/submitted/expired/released/failed_retriable/termination_uncertain`、`verify_task_spec_rejected`；`budget_exhausted`；`inventory_reconciled`、`snapshot_gap`、`guard_baseline`、`recon_invalid_record`、`unit_disposition`、`triage_recorded`；`frontier_recorded`、`sink_probe_recorded`、`connector_paired/unresolved/incompatible/evaluated`、`unpaired_half_chain`；`dedup_suggested`、`candidate_deduplicated`、`second_opinion_enqueued/pending/adjudicated/not_applicable/target_missing`、`verified_findings_stored`、`packet_render_failed`；`coverage_gap`、`analysis_gap`、`hunter_overflow`、`signal_overflow`、`packet_overflow`。其中 `boundary_scan`、`signal_scan` 是 `snapshot_gap` payload 的 `source` 标记，不是独立事件类型；终止不确定的预算保留以 `attempt_termination_uncertain` 事件与 `termination_uncertain_budget_retained` 不完整原因表达。每次 reducer 必须满足重放结果相同；重复提交不得再追加相同业务事件。投影与真实事件不一致时中止后报告，而非自动删除原事件。

发布工件时先生成临时文件、计算哈希、必要的 fsync、同目录原子重命名，再提交引用；由于文件系统与 DB 非原子，崩溃测试覆盖重命名前、后及事务提交前、后。恢复只回收无引用临时工件，不删除已引用或用户文件；丢失已引用工件使 run corrupt。并发提交同一结果按 DDS-04 定义去重。

## 6. IFC-06 首版 CLI 参数与输出

以下为统一开发的基线，P0 的能力实际取证在**全部开发完成后**的统一测试中执行；不存在的宿主参数不能据此假设可用。命令的程序路径由安装适配确定，表中以 `audit` 表示入口；运行不得通过 shell 拼接用户输入。使用 `--json` 时 stdout 只能输出一个 UTF-8 JSON，stderr 放无敏感值的诊断。若会话使用流式模式，须独立定义为另一种格式，不可混用。已实现的输出格式开关（DSR-074）：各子命令接受 `--format {json,human}`，默认 json；json 为面向自动化的冻结信封，human 为面向终端的渲染，退出码与格式无关；旧 `--json` 开关保留为历史默认，显式 `--format` 优先。

| 命令 | 参数／输入 | 操作／输出 |
|---|---|---|
| `guide` | `--query TEXT --language LANG --json` | 轻量安全问答：仅按方法知识与目录卡片作答，不创建 run、事件库或审计卷宗；空、过短或无请求动词的模糊请求返回澄清问题，不静默启动完整审计。 |
| `doctor` | `--host claude|codex|session`，`--json` | 非破坏性能力探测；需要启动真实 CLI 的检查需显式 `--probe` 并提前告知用户；返回 capability 对象数组。 |
| `prepare` | `--target PATH --run-dir PATH --config PATH --json` | config 是 RunConfig；创建新 run、固定快照和计划，返回 run ID、snapshot ID、范围/预算摘要。已有 run 目录拒绝覆盖。 |
| `run` | `--run-dir PATH --host claude|codex --concurrency N --json` | 激活或继续 driver；仅对能力允许的参数启动宿主。用户取消后停止派发并处理在途任务，不以取消信号冒充进程已退出。 |
| `next` | `--run-dir PATH --batch N --json` | 默认只领取会话内任务，N 正整数，返回至多 N 个 Claim 以及不足原因；含令牌的输出只能交给获授权执行者，不进审计日志。 |
| `start` | `--run-dir PATH --json`，stdin 为 claim 认证对象 | 标记指定 attempt 开始，成功返回状态；过期/错误令牌拒绝。 |
| `submit` | `--run-dir PATH --json`，stdin 为 IFC-02 结果对象及 claim 认证对象 | 校验并提交；校验失败保留 attempt 以支持有界修正，凭证不经命令行参数。 |
| `status` | `--run-dir PATH --json` | 返回状态、revision、任务计数、预算及未知项，不返回令牌和原始源码。 |
| `pause` | `--run-dir PATH --reason TEXT --json` | 禁止新领取，返回在途统计；reason 限长且仅保留在本地，禁止输出至可移植导出。 |
| `resume` | `--run-dir PATH --json` | 校验版本、快照和工件；成功恢复到 paused 状态，启动任务仍需 `run` 或 `next`。 |
| `finalize` | `--run-dir PATH --json` | 收敛、门禁、报告与终态；不能收敛时返回原因，不能混合新旧报告代次。 |
| `report` | `--run-dir PATH --json` | 只读取最近完整发布代次及其 ID，不自动对旧格式执行升级；失败明确返回。 |
| `host-fail` | `--run-dir PATH --task TASK_ID? --retryable --max-retries N --json`，stdin 为 claim 认证对象及失败详情 | 上报宿主/worker 失败：可重试失败在 `--max-retries` 限额内 requeue（新 generation 与新预留）；不可重试或超限转 quarantine 并记录覆盖缺口，不把失败规约成成功结果；终止不确定的失败保留预算预留。凭证不经命令行参数。 |
| `mcp` | `--run-dir PATH` | 基于标准输入输出的候选服务；未完成兼容与安全测试不得标为支持，stdout 不混杂诊断。线协议为标准 MCP（JSON-RPC 2.0）：`initialize` → `notifications/initialized` → `tools/list` → `tools/call`，通知帧（无 `id`）零回包；旧式直连（方法名即工具名）保留兼容，线协议格式固定，`--format` 仅接受 json。**[DA-02]** |

JSON 输出信封固定为 `{"schema_version":"1.0","ok":true,"value":{...}}` 或 `{"schema_version":"1.0","ok":false,"error":{"code":"...","message":"...","retryable":false,"details":{}}}`。进程退出码：0 成功，2 输入或 schema 错误，3 状态/并发冲突，4 预算或能力不可用，5 宿主失败，6 存储损坏/IO，7 门禁失败；取消使用 130。错误枚举到退出码由 CON 建立唯一映射；`next` 返回零任务且原因是预算不足时不能以普通成功隐瞒终止，须给 `BUDGET_EXHAUSTED` 或在成功值中明示 `dispatch_state=budget_exhausted`，由入口一致处理。

## 7. IFC-07 存储与具体对象约束

本节是 DB 的逻辑契约，不要求其他模块直接使用 SQL；LED 可增加索引和实现字段，不得减少不变量。

| 表 | 最小列与约束 |
|---|---|
| `runs` | `run_id` 主键、`snapshot_id`、`state`、`schema_version`、`skill_version`、`knowledge_version`、`config_ref`、`revision`；revision 单调递增。 |
| `events` | `event_id` 主键、`run_id`、`revision`、`event_type`、`occurred_at`、`actor`、`payload_version`、`payload`；`(run_id,revision)` 唯一，事件只追加。 |
| `tasks` | `task_id` 主键、`run_id`、`task_key`、`kind`、`state`、`generation`、`spec_digest`；`(run_id,task_key)` 唯一。 |
| `attempts` | `attempt_id` 主键、`task_id`、`generation`、`status`、`token_digest`、`expires_at`、`result_digest?`、`receipt_ref?`；`(task_id,generation)` 唯一。 |
| `budget_dimensions` | `(run_id,dimension)` 主键、`mode`、`limit`、`settled`、`reserved`、`unit`；enforced 下在事务提交时 settled+reserved ≤ limit，超额事实另记并暂停。 |
| `reservations` | `(attempt_id,dimension)` 主键、`reserved`、`settled?`、`state`；使用整数单位，重复结算不得重复扣费。 |
| `artifacts` | `artifact_id` 主键、`run_id`、`kind`、`relative_path`、`sha256`、`size`、`generation?`；路径受 run 根目录约束，文件已发布后才引用。 |
| `coverage_intervals` | `run_id`、`snapshot_id`、`unit_id`、`path`、`dimension`、`start_line`、`end_line`、`attempt_id?`、`source`、`confidence`；计算时按维度和文件做区间并集。 |

约束应使用事务、唯一约束和外键共同实现；DB 只能由应用层访问。不可变事件存放结果/工件引用，而非明文 token。claim 校验在已完成重传路径先检查已完成结果与凭证摘要，再检查过期；对未完成 attempt 才允许依据过期条件拒绝。用量 `u > r` 属于异常事实：事务记录外部报告和能力失效，允许异常态突破账本数值的预期而不能回滚成“未发生”，后续立即冻结派发。

`result_digest` 对完整且通过结构校验的 WorkerResult 规范编码：UTF-8、key 字典序、无额外空白、非 ASCII 原字符、整数规范十进制；不接受浮点、重复键及非有限数。摘要为规范编码 SHA-256。实现与测试必须共享规范化规则；收件时重算并比较，不信任调用者声称的哈希。

## 8. IFC-08 校验器与安全声明

首版 schema 校验子集为 `$schema`、`$id`、`$defs`、仅本地 `$ref`、`type`、`properties`、`required`、`additionalProperties`、`items`、`minItems`、`maxItems`、`uniqueItems`、`minLength`、`maxLength`、`minimum`、`maximum`、`enum`、`const`、`oneOf` 和 `pattern`；`title`、`description` 为仅注释关键字。递归引用、远程引用、未知关键字、超深结构和过长输入明确拒绝；限制值在 CON 的 schema 中定义并固定。`oneOf` 必须恰有一个分支匹配。锚点存在、跨对象引用、评级和提交代际等是语义校验，不借 schema 伪造证据。

所有未探测能力默认为 `unknown`，首版默认不暴露声称已验证的硬 token/费用控制，也不把 MCP 宣称为 OS 沙箱。诊断不得输出认证 token、claim token 或已识别密钥。由宿主是否保留对话日志导致的凭证暴露风险必须披露：stdin/受限工具不是端到端保密证明。
