# 详细软件设计：组件、生命周期与集成

> 状态：待联合评审的实现设计基线，**不是已实现能力**。与[系统需求](./SYSTEM_REQUIREMENTS.md)、[软件设计](./SOFTWARE_DESIGN.md)和[设计审查](./SOFTWARE_DESIGN_REVIEW.md)配套；跨模块交换协议见[接口与数据契约](./INTERFACE_CONTRACTS.md)，派工、依赖和验收见[详细开发需求](./DETAILED_DEVELOPMENT_REQUIREMENTS.md)。
>
> 若本文件和早期文档冲突，以 SR 和本文件的安全约束为准；接口中的待验证项不得实现为未经声明的保障。按用户要求先完成全量开发及测试代码，再统一执行测试；能力探测的实现可先开发，实际探测留待统一测试。开发前冻结接口版本并由涉及的负责人评审。本文中的设计编号为 DDS，不是系统需求编号。

## 1. DDS-01 交付边界与组件图

```text
用户/宿主
   | guide (不创建 run)
   +-- audit -> CLI / in-session / MCP(可选)
                       |
              application / scheduler
        +----------+---+--------+----------+
        |          |            |          |
     snapshot    ledger      analysis   reporting
        |       (budget)    (packets)  (coverage/retro)
     inventory      |            |
        |           +----- host adapters ------+
     knowledge              Claude / Codex / session
        |
    只读冻结快照 <--- worker 读取；目标内容不可信
```

应用层是状态转换的唯一入口；CLI/MCP 不直接修改 SQLite，不从外部接受任意文件写入目的地。报告、门禁、预算、两个引擎共用同一应用服务。MCP 传输使用标准线协议（JSON-RPC 2.0：`initialize` → `notifications/initialized` → `tools/list` → `tools/call`，通知帧零回包；旧式直连保留兼容），仍只经应用服务访问状态 **[DA-02]**。Python 核心仅标准库；具体最小版本由 P0 确认，未确认时不将语法或 SQLite 行为假定为某最低版本。网络、文件写和执行隔离不由 prompt 或 MCP 自身保证。

## 2. DDS-02 模块边界与文件所有权

以下是**计划路径**，不是已存在的文件。每一行是单一负责人负责的写入域，配套测试放在对应子目录；公共入口、跨模块 schema 和集成测试只能由集成负责人合并。测试可用内存假实现，不得伪装成真实 CLI 通过。

| 域 | 计划路径 | 输出／使用 | 所有者 |
|---|---|---|---|
| 入口与集成 | `skill/SKILL.md`, `skill/scripts/audit.py`, `skill/scripts/auditkit/app/`, `tests/integration/` | 命令解析、组合、依赖注入及引擎切换 | INT |
| 契约 | `skill/schemas/`, `skill/scripts/auditkit/contracts/`, `tests/contracts/` | JSON Schema、错误类型、语义校验 | CON |
| 快照清点 | `skill/scripts/auditkit/snapshot/`, `skill/scripts/auditkit/inventory/`, `tests/snapshot/` | 清点、冻结、切块、区间 | SNP |
| 状态预算 | `skill/scripts/auditkit/ledger/`, `tests/ledger/` | 事务、任务、attempt、事件、预算 | LED |
| 分析任务 | `skill/prompts/`, `skill/scripts/auditkit/analysis/`, `tests/analysis/` | 包、结果、候选、连接、验证与定级 | ANA |
| 知识 | `skill/knowledge/`, `tests/knowledge/` | 方法、索引、卡片、信号、合成例 | KNW |
| 宿主 | `skill/scripts/auditkit/hosts/`, `tests/hosts/` | 能力检测、CLI 运行、结果提取 | HST |
| 报告 | `skill/scripts/auditkit/reporting/`, `tests/reporting/` | 覆盖、报告、轨迹、成本和自审 | RPT |
| 安全与验证 | `tools/`, `tests/security/`, `tests/e2e/`, `tests/performance/` | 检查、攻击与集成评测 | QAV |

`tests/fixtures/` 下各团队在自己命名的子目录独占写入；跨团队 fixture 由 QAV 管理。KNW 可按语言拆子目录给不同人员，公共索引由 KNW 统一合并。上述边界不是架构强制路径：移动路径须先由 INT/CON 和相关所有者批准，同时更新任务与契约。

## 3. DDS-03 运行与存储生命周期

### 3.1 初始化与快照

1. `doctor` 不创建审计 run，检测版本、认证和已知隔离能力，输出来源与未知项；不得读取目标执行脚本。
2. `prepare` 验证三种根目录互不重叠、目标可读及运行目录可写；验证预算与安全能力，不满足拒绝。创建新 run 专属目录，禁止覆盖已有 run；初始化文件采用私有权限，系统不支持权限语义时记录能力不足。创建失败不宣称准备完成。
3. Snapshot 以可恢复的准备阶段写入临时目录；仅复制范围内常规文件，默认不跟随链接。保存文件 SHA-256、字节数、相对路径、解码状态、行数和文件类型，禁止路径逃逸。文件无法安全解码可记录为不可分析和覆盖缺口，不按空文件计数。读前后核对文件身份、大小和摘要，并复查目标树；操作系统不提供原子快照时仍可能漏过恢复原状的瞬时变化，必须记录“采集期源稳定”前提。准备提交前失败则 run 为 prepare_failed，不能启动 hunter。
4. 快照根哈希对按 UTF-8 字节排序的规范相对路径、文件类型、长度及内容摘要的无歧义长度前缀编码计算；不包含 mtime 或绝对路径。大小写、非法字节路径和跨平台差异须在 P0 定义并形成测试；不可表示的路径显式失败或排除并记录，不静默归一碰撞。空快照、空文件、不同换行均有独立测试。快照生成后任何篡改使校验失败。
5. 行范围使用 **1-based 闭区间**；空文件无行区间，CRLF 算一行结束，不改变快照字节，末尾换行不额外创造空行。扫描和分块在解码后的统一文本视图使用该行约定；原始 byte 与解析结果均可追溯。

### 3.2 启动、暂停、结束与恢复

运行状态：`preparing → ready → active → paused → active`，可从 ready/active/paused 进入 `finalizing → complete | incomplete`；准备失败为 `prepare_failed`，不可恢复的损坏为 `corrupt`。`complete` 仅代表声明范围与必要门禁完成；预算停止、未处理任务、未知保护或未验证候选产生可枚举 incomplete 原因。持久状态和门禁状态不可用时返回错误而非构造终态。

driver 派发的停止序列按预算维度感知 **[DA-06]**：hunt 领取被 `BUDGET_EXHAUSTED`（验证保留底线）阻断时不全局停止，仍继续派发 verify/second-opinion 任务以消费验证保留底座，直至验证预算也耗尽或队列清空才进入停止；停止原因按维度细分（`budget_exhausted`＝hunt 预算耗尽且仍有排队任务、`verification_reserve_exhausted`＝验证保留底线导致、`queue_drained`＝队列清空、`paused_or_blocked`＝run 非活跃或无成因事件），不以 hunt 预算耗尽冒充验证完成或全局预算耗尽。

`finalizing` 首先禁止新 claim，收敛/取消在途任务，记下未完成与未知用量，按一致数据库读快照生成报告；G3/G4 通过并原子发布所有报告后记录终态。进入收敛前有效租约内的 claimed/running 在途 attempt 先行阻断（`INVALID_STATE`，先 pause 或等租约过期）**[DA-01]**。若无法发布完整报告保留 finalizing 与错误，允许恢复重新生成；禁止出现报告显示 complete 但 DB 是 incomplete。冻结快照被修改或卷宗关键文件缺失时进入 corrupt，保留诊断，不能在同一 run 重新采集。切换引擎前必须暂停，等待已运行任务提交或过期且停止确认，保留预算预留；禁止将活跃任务当作已释放。

## 4. DDS-04 调度、数据一致性与预算

生产者由状态库产生 `queued` 任务，统一应用接口领取；worker 只获得任务 packet、受限快照访问与用于该 attempt 的提交能力，不获得数据库读写权限。会话内如不能从宿主限制其他工具，必须在能力报告中明确，不承诺隔离。调度遵守阶段和风险排序，验证预留不足不能通过丢弃候选“完成”审计。

任务持久状态及 attempt 的区分：

| 操作 | 前置 | 原子效果 | 错误结果 |
|---|---|---|---|
| enqueue | run 可工作；确定性任务键未存在 | 写 task/事件；同任务键同 payload 返回原 ID | 同键不同 payload 为冲突 |
| claim | `queued`，run `active`，预算可预留 | generation+1、创建 attempt、保存 token 摘要及到期时间、预算预留、追加事件 | 无任务、预算不足或状态冲突；不部分提交 |
| start | 当前 attempt/token 有效且未过期 | `claimed → running`，记录开始 | 过期/旧代际拒绝 |
| submit | 当前 attempt 有效且结果通过结构与语义校验 | 写结果工件引用、结算可知用量、done 和事件 | 无效结果可修后重交；旧代际拒绝 |
| retry/expire | 当前 attempt 失败或已过期；旧 worker 能否停止另行确认 | 终结 attempt、记录原因；若可安全重试则新 generation 重新排队 | 成本未知或可能仍在运行时冻结预留，不宣称已停止 |
| cancel | 用户或预算要求停止 | 禁止新领取，记录取消请求及确认状态 | 未确认退出时列为未收敛；不得释放硬预算 |

入队 spec 按 IFC-02 `TaskSpec` 的 `oneOf` 三分支（hunt/recon/verify，`task_kind` const 判别）做 schema 校验，无效 spec 拒绝入队并记录，不落库不可执行形状 **[DA-04]**。claim token 用安全随机数生成，仅存摘要；不进日志或报告；凭证不是审计系统对任意本机用户的认证机制。提交采用 `(run_id, task_id, attempt_id, generation, token)` 和结果 SHA-256：同 attempt 在**有效期内已提交**的相同内容重放返回原回执（不再创建事件）；不同内容报 conflict。已完成后的网络重传可返回原回执，即便时间已过期，但必须 token、generation 和内容均匹配且该 attempt 确已提交；从未提交的过期 attempt 一律拒绝。

SQLite `BEGIN IMMEDIATE` 保护读取/更新和额度预留；事务中含约束和受影响行数检查。driver 可以单写队列，但仍须应对多进程。**lease 到期只允许拒绝旧结果，不证明旧进程停止**：若强预算无法可靠取消与结算，则保留旧预留，同时有足够额度时才能再 claim；否则暂停。默认有效期和续期策略需能力验证，不凭猜测选为通用常数。时钟回拨/未知使用暂停并人工处理，不能降低防护。

每个预算维度的保留量和结算量使用整数最小单位；金额须明确币种和精度，禁止浮点作为货币账本。硬限额仅在可验证最坏调用限额和子调用约束存在时可启用。若可靠最终用量 `u ≤ r`，结算 u 并释放 r-u；未知则保持 r；若上游报告 `u > r`，记录超额、阻断新任务、标记能力失效，不能声称硬上限未破。任务数硬预算以**每次启动 attempt**计数，不按任务去重；墙钟只保证不在截止后派发，不保证进程届时退出。

## 5. DDS-05 分析与闭环

S0 snapshot/inventory/plan → S1 recon → S2 hunt → S3 verify → S5 report → S6 retro；S4 不在首版。每阶段产出由契约校验并落库，可在预算不足时提前进入 finalizing。无法启动 Recon 时不伪造空的安全基线；提示包须携带 `unknown`。

规划不以信号为全覆盖依据。一个分析任务的 packet 绑定快照 ID、单元、规则和显式预算；提示包仅包含目标范围及相关上下文，遇到必要信息溢出则拆分或记录缺口。Kotlin/Scala 的 Java 基座索引按平台三态展开：prepare 时从冻结快照 manifest 扫描 JVM 构建标识（pom.xml、Gradle 构建/设置脚本、`*.sbt`、`.mvn/`），有标识判 JVM，无证据判未知——不展开基座索引并在 packet 行披露 platform unknown，不默认按 JVM 处理 **[DA-03]**。worker 输出 Candidate/Frontier/SinkProbe，任何上限造成的未输出区域通过溢出记录入账；禁止靠更改字段限制掩盖溢出。连接只产出 `hypothesized` 边：符号匹配、参数位置和跨语言转换须 verifier 分别核验；未连接条目保留到报告。

每个验证必须创建与 hunter 不同的 attempt 和新上下文；输入含原候选及独立读取快照权限，不把候选内容当成证据。所有结果需记录锚点、边及其判定。需要外部事实时给 `needs_validation`，仅实际找到证伪证据才 `rejected`。审计来源依赖图保存候选合并关系和验证 attempt；拒绝环状 provenance。定级矩阵和人工调整按 SD-05；调整为新事件，保留旧值与原因，不重写既往事件。

## 6. DDS-06 报告、门禁和自审

每个输出在同一 `report_generation_id`、同一 ledger revision 上派生；先完整写入暂存目录，校验计数与引用后发布 generation，再写入终态。崩溃重启后按 revision 检测未完成的生成，不把不同 generation 混合。主报告含完整/不完整、范围、快照、覆盖、发现、待验证、局限及成本未知；结构化结果包括全部四种验证处置。覆盖以纳入文件/行区间并集统计，各深度彼此独立，不强制存在可观测读取；每条数据包括来源及可信度。

G0 快照、清点、计划；G1 单元、溢出及未完成；G2 候选/裁决/锚点/定级；G3 报表和事件对账；G4 自审生成与导出条件。每道门禁应返回 `pass|fail|not_applicable`、检查项及证据引用；fail 会禁止 complete，但不妨碍有诊断的不完整报告。`not_applicable` 不等于 pass，理由必须存在。G1/G2 公式只对已派发任务对账，存在“计划了但从未派发”的结构性盲区；终态判定另按计划覆盖不变量硬规则执行 **[DA-01]**——plan_units 与 done 任务对账，零派发或未达 done（verify 亦接受显式 quarantine）的单元强制 `incomplete(unprocessed_units)`，不因 lost=0 或任务数对账相等判 complete；该不变量当前为 finalize 硬规则，是否并入 G1 公式定义由设计审查确认。

本地自审包括流程、成本、知识质量与能力缺口；不可用数据用 null 和原因，不将未知赋值为零。对外导出默认关闭；只允许经过审查的枚举/约束聚合值，不导出自由文本，审核失败不导出。产物包含敏感信息，日志也不得输出 claim token、认证材料和已知凭据值。通用检测不能证明完全识别所有秘密；测试已知样本，人工审核由维护者负责。

## 7. DDS-07 P2 端到端验收夹具

全部由团队新写的合成代码，不复制历史审计内容：

| 编号 | 夹具 | 可复现期望 |
|---|---|---|
| E2E-01 | Python：请求处理输入跨两个文件流向不安全反序列化，分配不同 unit；附同样数据被允许名单转换的反例 | 生成可回溯的 source→sink，独立 verifier 证据完整可 E2；防护反例不得确认；全程用测试宿主，真实模型结果另记。 |
| E2E-02 | JavaScript + TypeScript：用户可控值进入 DOM 敏感操作；同目录有安全文本赋值 | TS 同时考虑 JS 运行时；候选及反例处理可查。 |
| E2E-03 | Go：安全校验错误被忽略导致失效开放；另有无安全影响的普通 I/O 错误 | 前者能进入验证，后者不得仅因忽略错误升级成 confirmed。 |
| E2E-04 | 两 unit 分别含 frontier 与悬空 sink，另有同名但不兼容参数位置的边界 | 连接是待证假设；错误连接不能确认为事实；未连接项进入未决/缺口。 |

对于使用模型的检出和驳回，测试需保存模型、版本、预算、执行次数和证据；不把一次随机结果等同于可靠召回。确定性调度/报告使用固定合成 worker 响应，需与真实双宿主评估分开。每种受支持引擎对同一固定响应集产出等价**规范化**状态与报告内容，排除时间、随机 ID、worker 运行元数据；真实模型输出不要求逐字一致。
