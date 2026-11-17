# 真实项目审计运行教训记录（Run Lessons）

> 状态：持续追加。来源：ZCode（zai-org，18,708 文件 TypeScript/TSX monorepo）首次真实审计，run-001~008（2026-11-16），快照 `snp-2df5116f0966`。
> 性质：运行期工程教训与开放问题。设计层勘误另见 `docs/design/DESIGN_ALIGNMENT_NOTES.md`（DA-01~05）。运行数据卷宗：`/root/zcode_run/run-001 ~ run-008`（run-008 为首个成功贯通轮，run-001~007 保留为迭代历史）。

## 1. 已暴露并已修复的缺陷（六轮"发现-修复-重测"）

| # | 轮次 | 缺陷 | 根因 | 修复 | 提交 |
|---|---|---|---|---|---|
| L-01 | run-001 | 租约 300s < 真实 LLM 任务时长 → `StaleAttemptError` **炸掉整个审计循环** | 合成 worker 秒级完成，真实调用 3-10 分钟；循环对 submit 的 StaleAttempt 无捕获 | CLI `--lease-seconds`（真实跑 1800）+ 循环内任务级重排（走 report_host_failure） | 9cd7d43 期间 |
| L-02 | run-002 | 适配器超时 120s 误杀真实任务 → 可重试失败 → 熔断 9 连败 → **mass-quarantine 147 任务** | adapter 默认 `timeout_seconds=120` 为探测级数值，非审计任务级 | CLI `--task-timeout`（真实跑 1200） | 9cd7d43 期间 |
| L-03 | run-002 | enforced `tasks` 预算是**并发上限**而非累计上限——"审计前 10 个任务"无法表达，driver 燃烧全部队列 | 预算语义按设计 §5.2（预留/结算）实现正确，但缺会话级累计派发上限的入口 | CLI `--max-tasks` → run_dispatch_loop `max_batches`；剩余单元如实 incomplete | 9cd7d43 期间 |
| L-04 | run-003 | 真实模型"散文+裸 JSON"输出（无围栏）解析失败 → 任务隔离 | 提取器只认 ``` 围栏 | 鲁棒提取：围栏 → 首个`{`到末个`}`回退 | b38d868 后 |
| L-05 | run-003 | `INTERNAL_ERROR` **吞掉 traceback**（stderr 0 字节）→ 崩溃无法诊断 | CLI 顶层异常处理只打 str(ex) | traceback 落 stderr（诊断走 stderr 符合 IFC-04） | b38d868 后 |
| L-06 | run-004 | coverage range 缺字段 → `rng["path"]` 硬崩循环；worker_result.schema 对 coverage/ranges **零约束**（SR-025 违反） | schema 写的是假想形状，真实模型不产 schema_version 等字段 | schema 收紧（ranges 必填 path/line_start/line_end）+ DSR-018 有界格式重试 + 任务级异常隔离 | b38d868 后 |
| L-07 | run-007 | 真实模型 candidate.source 为字符串 → 去重指纹 `.get` 崩溃 | hunter 按 `"source" in rec` 分类，字符串 truthy 被当 dict 用 | hunter 按端点**类型**分类；dedup 池守卫（非契约形状 → analysis_gap 定位拒绝） | 1f4e5af |
| L-08 | 结构性 | coverage 记账依赖**模型自报**——真实模型不稳定产出，重试烧真实 LLM 调用 | 违反设计原则 1（记账交给程序）与 SR-021（自述不能替代观测） | coverage 改为程序派生：从工具包发布的 packet 解析 `context_supplied` 区间；模型自报条目如实丢弃并计数到 stderr | 1f4e5af |
| L-09 | 结构性 | packet 输出契约是散文描述，模型不知道要产哪些字段 | 违反"一处定义处处派生" | 输出契约从 worker_result.schema 派生枚举 envelope 字段，注入每角色 prompt | 1f4e5af |

## 2. 已暴露、尚未修复的开放问题（按危害排序）

| # | 问题 | 证据 | 影响与建议 |
|---|---|---|---|
| O-01 🔴 | **packets.py 渲染真实单元崩溃**：`packet_render_failed` ×15，真因 `AttributeError: 'str' object has no attribute 'get'`（与 L-07 同类，但只修了 dedup 没修 packets）——某真实 T1 单元 3 次尝试全灭，该高优单元当前无法被审计 | run-008 events `packet_render_failed`；task-b92c9a9117ee | packets.py 对真实 unit/guard 形状做与 L-07 同等的类型防御；真实失败样本固化为 fixture |
| O-02 🟡 | **真实宿主成本遥测缺失**：claude headless 输出无 usage block → COST.md Token 计量 unavailable（"usage records were persisted but none carried a token-dimension value"） | run-008 COST.md；usage_settled 事件 availability 全部 unavailable | claude/codex adapter 从 CLI JSON 输出提取 usage 字段（claude --print 结果含 usage 时提取；codex exec --json 探索）；SR-020 在真实宿主上可观测 |
| O-03 🟡 | **COST.md 分母口径误导**："总执行任务数 4464" 实为全部入队任务（含未执行的 4457）——执行数应单列 | run-008 report/COST.md | cost.py 拆分 `total_enqueued` 与 `total_executed`，标签对齐 |
| O-04 🟢 | **stop_reason 消歧缺验证底座场景**：run-008 实际因预算验证底座（verify reserve floor）停止派发，标注为 `paused_or_blocked`（应为 budget_exhausted 类） | run-008 driver output；`_stop_reason_for_drain` | 消歧逻辑补"验证底座耗尽"事件/状态判断 |
| O-05 🟡 | **packet 分页/拆分未实现**（DSR-059）：真实单元远超 16k 字符容量，只有溢出记录没有分页——真实大单元审不了 | run-008 `packet_overflow` ×4 与 15 次渲染失败 | 按 DSR-059 实现分页或拆分任务；容量参数化 |
| O-06 🟢 | **connector 双向子串匹配宽松**：`lib.encrypt` ~ `encrypt` 即配对，可能误配 | SC 组 SWR-005 验收记录 | 真实数据下量化误配率；收紧策略待设计审查 |
| O-07 🟢 | **未知语言占 51%**（9,546 个 md/svg/txt/json/config 文件）：真实仓库非代码资产占比过半，通用方法面对这些的审读策略未定义 | run-008 inventory_reconciled by_language | 定义非代码资产的清点/审读策略（文档类 secrets 泄漏检查等） |
| O-08 🟢 | **codex headless 本沙箱不可用**（300s+ 不完成）：codex 引擎组合无法实测 | probes.py 实测；test_real_hosts skip | 环境问题非代码缺陷；真实环境实测后再评估 |
| O-09 🟢 | verifier `factor_reasons` 罐头兜底待收紧 | SB 组 SWR-011 验收记录 | 与调用方一并强改为必填（H′ 已将 confirmed 缺理由降级 needs_validation，verifier 内部罐头仍在） |

## 3. 真实运行正向验证清单（同一轮确认按设计工作）

- 三根分离 + 18,708 文件内容寻址快照（root_hash 稳定，重 prepare 幂等）
- 组件识别：真实 npm/Gradle 根（apps/zcode-cli 353、packages/adapters 446…），default=0
- JVM 平台证据：`packages/android/build.gradle.kts` 检出（DA-03 实战）
- 三路清点对账闭合（18,708 = included，reconciled=true）
- recon 守卫基线、AIMD 并发爬升 1→5、预算验证底座停止派发、熔断与隔离
- 门禁诚实：G1/G2 fail（计划未完成）、G3/G4 pass；终态 incomplete 如实
- 全介质脱敏、226 个显式 coverage gaps、1 个 unverified 候选进 NEEDS-VALIDATION

## 4. 流程教训

1. **合成套件对真实数据形态存在系统性盲区**：六轮缺陷无一来自合成场景——全部来自真实模型输出形态与真实仓库规模参数。整改：把 run-008 的真实 worker 输出固化为 fixture（待办 O-10）。
2. **"诚实 unknown"会掩盖代码缺陷**：探测/结算失败与能力缺失产出相同状态——real_cli 测试必须区分断言（L-01/L-02 的教训，已部分实施）。
3. **每轮 bounded real run 都是廉价的真实测试**：run-001~008 每轮以 ≤10 任务预算暴露 1-3 个缺陷，成本远低于全量盲跑。

## 5. 第二批真实运行教训（run-009b~011，验证闭环迭代）

| # | 问题 | 根因 | 状态 |
|---|---|---|---|
| L-10 | 并发事件追加撞 (run_id, revision) UNIQUE 约束 → STORAGE_ERROR | EventStore 的 revision SELECT-then-INSERT 不在事务内 | ✅ 已修复：append_event 包 BEGIN IMMEDIATE + 回滚；并发回归测试 |
| L-11 | 崩溃 driver 的**有效租约**预留滞留（reclaim 只回收过期）→ verify 连底座都领不到 | 设计空白：无管理路径处理"进程死亡但租约未过期" | ⚠️ 开放：reclaim 增加 force 参数或租约上限收紧 |
| L-12 | verify 包渲染对真实候选形状崩溃（steps 为文本串、端点为 {artifact,validation}）→ 熔断隔离 6 个验证任务 | service 层未做与 packets 同级的形状防御 | ✅ 已修复：路径按 manifest 后缀唯一解析、解析感知提取、渲染失败 3 次熔断隔离 |
| L-13 | scope.include 精确文件路径**未收窄**快照（10,160 文件仍入清单） | scope 匹配语义未核查 | ⚠️ 开放：核查 scope 匹配实现（RUN-LESSONS O-10） |
| O-12 🔴 | **finalize 运行中修改代码** → 发布中断 → run 终态 corrupt（本次 run-011） | 流程缺陷：代码编辑与运行中 finalize 并发 | 流程红线：finalize 运行期间禁止编辑仓库代码；corrupt run 按设计需新 run 替代 |

第二批已修复的生产缺陷（验收测试派生）：
- finalize 合并点 SR-011 降级：confirmed 缺 rating 因子理由 → needs_validation（保留全部已验证证据与 blockers）
- service store 路径同步 H′ 降级语义（verifier 与 service 双路径一致）
- 真实候选元数据绑定：verified finding 缺 title/issue/source/sink/steps 时从 verify spec 的 candidate 档案补齐（程序拥有的卷宗数据）
- 畸形候选去重池守卫 + hunter 端点类型分类（字符串端点不再崩指纹计算）
- coverage 记账程序派生（packet 内容 = 程序观测事实，模型自报丢弃并计数）
