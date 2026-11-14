# polyglot-audit 操作手册（OPERATIONS）

对应需求：DSR-080 / SWR-012 / SWR-026 / SWR-029。设计依据：`docs/design/SOFTWARE_DESIGN.md`、`docs/design/INTERFACE_CONTRACTS.md`、`docs/design/SOFTWARE_DESIGN_REVIEW.md`。

> **状态声明**：本手册中所有"已支持版本""已验证能力"均为**候选**，实际支持范围由统一测试（`tools/run_all_tests.py` 与双宿主实测）结论决定；未实测能力一律保持 unknown，不标为受支持（设计原则 8：能观测的不靠声明）。发布前须完成 `docs/RELEASE-CHECKLIST.md` 中 GATE-01～07 证据。

---

## 1. 安装前置

| 项目 | 要求 | 说明 |
|---|---|---|
| Python | 3.8 或以上（**候选下限，统一测试后确定**） | 全部代码仅使用 Python 标准库 |
| 第三方依赖 | **零** | 不安装任何 pip 包；`sqlite3`、`argparse`、`json`、`pathlib` 等均为标准库 |
| 磁盘 | 建议预留目标仓库体积 1～2 倍 | 快照为内容寻址的私有冻结副本 |
| 操作系统 | Linux / macOS（**候选**；Windows 未测） | SQLite 文件系统约束见 §6.2 |

校验安装：

```bash
python3 -I skill/scripts/audit.py doctor          # 静态探测
python3 -I skill/scripts/audit.py doctor --probe  # 主动探测已安装的宿主 CLI
```

`doctor` 只读探测，不创建任何文件。

## 2. 安装与卸载

### 2.1 通用安装（两个宿主相同部分）

1. 将仓库放到任意目录（下称 `<repo>`），skill 载荷位于 `<repo>/skill/`。
2. 确认三根分离约束：目标仓库、skill 载荷（`<repo>/skill`）、输出 run 目录三者互不重叠、不含逃逸符号链接。
3. 运行 `doctor` 确认 Python 与宿主 CLI 可用。

### 2.2 Claude Code 安装（**候选——实际支持由统一测试决定**）

- 推荐方式：将 `<repo>` 作为 skill 目录安装到 Claude Code 的 skills 路径（如 `~/.claude/skills/polyglot-audit`，或项目级 `.claude/skills/polyglot-audit`），入口为 `skill/SKILL.md`。
- 配置要点：宿主需允许子进程调用 `python3`（`skill/scripts/audit.py`）；审计过程中模型按任务协议领取/提交（claim/submit），凭证只经 stdin 传递。
- 能力探测：`python3 -I skill/scripts/audit.py doctor --host claude --probe`。

### 2.3 Codex CLI 安装（**候选——实际支持由统一测试决定**）

- Codex CLI 以子进程驱动方式使用同一入口 `skill/scripts/audit.py`（`--host codex`）；MCP 候选服务器为 `audit.py mcp --run-dir <DIR>`。
- 配置要点：结构化输出、委派、只读/执行/网络与认证能力均须通过 `doctor --probe` 实测；未验证项保持 unknown，不静默降级。
- 能力探测：`python3 -I skill/scripts/audit.py doctor --host codex --probe`。

### 2.4 卸载

1. 停止正在运行的进程（`run` 驱动循环、`mcp` 服务器）；中断使用 Ctrl-C（退出码 130）。
2. 删除已发布的 run 卷宗（可选）：直接删除对应 `<run-dir>/`（含 `events.db`、`snapshot/`、`report/`）。
3. 从宿主 skills 路径移除 skill 目录（Claude：删除 `~/.claude/skills/polyglot-audit` 或项目级对应目录；Codex：移除 CLI 配置中的 skill/驱动条目）。
4. 删除 `<repo>` 本身。无全局包、无缓存目录、无注册表残留需要清理。

## 3. 两种模式

| 模式 | 入口 | 是否建卷宗 | 适用 |
|---|---|---|---|
| **guide** | `audit.py guide --query "<问题>" --language <lang>` | **否**——不创建 run 目录、events.db 或任何审计产物 | 即时安全问答、方法咨询 |
| **audit** | `audit.py prepare/run/...` | **是**——完整卷宗与门禁 | 正式的、有证据链的仓库审计 |

分流规则（DSR-032）：

- guide 对**模糊请求**（空查询、少于 8 字符、不含请求动词如 问/查/审/分析/audit/how 等）返回 `status: "ambiguous"` 与澄清问题，不执行任何动作；动词白名单可在 `GuideService` 构造时配置。
- audit 模式缺 `--target` / `--run-dir` / `--config` 任一参数时 argparse 直接非零退出，不运行；齐备时由服务层继续验证（路径安全、配置 schema、G0）。

## 4. audit 使用流程

```bash
# 0. 预检
python3 -I skill/scripts/audit.py doctor [--host claude|codex] [--probe]

# 1. 准备：校验三根分离与配置，冻结快照，规划任务单元，评估 G0
python3 -I skill/scripts/audit.py prepare --target <目标目录> --run-dir <输出目录> --config <config.json>

# 2. 激活并驱动
python3 -I skill/scripts/audit.py run --run-dir <输出目录> [--host claude|codex|session] [--concurrency N]

# 3. 领取 / 开始 / 提交（claim 与结果一律走 stdin，凭证不经 argv）
python3 -I skill/scripts/audit.py next   --run-dir <输出目录> [--batch N]
python3 -I skill/scripts/audit.py start  --run-dir <输出目录>   < claim.json
python3 -I skill/scripts/audit.py submit --run-dir <输出目录>   < payload.json

# 3b. 宿主/worker 失败上报（可重试则任务重新入队，超出重试上限则隔离并记覆盖缺口）
python3 -I skill/scripts/audit.py host-fail --run-dir <输出目录> [--task <task_id>] [--retryable] [--max-retries 2] < fail.json

# 4. 观测与控制
python3 -I skill/scripts/audit.py status --run-dir <输出目录>
python3 -I skill/scripts/audit.py pause  --run-dir <输出目录> [--reason TEXT]
python3 -I skill/scripts/audit.py resume --run-dir <输出目录>   # 先校验完整性再恢复

# 5. 收尾：评估 G1..G4 门禁，发布报告；incomplete 会透出 incomplete_reasons/coverage_gaps
python3 -I skill/scripts/audit.py finalize --run-dir <输出目录>
python3 -I skill/scripts/audit.py report --run-dir <输出目录>

# 6. （候选）MCP stdio 四工具服务器
python3 -I skill/scripts/audit.py mcp --run-dir <输出目录>
```

`config.json` 最小示例（与 tests/e2e 用法一致）：

```json
{
  "schema_version": "1.0",
  "target": "/abs/path/target",
  "run_dir": "/abs/path/run",
  "report_language": "zh",
  "profile": "standard",
  "scope": {"include": ["*.py"], "exclude": ["tests/*"]},
  "budgets": [{"schema_version": "1.0", "dimension": "tasks", "mode": "enforced", "limit": 20, "settled": 0, "reserved": 0, "unit": "tasks", "availability": "exact"}],
  "safety_acceptance": {"allow_unverified_execution": false, "allow_unverified_network": false, "allow_unverified_write": false, "user_approved": true}
}
```

OS 级隔离未经验证时 `safety_acceptance.user_approved` 必须为 `true` 才能启动（SKILL.md §2）。

## 5. 命令参考表（冻结接口，DSR-074）

全部子命令输出统一 JSON 信封：成功 `{"schema_version":"1.0","ok":true,"value":{...}}`；失败 `{"schema_version":"1.0","ok":false,"error":{"code","message","retryable","details"}}`。诊断信息只写 stderr。

| 子命令 | 关键参数 | stdin | 作用 |
|---|---|---|---|
| `doctor` | `--host claude\|codex\|session`、`--probe` | — | 探测宿主环境、Python、CLI 可用性（只读） |
| `prepare` | `--target`、`--run-dir`、`--config`（均必填） | — | 校验并冻结快照、规划单元、评 G0 |
| `run` | `--run-dir`、`--host`、`--concurrency` | — | 激活 run 并进入驱动循环 |
| `next` | `--run-dir`、`--batch` | — | 事务性领取下一批任务（含 claim_token） |
| `start` | `--run-dir` | claim JSON | 标记 attempt 为 running |
| `submit` | `--run-dir` | claim + result JSON | 幂等提交 worker 结果（凭证/claim 不从 argv 读取） |
| `status` | `--run-dir` | — | 输出 run 状态、revision、任务与预算计数 |
| `pause` | `--run-dir`、`--reason` | — | 安全暂停调度 |
| `resume` | `--run-dir` | — | 校验快照与产物完整性后恢复 |
| `finalize` | `--run-dir` | — | 评 G1..G4、对账并发布报告（透出 `incomplete_reasons`/`coverage_gaps`） |
| `report` | `--run-dir` | — | 读取已发布的 `REPORT.md` |
| `mcp` | `--run-dir` | JSON-RPC 行 | stdio MCP 候选服务器（next/submit/status/read_artifact） |
| `host-fail` | `--run-dir`、`--task`、`--retryable`、`--max-retries` | claim + 失败详情 JSON | 上报宿主失败：可重试则重排（generation+1），否则隔离并记覆盖缺口（DSR-065） |
| `guide` | `--query`、`--language` | — | 轻量问答；模糊请求返回澄清问题；**不建卷宗** |

### 退出码语义（与 `auditkit/contracts/errors.py` 一致）

| 退出码 | 语义 | 典型错误码 |
|---|---|---|
| 0 | 成功 | — |
| 2 | 输入 / schema / 超限 | `INVALID_INPUT`、`UNSUPPORTED_SCHEMA`、`PATH_UNSAFE`、`LIMIT_EXCEEDED` |
| 3 | 状态 / 并发冲突 | `INVALID_STATE`、`STALE_ATTEMPT`、`IDEMPOTENCY_CONFLICT` |
| 4 | 预算 / 能力不可用 | `BUDGET_EXHAUSTED`、`CAPABILITY_UNAVAILABLE`、`SAFETY_APPROVAL_REQUIRED`、`USAGE_UNKNOWN` |
| 5 | 宿主失败 | `HOST_FAILURE` |
| 6 | 存储 / 损坏 / 快照不一致 | `STORAGE_ERROR`、`CORRUPT_RUN`、`SNAPSHOT_INCONSISTENT` |
| 7 | 门禁失败 | `GATE_FAILED` |
| 130 | 用户取消（SIGINT/Ctrl-C） | — |
| 1 | 未分类内部错误（`INTERNAL_ERROR`） | — |

未知子命令或非法参数一律非零退出。

## 6. 诊断与恢复

### 6.1 doctor

`doctor` 覆盖 Python 版本、标准库可用性、宿主 CLI 安装与版本、以及（`--probe` 时）结构化输出/委派/只读/执行/网络/认证等能力探测。探测结果如实记录 unknown；unknown 不等于可用，也不自动降级。

### 6.2 损坏 run（CORRUPT_RUN / STORAGE_ERROR）

- 现象：`resume`/`finalize` 报 `CORRUPT_RUN`（卷宗产物被移动或修改）或 `STORAGE_ERROR`（无法读写 events.db / 报告目录不可写）。
- 处置：先 `status` 确认状态；**不要手工改 events.db**。若为产物外移，可将其放回原路径后 `resume` 重新校验；若 events.db 本身损坏，该 run 视为不可恢复——保留现场，另起 `prepare` 新 run。SQLite 依赖文件系统原子性，网络文件系统上的 run 目录不受支持（适用范围以 GATE-02 证据为准，**候选**）。
- 损坏的 run 不产出报告：finalize 在校验失败时置状态 `corrupt` 并拒绝发布。

### 6.3 暂停与恢复

- `pause` 停止调度（状态 `paused`），已领取任务仍按原 attempt 有效期处理；`resume` 先做完整性校验（快照摘要、产物清单），通过后才回到可调度状态。
- 进程中断（130 / 崩溃）：重入用 `resume`；事件账本为 append-only，重启后由事件重放重建状态。迟到的提交按租约 generation 拒绝（`STALE_ATTEMPT`，退出码 3），不会污染已重排的 attempt。

### 6.4 事件重放

`events.db` 中 `events` 表为唯一事实来源；恢复/对账（`resume`、`finalize` 的对账段）通过顺序重放事件核对 revision、任务状态与产物引用。人工核查可直接只读查询：`sqlite3 <run-dir>/events.db "SELECT * FROM events ORDER BY id"`。

## 7. 已支持版本（**候选——统一测试后确定**）

| 项 | 状态 |
|---|---|
| Python 下限 | 候选 3.8+；以 GATE-07 兼容测试结论为准 |
| Claude Code CLI 版本 | 未实测——保持 unknown，不标受支持（GATE-01） |
| Codex CLI 版本 | 未实测——保持 unknown，不标受支持（GATE-01） |
| SQLite 文件系统适用范围 | 以 GATE-02 故障注入结论为准 |
| JSON Schema 子集 / CLI+MCP 接口版本 | `schema_version: "1.0"`；完整 JSON Schema 兼容性不声称（GATE-07） |

发布前必须先完成 `docs/RELEASE-CHECKLIST.md`。

## 8. 已知限制

1. **无 OS 级沙箱**：MCP/提示封装只是传输隔离；执行/网络/写入隔离未验证时需用户显式批准。
2. **无 token/费用硬预算声称**：并发任务实际花费不可预知，硬上限仅在预算维度可强制（任务数）时成立；其余为软预算（GATE-03）。
3. **complete ≠ 安全**：`final_state: "complete"` 只表示流程与门禁完整，不证明无漏洞。
4. **guide 不写盘**：guide 模式的回答不构成审计结论，也不产生证据。
5. **目录名册是引导不是围栏**：语言卡片目录不构成完整漏洞类枚举。
6. **导出默认关闭**：跨运行/跨仓库导入导出须人工审核，失败关闭（GATE-06）。
7. **性能/成本数字是目标假设**：未完成规定口径测量前不得对外引用（GATE-05）。

## 9. 故障排查速查

| 现象 / 错误码 | 退出码 | 排查 |
|---|---|---|
| `PATH_UNSAFE` | 2 | 三根目录重叠或存在逃逸 symlink；改为互不嵌套的绝对路径 |
| `SNAPSHOT_INCONSISTENT` | 6 | 快照采集期间目标被修改；确保目标静态后重试 `prepare` |
| `BUDGET_EXHAUSTED` | 4 | 预算到达；查看 `NEEDS-VALIDATION.md` 的部分结论或调大预算 |
| `CORRUPT_RUN` | 6 | 见 §6.2；勿手改 events.db |
| `STALE_ATTEMPT` | 3 | 提交晚于租约；重新 `next` 领取新 attempt |
| `IDEMPOTENCY_CONFLICT` | 3 | 同 attempt 用了不同 digest 重复提交；核对提交内容 |
| `GATE_FAILED` | 7 | 查看 finalize 输出的 `gates` 与 `incomplete_reasons`；补证据或接受 incomplete |
| `USAGE_UNKNOWN` | 4 | 宿主未回传统计；确认宿主遥测能力，不得伪造用量 |
| guide 一直返回 ambiguous | 0 | 查询需 ≥8 字符并含请求动词；或调整 `GuideService` 动词白名单 |
| 命令退出 1 / `INTERNAL_ERROR` | 1 | 查看 stderr 诊断；多为路径不存在或环境问题，提 issue 附 `doctor` 输出 |
