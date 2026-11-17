
## 补充（2026-11-17）：第三批运行与工程教训

| # | 问题 | 状态 |
|---|---|---|
| L-10 | 并发事件追加撞 (run_id, revision) UNIQUE 约束 | ✅ 修复：append_event 包 BEGIN IMMEDIATE + 并发回归测试 |
| L-11 | 崩溃 driver 的**有效租约**预留滞留，verify 连底座都领不到 | ⚠️ 开放：reclaim 支持 force 参数（当前只能等租约过期） |
| L-12 | verify 包渲染对真实候选形状崩溃（steps 文本串/端点 {artifact,validation}） | ✅ 修复：manifest 后缀唯一解析 + 解析感知提取 |
| L-13 | scope.include 精确文件路径未收窄快照（10,160 文件仍入清单） | ⚠️ 开放：核查 scope 匹配语义（O-10） |
| L-14 | **fixture 目录字节码缓存污染**：py_compile/导入 fixture 生成 __pycache__/*.pyc → 清点分母抬高（decode_failure 假缺口）→ 组件计数偏移 | ✅ 修复：清理遗留缓存；规则本已排除 __pycache__ 目录；预防=禁止对 tests/fixtures/** 执行 py_compile/导入（流程红线，与 O-12 同族） |
| O-10 | scope.include 精确路径匹配语义未核查 | ⚠️ 开放 |
| O-12 | **finalize 运行期间编辑仓库代码** → 发布中断 → run 终态 corrupt（run-011 实证，编排者自查） | 流程红线：已归档，防御=corrupt 终态诚实拒绝 |
