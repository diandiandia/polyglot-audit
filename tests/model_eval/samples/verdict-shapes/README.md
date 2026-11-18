# Verdict output shape samples (SR-029 / DSR-047)

从真实验证运行抽象出的 **verdict 记录形态样本**——仅保留字段结构（形状），
全部内容为合成虚构值。用途：

1. 验证 worker 输出提取器（`_extract_findings`）对这些形态的兼容性；
2. model_eval 评测的输出契约基准（shape conformance），与 SR-016 一致：
   样本不含任何真实项目信息。

样本清单：
- `confirmed-full.json` — 完整 confirmed：含 rating 嵌套因子理由、
  source/sink、steps、remediation（通过验证器与契约校验的基准形态）
- `confirmed-minimal.json` — worker 常见简化形态：缺 rating/部分档案字段
  （service 侧由候选档案绑定补齐，见 _store_verified_findings）
- `needs-validation-blockers.json` — 带 blockers 与 validation_plan 的未决形态
- `rejected-counter-evidence.json` — rejected 必须携带反证
