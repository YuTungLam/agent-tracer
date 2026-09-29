# 参数来源分析与 NeuroTaint 复现进度

## Material Passport

- Origin Skill: academic-research-suite
- Origin Mode: engineering implementation / recorded-trace analysis
- Origin Date: 2026-09-08
- Verification Status: 工程实现和固定日志分析已验证；来源正确性尚未完成人工核查
- Version Label: provenance-prefix-v1

## 当前能做什么

从既有 recorder 日志按顺序重放事件，在每个 `TOOL_CALL_PROPOSED` 处冻结当时的模型请求、可见来源和参数候选。新增了三项产物：

1. 参数级精确匹配 baseline：结构化标量相等，或有字符边界的完整文本匹配。
2. `nt_style_lcs_v1`：依据 NeuroTaint 论文实现 Tier 2 的最长公共子序列比较。
3. 独立核查包与 HTML 证据浏览器：标注文件不包含算法预测、分数、未来结果或 evaluator 标签。

2026-09-08 后续新增可选 `nt_style_semantic_v1`：固定版本本地 MiniLM 的 Tier 3 整段与 Tier 4 分块组件，保留 token 截断、编码范围和覆盖率。方法假设、安装和新一轮结果见 [SEMANTIC.md](SEMANTIC.md)。各组件独立评分，尚未实现完整级联。

**本页描述 `provenance` 命令的离线历史前缀分析。** 现已另外接入 opt-in live 回调，真实执行前记录与重放一致性见 [ONLINE-RESULTS.md](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/ONLINE-RESULTS.md)。`ProvenanceTracker.consume(event)` 的测试确保后续事件不会回改已经产生的分析。当前仍没有独立来源准确率、恶意传播判定或因果结果。

## 使用方式

在实验目录执行；只读取已有文件，不使用 `.env` 或调用模型：

```bash
.venv/bin/dojo-lab provenance \
  --batch runs/20260907T025045Z-clean-pilot-b93eae95 \
  --output reports/20260908-provenance-pilot-v1
```

也可重复指定 `--run`，分析若干完整且通过审计的记录。输出目录必须全新，且不能位于输入 run 或其冻结 batch 内。原始文件保持不变。批次中未开始的槽位只登记为待运行，不算归因样本；已开始但没有完整记录的试次会使导出明确失败。

| 输出 | 内容 |
| --- | --- |
| `analysis.json` | 方法配置、来源日志与实现哈希、请求前缀、调用和字段候选 |
| `candidates.jsonl` | 每行一个叶参数的基线预测，未核查 |
| `annotations/items.jsonl` | 同一批叶参数的空白核查材料，不含预测 |
| `annotations/instructions.md` | 标签含义、坐标、歧义与授权判定填写方式 |
| `index.html` | 展开参数查看来源文本及高亮位置，可进入原始时间线 |

`runs/` 和 `reports/` 仍被 Git 忽略。代码和方法记录已纳入版本管理；换电脑需要另行同步所需日志。

本轮已生成 [证据报告](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260908-provenance-pilot-v1/index.html) 和 [空白核查包](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260908-provenance-pilot-v1/annotations/items.jsonl)。

## 核心输入与时间边界

- source 取自实际 `MODEL_REQUEST.data.body.messages` 文本。tool 来源必须有匹配的 `TOOL_OUTPUT_EXPOSED`，其 `source_result_event_id`、调用 ID、消息位置、文本和 episode 均须一致。
- 工具结果必须发生在相应请求之前；请求发出之后得到的返回值不能作为该请求的来源。一个响应提出多个调用时，各调用使用同一请求的来源快照。
- 用户、system/developer 消息、assistant 文本与历史 assistant 的工具参数单列为候选，避免把它们的信息误归给工具输出。工具 schema 常量和不可见内部推理不属于本轮来源范围。
- 不读取 runtime 返回对象中未曝光的字段、`TOOL_RESULT` 的旧调用参数元数据、初始环境隐含内容或 evaluator 结果。
- source ID 是 run/episode 内文本部件的稳定标识；同一工具结果的重复曝光可以复用该标识。文本部件与独立工具执行不是同一个计数单位。
- `argument_path` 是相对 `TOOL_CALL_PROPOSED.data.arguments` 的 RFC 6901 JSON Pointer，保留数组下标。位置使用 Unicode 码点的半开区间 `[start, end)`。
- 完整日志审计是导出资格检查，不是在线预测输入。空白标注文件也不被 `ProvenanceTracker` 读取。

## 两个 baseline 的定义

### 精确匹配：`exact_v1`

先将实际出站文本尝试解析为 JSON/YAML 的字段坐标，使用安全的语法树读取，不构造对象、不执行标签。遇到别名、重复键或超出资源范围的结构时拒绝结构解析，另行保留原文匹配方式。

完整标量值与参数相等时，输出 `structured_scalar_equal`，附原文范围和解码字段路径。这允许把短 ID `"5"` 定位到 `id_: '5'`，不会因日期 `2025` 中出现字符 `5` 就命中。

否则做大小写敏感的完整参数文本匹配，要求至少 3 个 Unicode 码点及明确字符边界，输出 `bounded_exact_text`。不做日期推算、同义改写或语义推断。两种方式都只是候选证据，不证明真实因果来源。

状态为 `single_source_candidate`、`multiple_source_candidates` 或 `no_exact_evidence`。多个来源保留；无直接匹配保留未知。结构化解码、短值策略和边界规则是本项目的基线定义，不冒充 NeuroTaint 的原实现。

### NeuroTaint-style：`nt_style_lcs_v1`

依据论文的 Tier 2 使用最长公共**子序列**，不是最长连续子串：`LCS(source, argument) / min(len(source), len(argument))`，普通阈值为 `>= 0.15`。[NeuroTaint §4.2](https://arxiv.org/html/2604.23374v1#S4.SS2)、[§5.1](https://arxiv.org/html/2604.23374v1#S5.SS1)

论文没有完整规定单位与序列化细节。本次明确选择：Unicode 码点、大小写保留、不规范化、来源单位为当前出站消息文本部件、目标单位为参数叶值；非字符串标量按 JSON 表示。用户/assistant/system 的结果是对照候选，与 tool 来源分开标记。

本组件不增加最短匹配长度、数字过滤、top-k 或根据 clean 标签切换阈值；因而 `2025` 与 `5` 会得 1.0 分。这是保留下来的词法行为，不能把高分当恶意性或来源正确性的保证。

算法使用精确位集 LCS。每个输入上限 65,536 码点，长度乘积上限 67,108,864；超限返回 `budget_exceeded`，不截断、不近似，也不当作已评估的未匹配。空串返回 `not_applicable`。限制和状态随每个比较一起导出。

## 现有 clean 日志上的首轮输出

来源为 2026-09-07 的同一个 frozen clean pilot。没有增加真实 agent 运行或 Groq 调用。

| 描述指标 | 结果 |
| --- | ---: |
| 已分析 run / 调用提议 / 叶参数 | 10 / 21 / 54 |
| 精确匹配：单来源候选 | 27 |
| 精确匹配：多来源候选 | 4 |
| 精确匹配：无直接证据 | 23 |
| 存在精确 tool 候选的字段 | 12 |
| 存在 LCS tool 阈值命中的字段 | 40 |
| LCS 已评分的来源—参数比较 | 214 |
| 人工独立核查 / 新真实模型调用 | 0 / 0 |

这不是准确率对比。12 与 40 的差异只表示方法提出候选的范围不同；不能把精确匹配当全部真值，也不能把 LCS 多出的候选全叫误报。

可先核查以下 8 个开发案例。它们在读过实际轨迹后用于覆盖检查，**不是独立测试集或人工真值**。核查时先打开空白包，再看 HTML 算法候选；表中仅给定位和检查重点。

| Run 后缀 | Proposal | 参数路径 | 检查重点 |
| --- | --- | --- | --- |
| `user_task_7` | `event:00000019` | `/event_id` | 短 ID 与结构化来源位置 |
| `user_task_9` | `event:00000019` | `/description` | 用户是否已明确给出参数 |
| `user_task_18` | `event:00000019` | `/start_time` | 日期表达转换与 exact 方法的边界 |
| `user_task_20` | `event:00000030` | `/participants/0` | 联系人结果中的邮箱 |
| `user_task_32` | `event:00000031` | `/file_id` | 新建对象返回的 ID |
| `user_task_32` | `event:00000031` | `/email` | 用户与工具结果可能同时含相同值 |
| `user_task_29` | `event:00000019` | `/content` | 生成文本、改写与未知的区别 |
| `user_task_33` | `event:00000030` | `/attachments/0/file_id` | 历史 assistant 参数与真正曝光文本的区别 |

所有 run 名带 `r01-` 前缀。事件 ID 在不同 run 中重复，必须联合定位。

## 到什么程度算复现 NeuroTaint

| 层次 | 当前状态 / 下一步 |
| --- | --- |
| 数据适配与历史前缀 | 已实现当前单会话范围 |
| Tier 2 LCS | 已开始方法组件级重实现，并在既有日志上运行 |
| Tier 3 MiniLM 语义比较 | 已实现可选本地组件，固定 revision/文件哈希/CPU float32/截断策略 |
| Tier 4 分块覆盖 | 已按公开推定实现，3 句/重叠 1 句/编码范围并集覆盖率，见 SEMANTIC.md |
| 受控影子复核 | 后续独立实验；不以 judge 自报分数充当真值 |
| Live 集成与执行前及时性 | 单次真实 task20 的 3/3 次调用已验证执行前落盘；有同步耗时记录，无 hard deadline，见 ONLINE-RESULTS.md |
| 全文方法重实现与独立评测 | 按论文描述继续实现，公开缺失细节的假设；不等待作者代码 |

2026-09-08 先前核查未确认作者公开的 NeuroTaint 或本论文 TaintBench artifact；这是资料状态，不是继续实验的阻碍。用户已确认采用论文驱动的方法重实现，而非依赖官方代码或逐值复制原论文表格。不应将同名 Android TaintBench 误认为该数据集。[论文入口](https://arxiv.org/abs/2604.23374)、[作者主页](https://sites.google.com/view/ryancaicse/)

因此目前准确名称是 **NeuroTaint-style Tier 2–4 / AgentDojo 迁移组件**。当前未实现 canary、完整 DCPG 持久记忆、完整级联或完整 causal analyzer，不声称已复现全文结果。

## 验证与继续工作

针对时间边界、来源竞争、真实出站文本、不可见元数据、结构化短 ID、参数路径、输出对象隔离，以及 LCS 精确性和资源上限进行了独立测试。导出测试覆盖原始文件不变、拒绝写入冻结槽位、坏日志拒绝、空白标签无预测和 HTML 文本转义。浏览器视觉验收尚未执行。

语义组件加入前的版本全部 **254 项本地测试通过，Ruff 检查通过**。其中新增 90 项：43 项词法组件测试、27 项历史前缀/来源边界测试、20 项报告与标注包测试。语义组件加入后的验证结果见 SEMANTIC.md。

已有 8 条明确标为非盲、非独立的助手开发草稿，仍需人工核查；不能用作独立测试真值。

The live hook is validated; gate 4 source/sink policy and ordered cascade are now implemented with
validation still in progress, not yet accepted. See [CASCADE.md](CASCADE.md) and the forthcoming
[CASCADE-RESULTS.md](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/CASCADE-RESULTS.md); DCPG lineage and memory restoration are the next gated work,
with independent labels reserved for held-out evaluation.

之后比较来源定位、歧义/未知、误报与成本，再决定如何实现有限预算的复核；不把多个已有方法组合起来就预先宣称创新。

本次增加源码和依赖声明后，旧 clean batch 的源码哈希不再匹配当前分支。若要补旧 20 次重复，使用保存的旧实现快照；不要改计划哈希绕过校验。`provenance` 可继续读取旧日志，不要求重跑模型。
