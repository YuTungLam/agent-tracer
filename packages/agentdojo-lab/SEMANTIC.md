# NeuroTaint-style 语义组件：固定协议与复现边界

## Material Passport

- Origin Skill: academic-research-suite
- Origin Mode: engineering implementation / recorded-trace analysis
- Origin Date: 2026-09-08
- Verification Status: 工程测试、本地模型运行及重复性已验证；来源准确性尚未完成人工评估
- Version Label: nt-style-semantic-v1

## 本轮完成条件

实现论文 Tier 3 的 MiniLM 余弦比较与 Tier 4 的分块比较，接入现有历史前缀分析，保存可复核的模型、输入、分块和截断信息。读取原有 10 条 clean 轨迹，不重新调用 Groq，不改原始轨迹。代码默认仍只运行 exact/LCS；语义层必须显式启用。

本版本**对每个可见来源—参数对分别计算各组件**，没有按命中提前停止，也没有构建完整 NeuroTaint 级联。候选数量和离线总耗时都不能冒充论文级联的准确率或成本。

依据：[NeuroTaint §4.2](https://arxiv.org/html/2604.23374v1#S4.SS2)、[§5.1](https://arxiv.org/html/2604.23374v1#S5.SS1)、[MiniLM 官方模型卡](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2)。论文未充分说明的细节在下面作为本地实现假设公开，不声称与作者代码逐行一致。

## 冻结配置

| 项目 | 配置 |
| --- | --- |
| 模型 | `sentence-transformers/all-MiniLM-L6-v2` |
| Revision | `1110a243fdf4706b3f48f1d95db1a4f5529b4d41` |
| 本地模型清单 | 包内 `model_pins/minilm-v1.json`，启动逐文件验证 SHA256 |
| 上游校验 | 配置及词表核对 Hugging Face Git blob；权重核对 LFS SHA256 |
| 编码 | CPU、float32、模型原生 pooling、归一化 embedding；不更新参数 |
| 最大序列 | 256 tokens，包含特殊 token，记录原始/实际 token 数及原文编码范围 |
| 普通语义阈值 | cosine ≥ 0.60 |
| 覆盖率阈值 | ≥ 0.10 |
| 参数单位 | 当前提议的 JSON 叶值；字符串原文，非字符串标量用 JSON 表示 |
| 来源单位 | 当前实际出站请求的文本部件，沿用曝光验证与时间边界 |
| 比较范围 | user/system/developer/assistant/tool 均作为单独候选，tool 单独统计 |
| 分句假设 | `. ! ? 。 ！ ？` 后的空白，或换行；不使用语义分句模型 |
| 分块假设 | 每块 3 句，相邻重叠 1 句；保存原文 Unicode 半开区间 |
| 覆盖率假设 | 过语义阈值的块中，实际编码 token 范围的并集长度 / 原文全部码点数 |
| 资源范围 | 每输入最多 65,536 码点，每来源最多 128 块；超限显式未评分 |
| 缓存 | 固定编码器实例内按精确文本缓存；最多 1,024 条和 1,048,576 码点 |

标点缩写、没有空格的中文句子、YAML 行和长单句可能产生不理想的块。本轮不根据已有任务结果临时调整这些规则；更换规则需使用新配置/版本。

普通阈值适用于本轮单会话 clean 组件分析。尚未实现论文的 RAG/memory 与 safe-control 策略档位；不能根据评测标签自动改为 0.85 或 0.95。所选模型是英语句子/短段编码器，不应将本轮结果外推为跨语言传播能力。

## 截断与未评分

Tier 3 保留整段来源和参数的编码窗口。Tier 4 对每个块另做编码；块过长仍会截断。过阈值块只有**实际编码范围**进入覆盖率分子，重叠范围只计一次。token 范围是首末有效 token 的原文包络，包络内空白也计入长度；这不是逐 token 内容贡献度。

`status=scored` 表示能计算编码视图的相似度，不等于已完整处理原文。`truncated` 和 `complete` 描述输入处理范围，不是结论置信度。`not_applicable`、`budget_exceeded`、`encoder_error` 使用空分数和空 matched，不能当作已测负例。报告展示来源与参数的截断信息。

高相似度仍可能只是相同主题；低相似度也不能排除控制影响。参数生成原因、恶意性、用户授权和语义重合必须分开分析。

## 安装、下载与运行

```bash
UV_CACHE_DIR=.uv-cache .bootstrap/bin/uv sync --extra figures --extra semantic

HF_HOME=.model-cache/hf HF_HUB_DISABLE_IMPLICIT_TOKEN=1 HF_HUB_DISABLE_TELEMETRY=1 \
  .venv/bin/hf download sentence-transformers/all-MiniLM-L6-v2 \
  model.safetensors config.json config_sentence_transformers.json modules.json \
  sentence_bert_config.json special_tokens_map.json tokenizer.json tokenizer_config.json \
  vocab.txt 1_Pooling/config.json \
  --revision 1110a243fdf4706b3f48f1d95db1a4f5529b4d41 \
  --local-dir .model-cache/all-MiniLM-L6-v2-1110a243

HF_HUB_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1 \
  .venv/bin/dojo-lab provenance \
  --batch runs/20260907T025045Z-clean-pilot-b93eae95 \
  --semantic-model .model-cache/all-MiniLM-L6-v2-1110a243 \
  --semantic-revision 1110a243fdf4706b3f48f1d95db1a4f5529b4d41 \
  --output reports/20260908-semantic-pilot-v1
```

输出目录须全新。模型下载与评分分开；评分只加载本地文件，禁止远程自定义代码，只使用 safetensors。模型缓存、运行日志和 HTML 结果不提交 Git；代码、模型校验清单、依赖锁与协议进入 Git。

## 开发标注

已复制 8 个教学案例到 `reports/20260908-provenance-dev-review-assistant-v1/`，填写 `assistant_draft` 与 11 处原文证据范围。助手此前已见这些案例与预测，因此**非盲、非独立、不是人工真值**。该包可辅助用户理解与核查，不用于独立测试准确率。原来的 54 条空白标注保持不变，语义分析也不读取这些草稿。

## 后续里程碑与工作量估计

以下为 2026-09-08 的粗略工程预算，不是自动后台执行计划或固定交付日期。

| 里程碑 | 验收条件 | 估计增量工程量 |
| --- | --- | --- |
| M1：词法与语义组件 | 固定模型/协议；真实本地编码；前缀分析与 HTML；测试通过 | 本轮已完成 |
| M2：单会话实时归因 | 独立 sidecar、执行前落盘、失败隔离与本地不干扰对照已验证；无 hard deadline | 当前范围已验证，见 ONLINE-RESULTS.md |
| M3：其余方法重实现 | 来源/敏感工具策略、完整级联、DCPG 与记忆恢复、单独 canary 条件、因果分析及隔离复核 | 约 2–3 工作日 |
| M4：迁移评测 | 独立来源标注、正常/攻击配对、重复运行、消融与归因成本 | 约 1–2 工作日，受标注与 API 配额影响 |

方法级重实现先按约 3–5 工作日量级规划，遇到跨会话适配或论文歧义可能增加。M4 不保证包含在该范围内。

2026-09-08 用户确认：以论文描述为依据独立重实现并检验方法，**不以获取作者代码作为前提**。未写明的细节公开记录假设；在 AgentDojo/Groq 上保留可复核的结果和失败案例。先排查实现错误、参数敏感性与设定差异，再判断失败是否支持研究 gap。原论文表格可作为参考，不是本项目必须逐值复刻的验收条件。具体执行约定见 [REPRODUCTION.md](REPRODUCTION.md)。

## 本轮结果

新报告：[20260908-semantic-pilot-v1/index.html](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260908-semantic-pilot-v1/index.html)。旧报告和原始轨迹保留不变。

| 描述指标 | 结果 |
| --- | ---: |
| run / 调用提议 / 参数叶值 | 10 / 21 / 54 |
| 来源—参数语义比较 | 214，全部 scored |
| 有 Tier 3 工具候选的字段 | 2 |
| 有 Tier 4 工具候选的字段 | 12 |
| Tier 3 出现截断的比较 | 22 |
| Tier 4 出现截断的比较 | 0 |
| 编码错误 / 资源超限 | 0 / 0 |
| 新 Groq/生成式模型调用 | 0 |
| 独立人工标注 / 来源准确率 | 0 / 未计算 |

12 个分块候选字段与 12 个 exact 工具候选字段不一定是同一集合，也不代表同样准确。全部数据仍是 clean 运行；不把相似度命中当作恶意传播或因果证据。

Tier 3/4 使用 float32 embedding，余弦汇总使用 Python `math.fsum`；依赖锁固定本次 `sentence-transformers 6.0.1`、`transformers 5.16.1`、`torch 2.14.0`。重载模型后完整重放第二次，214 个比较分数、全部前缀输出和候选计数**逐值相同**，见报告目录的 `reproducibility.json`。这只验证本机、固定版本、同批输入的重复性。

首轮命令总墙钟约 7.936 秒，读取/审计/全部启用组件分析约 1.710 秒，模型构造和报告写出不在后一个计时内。首轮与单元测试并行，第二轮命令约 5.687 秒；这些是执行诊断，**不是在线归因 overhead 或论文级联成本**。

验证：原 30 个日志/manifest/summary 文件哈希未变；新旧 54 条空白标注逐字节相同；模型 10 个输入文件通过固定清单校验；HTML 25 个本地链接有效，2241 个折叠节点，无脚本。未做浏览器视觉测试。

测试：全量 298 项通过，随后新增 2 项展示回归，语义集成文件共 13 项再次通过，合计覆盖 300 项。Ruff/格式检查通过；wheel 包含语义组件及模型清单，不含权重、密钥和运行数据。代码包位于 `/private/tmp/agentdojo-lab-semantic-wheel/`。

执行记录及评分前协议快照：`reports/20260908-semantic-pilot-v1-execution/`。重复检查输出：`reports/20260908-semantic-pilot-v1-repeat-check/`。模型和所有报告均留在本地，代码提交不自动同步它们。
