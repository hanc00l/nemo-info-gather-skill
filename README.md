# info-gather 工具体系

信息收集场景的第三方工具与编排脚本。与平台解耦，可被任意 Agent 独立使用。

## 快速开始

```bash
# 1. 准备目标清单
mkdir -p results/target
echo '{"type":"ip","value":"192.168.52.102:8080"}' > results/target/targets.jsonl

# 2. 端口扫描
python3 script/prepare_portscan.py --shared-dir results --out results/portscan/targets.jsonl
python3 script/port_scan.py --targets results/portscan/targets.jsonl \
    --port-range top-1000 --bin-dir bin --out results/portscan/ports.jsonl

# 3. 指纹识别
python3 script/fingerprint.py --input results/portscan --bin-dir bin \
    --out results/fingerprint/fp.jsonl

# 4. 漏洞扫描
python3 script/vuln_scan.py --input results/fingerprint --bin-dir bin \
    --data-dir data --out results/vulnscan/vulns.jsonl

# 5. 合并与归属地
python3 script/merge_assets.py --input-dir results --out results/report/assets_final.jsonl
python3 script/geo_resolve.py --input results/report/assets_final.jsonl \
    --out results/report/assets_final.jsonl --xdb data/ip2region.xdb
```

## 目录结构

```
{base}/
  SKILL.md       工具手册（Agent 唯一入口：脚本用法/JSONL 格式/tmux/安全）
  README.md      本文件（人类文档）
  bin/           二进制：subfinder / massdns / nerva / httpx / nuclei（不入库）
  script/        python3 标准库编排脚本
  data/          字典与公共资源
  share/         独立使用输出目录
  tmp/           独立使用临时目录
  config.yaml    在线平台密钥（参照 config.example.yaml）
```

## 安装

### 二进制（安装到 `{base}/bin/`，nmap 除外）

| 组件 | 来源 | 用途 |
|------|------|------|
| subfinder | github.com/projectdiscovery/subfinder | 子域名枚举 |
| massdns | github.com/blechschmidt/massdns | 子域名爆破（可选，dig 降级） |
| nerva | github.com/praetorian-inc/nerva | 端口协议识别 |
| httpx | github.com/projectdiscovery/httpx | Web 深度指纹 |
| nuclei | github.com/projectdiscovery/nuclei | 漏洞扫描 |
| nmap | nmap.org（系统包） | 端口扫描（系统 PATH） |

### 数据文件（`{base}/data/`）

| 文件 | 来源 |
|------|------|
| subnames.txt / subnames_medium.txt | 随库自带 |
| resolver.txt | 随库自带 |
| web_poc_map_v2.json | 随库自带 |
| ip2region.xdb | github.com/lionsoul2014/ip2region（不入库，运维安装） |

### 在线平台密钥

```bash
cp config.example.yaml config.yaml
# 编辑 config.yaml 填入 fofa/hunter/quake/icp/beianx key
```


## Agent 调用指南（Codex / Claude / 任意 LLM Agent）

本工具集通过 `SKILL.md` 与 Agent 交互——Agent 读这一个文件即可获知全部脚本用法、
JSONL 输出格式、tmux 后台执行规范与安全约束，无需人工逐步指挥。

### Agent 工作流

```
1. Agent 读取 {BASE}/SKILL.md        ← 获知全部能力与规则
2. Agent 根据用户目标编写 targets.jsonl
3. Agent 按管线顺序逐步调用脚本（Stage 模式）
4. Agent 读取各阶段 JSONL 产物，判断结果、决定下一步
5. 最终输出 assets_final.jsonl + Markdown 摘要
```

### 提示词案例

用户只需提供目标与开关偏好，Agent 自行读手册并执行。以下案例覆盖常见场景：

#### 案例 1：单 IP 全流程（端口扫描 + 指纹 + 漏扫）

```
阅读 SKILL.md，对 192.168.52.102:8080 进行信息收集，
开启端口扫描、Web 指纹识别和漏洞扫描，不需要在线接口查询和子域名枚举。
最后生成 assets_final.jsonl 报告。
```

Agent 执行：target → portscan → fingerprint → vulnscan → **report**（merge + geo）
产出：`report/assets_final.jsonl` + 媒体文件

#### 案例 2：单 IP 仅端口扫描与指纹（最常用）

```
阅读 SKILL.md，对 192.168.52.102:8080 进行信息收集，
开启端口扫描和 Web 指纹识别，不需要漏洞扫描。
完成后合并资产并生成报告。
```

Agent 执行：target → portscan → fingerprint → **report**
产出：`report/assets_final.jsonl`（2 条资产：web + port）

> **注意**：提示词中显式加上"生成报告"或"合并资产"可以显著降低 Agent
> 遗漏 report 阶段的风险（实测 Codex 在未提及时可能跳过 merge_assets）。

#### 案例 3：域名全流程（子域名枚举 + 爆破 + 解析 + 端口 + 指纹）

```
阅读 SKILL.md，对 example.com 进行信息收集，开启全部阶段：
在线接口查询、子域名枚举与爆破、端口扫描、Web 指纹识别、漏洞扫描。
产出最终资产清单。
```

Agent 执行：target → online → resolve → portscan → fingerprint → vulnscan → **report**

#### 案例 4：CIDR 网段扫描

```
阅读 SKILL.md，对 192.168.1.0/24 进行端口扫描和 Web 指纹识别，
限速 500pps，输出资产清单。
```

Agent 执行：target（CIDR 展开）→ portscan → fingerprint → **report**

#### 案例 5：单位名称在线查询

```
阅读 SKILL.md，通过在线接口查询"某某科技有限公司"的资产，
不需要端口扫描和指纹识别。
```

Agent 执行：target（unit 类型）→ online（fofa/hunter/quake + unit_domain）→ **report**
前提：`config.yaml` 中已配置对应平台的 API key

#### 案例 6：多个混合目标

```
阅读 SKILL.md，对以下目标进行信息收集（全部开启）：
- 192.168.52.102:8080
- 10.0.0.0/24
- example.com
- 某某科技有限公司
最后合并资产并输出报告。
```

Agent 执行：识别 4 种目标类型（ip/cidr/domain/unit）→ 全管线 → **report**

#### Agent 完成标志

每个案例的最后产物都是：

```
{输出根}/report/assets_final.jsonl
```

如果 Agent 执行完 fingerprint/vulnscan 后没有产出此文件，**任务未完成**，
应提示 Agent："请执行 merge_assets.py 和 geo_resolve.py 生成最终报告"。

### Agent 需要遵守的规则（已在 SKILL.md 中声明）

- **{BASE} 只读**：所有输出写 Agent 指定的输出目录，禁止写入工具根目录。
- **tmux 后台**：可能超过 1 分钟的脚本必须经 tmux 后台执行，禁止前台 sleep 轮询。
- **断点续跑**：portscan/vulnscan 支持 `.done` 断点，中断后重跑同一命令自动跳过已完成部分。
- **安全约束**：仅对授权目标操作，限速默认 1000pps，nuclei 禁止全模板扫描。
- **JSONL 格式**：所有脚本输入输出均为 JSONL（每行一个 JSON 对象），Agent 可逐行读取处理。

### 与 mirrorStrike 平台的区别

| | Agent 独立使用 | mirrorStrike 平台内 |
|---|---|---|
| 工作目录 | Agent 自选（如 `./results/`） | `shared/info-gather/{stage}/` |
| 阶段编排 | Agent 按手册自行决定顺序 | Planner fixed flow 自动推进 |
| 资产入库 | 不入库（只产出 JSONL 文件） | save_asset 批量入 PG |
| 媒体直传 | 不调用 upload_media.py | upload_media.py → Master |
| 漏洞落库 | 不调用 write_vuln | write_vuln + 复核 Fact |
| Fact/Intent | 无 | read_blackboard / write_fact / complete_intent |

两种模式共用同一套脚本和同一个工具手册，仅工作目录与平台协议不同。

## mirrorStrike 平台集成

- `skills/info-gather/SKILL.md` 为平台任务简报（Intent 协议/工作目录映射）。
- 脚本用法统一引用本目录 `SKILL.md`（工具手册），两文件零重叠。
- `deploy/worker-setup.sh` 将本目录同步到 Worker `/opt/tools/info-gather/`。
