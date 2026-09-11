---
name: info-gather
description: 信息收集工具集。对授权目标执行在线资产查询、子域名枚举、DNS 解析、
  端口扫描、Web 指纹识别与 nuclei 漏洞扫描，产出规范化资产清单。
  全部脚本为 python3 标准库实现，无平台依赖，可被任意 Agent 独立使用。
---

# 信息收集工具手册

本文件是全部脚本用法的唯一事实源。脚本输入为命令行参数与文件，输出为 JSONL
（每行一个 JSON 对象），退出码 0=成功。不调用任何平台 API。

## 工具根目录

所有工具位于信息收集工具根目录（下称 `{BASE}`，默认 `/opt/tools/info-gather`）：

```
{BASE}/
  SKILL.md     本文件（工具手册）
  bin/         subfinder / massdns / nerva / httpx / nuclei（nmap 用系统 PATH）
  script/      编排脚本（python3 标准库实现）
  data/        字典、resolver 与 poc_map（web_poc_map_v2.json）
  share/       独立使用时的输出目录
  tmp/         独立使用时的临时目录
  config.yaml  在线平台密钥（fofa/hunter/quake/icp/beianx）
```

**`{BASE}/bin/`、`{BASE}/script/`、`{BASE}/data/` 只读，禁止修改或写入。**

输出目录规则（Agent 可写的位置）：
- 独立使用：推荐 `{BASE}/share/<project>/`（该目录可写），或 Agent 自选的任意有写权限的目录。
- 平台任务：写任务共享目录（由平台协议指定，见平台侧技能说明）。

## 管线阶段与依赖

```
target → [online] → [resolve] → [portscan] → [fingerprint] → [vulnscan] → report
```

方括号表示可选阶段（按需跳过）。每阶段的输入依赖前置阶段产物；
前置产物不存在时该阶段自动跳过（空输入不报错）。

**report 阶段为必选**——无论启用了哪些阶段、跳过了哪些阶段，任务结束时都必须执行
merge_assets.py + geo_resolve.py 产出 `report/assets_final.jsonl`。
**没有 assets_final.jsonl = 任务未完成。**

| 阶段 | 输入 | 输出子目录 | 脚本 |
|------|------|-----------|------|
| target | 目标清单 | `target/` | Agent 手工编写 `targets.jsonl` |
| online | targets.jsonl | `online/` | online_query.py / unit_domain.py |
| resolve | targets.jsonl | `resolve/` | subdomain_enum.py / subdomain_brute.py / dns_resolve.py |
| portscan | targets + online + resolve | `portscan/` | prepare_portscan.py → port_scan.py |
| fingerprint | portscan/（或替代输入） | `fingerprint/` | fingerprint.py |
| vulnscan | fingerprint/ | `vulnscan/` | vuln_scan.py |
| report | 全部 | `report/` | merge_assets.py → geo_resolve.py |

### 目标清单格式

`target/targets.jsonl`（每行一个 JSON 对象）：
```json
{"type":"ip","value":"192.168.1.1"}
{"type":"cidr","value":"192.168.1.0/24"}
{"type":"domain","value":"example.com"}
{"type":"unit","value":"某某科技有限公司"}
```

显式端口直接写入 value（如 `{"type":"ip","value":"192.168.52.102:8080"}`），
下游脚本自动拆分内嵌端口。

## 脚本用法

所有脚本调用方式：`python3 {BASE}/script/<name>.py <参数>`。

### online_query.py — 在线资产平台查询

```bash
python3 {BASE}/script/online_query.py \
  --query 'domain="example.com"' \
  --platform fofa \                   # fofa|hunter|quake
  --config {BASE}/config.yaml \
  --out OUT.jsonl \
  [--limit 500]
```

输出：`{"host","ip","port","title","server","service","app":[],"platform","location"}`

### unit_domain.py — 单位名称反查域名

```bash
python3 {BASE}/script/unit_domain.py \
  --unit "某某科技有限公司" \
  --config {BASE}/config.yaml \
  --out OUT.jsonl
```

输出：`{"domain","source"}`。key 未配置退出码 3（不可用），调用方降级跳过。

### subdomain_enum.py — 子域名枚举

```bash
python3 {BASE}/script/subdomain_enum.py \
  --domain example.com \
  --bin-dir {BASE}/bin \
  --out OUT.jsonl
```

subfinder + crt.sh 去重。输出：`{"subdomain":"..."}`

### subdomain_brute.py — 子域名爆破

```bash
python3 {BASE}/script/subdomain_brute.py \
  --domain example.com \
  --bin-dir {BASE}/bin \
  --data-dir {BASE}/data \
  --dict small \                      # small|medium
  --out OUT.jsonl \
  [--threads 300]                     # massdns -s，公共 resolver 勿调大
  [--retries 5]                       # massdns -c
  [--resolvers FILE]                  # 默认 {BASE}/data/resolver.txt
```

massdns + 泛解析过滤。输出：`{"subdomain":"..."}`

### dns_resolve.py — DNS 解析与 CDN/云判定

```bash
python3 {BASE}/script/dns_resolve.py \
  --input subs.jsonl \                # 文件或目录（自动合并去重）
  --bin-dir {BASE}/bin \
  --out OUT.jsonl
```

输入行格式：`{"subdomain":"..."}` 或 `{"host":"..."}`。
输出：`{"host","ips":[],"cname","is_cdn","is_cloud"}`

### prepare_portscan.py — 端口扫描目标制备

```bash
python3 {BASE}/script/prepare_portscan.py \
  --shared-dir <info-gather输出根> \
  --out targets.jsonl \
  [--include-cdn]
```

汇聚 target/online/resolve 三处产物，归一化去重 + CDN/云过滤 + CIDR 展开。
输出：`{"ip":"..."}` 或 `{"ip":"...","port":8080}`（显式端口保留）。

### port_scan.py — 端口扫描

```bash
python3 {BASE}/script/port_scan.py \
  --targets ips.jsonl \
  --port-range top-100 \              # top-100|top-1000|full|逗号列表如 80,443,8080
  --bin-dir {BASE}/bin \
  --out OUT.jsonl \
  [--tech -sS]                        # -sS|-sT|-sV
  [--rate 1000]                       # packets/sec
  [--ping]                            # ICMP 存活探测
  [--max-seconds 0]                   # >0 时预算耗尽退出码 4
```

nmap 单工具，断点续跑（`.done` 记录进度，重跑自动跳过已完成部分）。
输出：`{"host","port","service","banner"}`

### fingerprint.py — 服务与 Web 指纹识别

```bash
python3 {BASE}/script/fingerprint.py \
  --input portscan_dir_or.jsonl \     # 目录（合并全部 .jsonl）或单文件
  --bin-dir {BASE}/bin \
  --out OUT.jsonl
```

两段式：nerva 协议识别 → httpx Web 深度识别（仅 http/https 端口）。
输出：`{"host","port","protocol","tls","banner","http_status","title","server","apps":[],"cname"}`
Web 端口追加媒体字段（相对 info-gather 输出根）：
`{"icon_path","icon_mime","screenshot_path","thumb_path"}`
媒体文件落 `{out目录}/media/{icons,screenshots,thumbs}/`。

**端口扫描被跳过时**：手动构建替代输入——聚合 online/ 记录（host+port）与 resolve/
存活域名（默认 80/443），剔除 CDN/云节点，按 (host,port) 去重写入
`portscan/targets_online_resolve.jsonl`，再以该目录为 `--input`。

### vuln_scan.py — 漏洞扫描（poc_map 指纹驱动）

```bash
python3 {BASE}/script/vuln_scan.py \
  --input fingerprint_dir_or.jsonl \
  --bin-dir {BASE}/bin \
  --data-dir {BASE}/data \
  --out OUT.jsonl \
  [--max-seconds 0]
```

按 `{BASE}/data/web_poc_map_v2.json` 指纹→POC 映射，仅扫命中模板。
**禁止全模板目录扫描。** 断点续跑（`.done`）。
输出：`{"template_id","severity","name","target","matched_at","matched_fingerprint"}`

### nuclei 模板库（nuclei-templates）

漏洞扫描依赖 nuclei 模板库，目录约定：

```
{templates_root}/
  nuclei-templates/            ← poc_map Source "nuclei-template" 对应目录
    http/
      cves/                    ← CVE 模板（如 2020/CVE-2020-9484.yaml）
      misconfiguration/        ← 配置缺陷（如 tomcat-scripts.yaml）
      default-logins/          ← 默认口令
      technologies/            ← 技术检测（如 apache/tomcat-detect.yaml）
      ...
  some_nuclei_templates/       ← 补充模板集
  private_nuclei_templates/    ← 私有模板（可选）
```

**模板根目录解析优先级**（vuln_scan.py 自动处理，Agent 无需手动指定）：

1. `--templates-root` 命令行参数（显式指定时优先）
2. 环境变量 `KB_DIR`
3. 默认 `/opt/kb`

**poc_map 路径映射**：`web_poc_map_v2.json` 中每条 POC 的 `Path` 是**相对**
`{templates_root}/{Source对应目录}/` 的路径。例如：

```json
{"Source": "nuclei-template", "Path": ["http/cves/2020/CVE-2020-9484.yaml"]}
```

实际文件路径为：`/opt/kb/nuclei-templates/http/cves/2020/CVE-2020-9484.yaml`

**模板缺失行为**：vuln_scan.py 逐条校验模板文件是否存在，不存在的计入
`缺失模板引用`（不影响其余模板扫描）；全部缺失时目标记为 `poc_template_missing` 跳过。

**安装/更新**（运维操作，非 Agent 日常）：

```bash
# 安装官方模板到 {templates_root}/nuclei-templates/
nuclei -update-templates -td /opt/kb/nuclei-templates/

# 或从 GitHub 克隆
git clone https://github.com/projectdiscovery/nuclei-templates.git /opt/kb/nuclei-templates
```

### merge_assets.py — 资产合并

```bash
python3 {BASE}/script/merge_assets.py \
  --input-dir <info-gather输出根> \
  --out report/assets_final.jsonl \
  [--shard-size 500]                  # 分片输出 assets_final.part_NNN.jsonl
```

扫描 input-dir 下 target/online/resolve/portscan/fingerprint/vulnscan 子目录
全部 .jsonl，按 authority（host[:port]）去重合并。

### geo_resolve.py — IP 归属地补全

```bash
python3 {BASE}/script/geo_resolve.py \
  --input report/assets_final.jsonl \
  --out report/assets_final.jsonl \
  [--xdb {BASE}/data/ip2region.xdb] \
  [--shard-size 500]
```

`location` 非空跳过；内网标「内网地址」；其余查 ip2region.xdb（缺失仅告警）。

### upload_media.py — 媒体直传（平台专用）

```bash
python3 {BASE}/script/upload_media.py --input report/assets_final.jsonl
# 需环境变量 MASTER_ADDR / PROJECT_ID / PROJECT_WORKSPACE_DIR
```

独立使用时不调用此脚本（无 Master API）。

## JSONL 字段总表

| 阶段 | 字段 |
|------|------|
| target | `type`, `value` |
| online | `host`, `ip`, `port`, `title`, `server`, `service`, `app[]`, `platform`, `location` |
| resolve(子域) | `subdomain` |
| resolve(解析) | `host`, `ips[]`, `cname`, `is_cdn`, `is_cloud` |
| portscan | `host`, `port`, `service`, `banner` |
| fingerprint | `host`, `port`, `protocol`, `tls`, `banner`, `http_status`, `title`, `server`, `apps[]`, `cname` + 媒体字段 |
| vulnscan | `template_id`, `severity`, `name`, `target`, `matched_at`, `matched_fingerprint` |
| report | 合并后资产记录（authority 去重） |

## 任务完成标志（Agent 必读）

一个信息收集任务完成的标志是产出以下文件：

```
{输出根}/report/assets_final.jsonl     ← 必须存在（合并+归属地后的最终资产清单）
```

无论用户要求开启哪些阶段，**report 步骤不可省略**：

```bash
# 最后一步（必选）：合并全部阶段产物 → 补归属地
python3 {BASE}/script/merge_assets.py --input-dir <输出根> --out <输出根>/report/assets_final.jsonl
python3 {BASE}/script/geo_resolve.py --input <输出根>/report/assets_final.jsonl     --out <输出根>/report/assets_final.jsonl --xdb {BASE}/data/ip2region.xdb
```

完成后向用户汇报：资产总数、各类型（web/port/ip/domain）数量、重要发现摘要。

## tmux 后台执行规范

所有可能超过 1 分钟的脚本调用（爆破/扫描/指纹/漏扫）一律经 tmux 后台执行，
禁止 bash 前台 sleep 轮询长任务：

```bash
# 启动（在输出根目录下执行）
tmux new-session -d -s ig-<stage> 'cd <输出根> && python3 {BASE}/script/<脚本>.py ... \
    > tmp/ig-<stage>.log 2>&1; echo "EXIT=$?" >> tmp/ig-<stage>.log'

# 轮询进度
tmux ls 2>/dev/null | grep ig-<stage>     # 会话存在=执行中，不存在=已结束
tail -20 tmp/ig-<stage>.log               # 末尾 EXIT=0 即成功
```

退出码：0=成功；4=部分完成（重跑同一命令续跑）；3=key 未配置（跳过）；1=错误。

## 降级策略

- 在线平台 key 未配置：脚本返回不可用（退出码 3），跳过该源，不阻断管线。
- massdns 缺失：dig 循环降级替代。
- Pillow 缺失：跳过缩略图，不影响截图与 favicon。
- ip2region.xdb 缺失：归属地留空，不阻断。
- CDN 资产不深度扫描（vulnscan 跳过）。

## 安全约束

- **仅对授权目标执行收集**。
- 扫描限速默认 1000pps（可配）。
- nuclei 仅按 poc_map 命中模板限速扫描，禁止全模板目录扫描。
