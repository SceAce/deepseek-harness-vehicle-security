# DeepSeek Harness 车联网安全与 CTF 工具插件

面向车联网比赛和本地样本分析的 DeepSeek Harness + Codex 组合包。Harness 侧按官方插件架构组合一个工具插件和一个 Skill Provider 插件，当前版本提供一个正式调查流程和六个确定性工具：

| 工具 | 用途 |
| --- | --- |
| `vehicle_investigation_plan` | 把附件、一句话或靶场目标路由为调查阶段、候选方向、验证动作、语言选择和停止条件 |
| `vehicle_tool_audit` | 检查 CAN、固件、逆向、Android、RF 工具的路径和版本 |
| `vehicle_can_log_summary` | 解析 candump 和 Vector ASC 日志，统计 CAN ID、通道与时间范围 |
| `vehicle_uds_decode` | 解码 UDS 请求、正响应、负响应和常见 ISO-TP 前缀 |
| `vehicle_program_analyze` | 提取程序架构、ELF 保护、导入和高价值字符串，生成证据、假设与工具验证步骤 |
| `vehicle_artifact_triage` | 计算固件哈希、采样熵、文件类型并执行只读 Binwalk 签名扫描 |

## 正式调查流程

```text
附件 / 一句话 / 靶场
        -> P0 输入与目标归一化
        -> P1 快速画像与方向排序
        -> P2 建立最多三个可验证假设
        -> P3 使用协议、IDA/r2、调试器或脚本验证
        -> P4 形成证据化结论并制定后续操作
```

流程统一使用 `E-*` 观察、`C-*` 有边界结论、`H-*` 假设、`V-*` 验证动作和 `F-*` 已确认发现。每轮优先执行信息增益最高且成本最低的验证动作，并保存原始输出和反证。

DeepSeek Harness 和 Codex 中都使用 `$investigate-vehicle-security` 作为总入口，使用 `$analyze-vehicle-security` 执行确定性采集和深入程序分析。详细规则由各自的 Skill 发现机制按需加载，不会一次占满模型上下文。

```text
dsh-vehicle-security bundle
├── dsh-vehicle-security/tools   -> 注册六个 vehicle_* 工具
└── dsh-vehicle-security/skills  -> 通过 ctx.skills.registerProvider() 提供两个 Skill
```

## 设计边界

- 文件路径默认限定在当前 `session.header.cwd` 内，并通过真实路径检查符号链接越界；也可显式配置固定 `workspaceRoot`。
- 外部程序使用固定可执行文件和参数数组调用，不拼接 shell 命令。
- 固件初检只扫描，不执行 Binwalk 解包，也不修改样本。
- 文件大小、命令超时和输出长度均可配置。

## 环境

- Node.js 22 或更高版本
- DeepSeek Harness `0.1.0-rc.6` 或同系列后续版本
- 可选本机工具：`can-utils`、Binwalk、GDB、QEMU、radare2、TShark、JADX、ADB、Frida

## 本地测试

```bash
cd /path/to/deepseek-harness-vehicle-security
pnpm install
pnpm test
pnpm run check
```

源码使用严格模式 TypeScript，`pnpm run build` 将 Harness 产物编译到 `lib/`，并把同一套分析模块同步到 Codex 技能的 `runtime/`。TypeScript 用于长期维护的插件、MCP、结构化输出和调查编排；Python 用于协议、IDAPython、Scapy/python-can、密码算法和快速验证；Shell 只用于短命令；C/C++ 或 Rust 留给已确定边界后的 fuzz harness 和 ABI 相关代码。

## 安装到 Harness Web profile

当前 Harness 使用 `next` 发布标签。把本目录作为本地组合包链接到内置 `web` profile：

```bash
cd /path/to/deepseek-harness-vehicle-security
npx @deepseek-ai/dsh@next plugin --profile web add .
npx @deepseek-ai/dsh@next web --dump-config
```

从待分析项目目录启动。文件类工具会使用新会话记录的绝对工作目录，与启动 DSH 服务时所在目录无关：

```bash
cd /path/to/competition-case
npx @deepseek-ai/dsh@next web
```

Web UI 默认地址是 `http://127.0.0.1:3080`。

## 配置

组合包的默认配置位于 `cordis.patch.yml`：

```yaml
- insert:
    - id: vehicle-security-tools
      name: dsh-vehicle-security/tools
      config:
        maxFileBytes: 268435456
        maxOutputChars: 40000
        commandTimeoutMs: 20000
        enableBinwalk: true
    - id: vehicle-security-skills
      name: dsh-vehicle-security/skills
```

比赛固件超过 256 MiB 时提高 `maxFileBytes`。只有需要将所有会话锁定到同一目录时才配置 `workspaceRoot`；默认的会话工作区更适合 Web UI 同时分析多个项目。禁用 `enableBinwalk` 后，初检仍会返回大小、SHA-256、采样熵和 `file` 类型。

## 调用示例

在对话中可以直接描述任务：

```text
从这个附件开始建立正式车联网调查，先选择最可能的方向和最快验证动作。
使用 vehicle_tool_audit 检查当前车联网工具环境。
分析 logs/drive.asc，只统计 0x7E0 和 0x7E8。
解码 UDS 报文 03 22 F1 90。
分析 bin/gateway，围绕诊断鉴权建立假设，并给出 IDA/r2/GDB 验证步骤。
对 firmware/gateway.bin 做只读固件初检。
```

## Codex / GPT-5.4

仓库同时包含一个模型无关的 Codex 插件，可用于 GPT-5.4 及其他支持 Codex 技能的模型。入口位于：

```text
codex-plugin/plugins/vehicle-security
```

本地 marketplace 位于 `codex-plugin/.agents/plugins/marketplace.json`。插件自带无绝对路径的 stdio MCP，Codex 安装插件后可直接发现六个 `vehicle_*` 工具。IDA Pro MCP、r2 MCP 等专业服务器保持独立安装，由总控 Skill 在深度验证阶段组合调用。

安装后优先在对话中调用 `$investigate-vehicle-security`，也可以直接验证确定性命令行助手：

```bash
SKILL_DIR="$PWD/codex-plugin/plugins/vehicle-security/skills/analyze-vehicle-security"
node "$SKILL_DIR/scripts/vehicle_security.mjs" investigate --objective '定位诊断鉴权逻辑' --path fixtures/sample.asc
node "$SKILL_DIR/scripts/vehicle_security.mjs" audit
node "$SKILL_DIR/scripts/vehicle_security.mjs" uds-decode --payload '03 22 F1 90'
node "$SKILL_DIR/scripts/vehicle_security.mjs" can-summary --path fixtures/candump.log
node "$SKILL_DIR/scripts/vehicle_security.mjs" program-analyze --path bin/gateway --focus 'diagnostic authentication'
node "$SKILL_DIR/scripts/vehicle_security.mjs" artifact-triage --path firmware/gateway.bin
```

Codex 版本复用编译后的 TypeScript 核心模块；修改 `src/*.ts` 后执行 `pnpm run build` 即可同步运行时。

## 打包分发

该项目将 TypeScript 编译为原生 ESM，并同时生成类型声明。生成的 tarball 可直接安装：

```bash
pnpm pack
npx @deepseek-ai/dsh@next plugin --profile web add ./dsh-vehicle-security-0.2.0.tgz
```

下一阶段适合增加 DBC 信号解码、DoIP/SOME-IP 报文分析、UDS 会话日志重建、IDA/r2 高层调查动作和可持久化 case 状态更新工具。

## CTF 工具插件

仓库同时提供独立的 CTF 工具层，入口和车联网工具分开：

```text
dsh-vehicle-security/ctf-tools   -> 注册 ctf_* 工具
dsh-vehicle-security/ctf-skills  -> 提供 investigate-ctf Skill
```

CTF 侧目标是工具优先：先审计本机能力、初检文件或 URL，再选择已有工具。只有在现有工具缺口明确时，模型才应该写临时脚本。需要用户启动服务、操作 GUI、连接设备、提供数据或确认会改动工作区的步骤时，使用 `ctf_human_request` 输出结构化人工动作。

| 工具 | 用途 |
| --- | --- |
| `ctf_start` | CTF 第一入口：审计本机能力、初检附件、判断 RE/Pwn/Crypto/Misc/Web，并给出下一步工具 |
| `ctf_tool_audit` | 检查本机 CTF 能力：binutils、GDB、pwntools、Sage/Z3、tshark、curl 等 |
| `ctf_mcp_configure` | 自动生成 CTF 外部 MCP 配置；只接收 `TAVILY_API_KEY` 等 secret，不要求手写 JSON 或路径 |
| `ctf_artifact_profile` | 对文件做 hash、大小、magic、file 类型、熵和文本样本初检 |
| `ctf_re_profile` | 用 `file/readelf/strings` 等工具提取逆向线索 |
| `ctf_re_r2_query` | 调用本机 radare2 执行受限的 headless 命令并保留 JSON/原始输出 |
| `ctf_re_ida_script` | 生成以 IDAPython 为主的函数、字符串和交叉引用分析脚本；可选 IDA batch 执行 |
| `ctf_pwn_profile` | 提取 ELF 保护、导入、字符串、checksec 输出和后续调试/gadget 动作 |
| `ctf_pwn_debug_probe` | 用 GDB batch 采集入口点、寄存器、栈、反汇编和回溯 |
| `ctf_pwn_gdb_probe` | 用 GDB/Pwndbg 执行 `context`、`vmmap`、寄存器和回溯探针 |
| `ctf_rop_search` | 调用 ROPgadget 或 ropper 搜索 gadget |
| `ctf_crypto_probe` | 检测 hex/base64/binary-ascii、熵、hash 和单字节 XOR 候选 |
| `ctf_misc_triage` | 用 binwalk、exiftool、7z、strings、zsteg 做 Misc/取证初检 |
| `ctf_pcap_profile` | 用 tshark 汇总 PCAP 协议层级和 TCP/UDP 会话 |
| `ctf_http_request` | 用 curl 发起结构化 HTTP 请求并返回状态、长度、hash 和预览 |
| `ctf_http_diff` | 对比两次 HTTP 请求的状态、长度和响应 hash |
| `ctf_web_browser_probe` | 用本机 Chromium/Chrome headless 获取 DOM、标题和截图 |
| `ctf_web_capture_probe` | 检查 mitmproxy/mitmweb 并生成启动实时抓包的人工 MCP 请求 |
| `ctf_tool_setup` | 生成 GDB/Pwndbg、IDA、r2、mcp-chrome、mitmproxy、Python CTF 环境和 BlackArch 的安装配置请求 |
| `ctf_human_request` | 生成结构化人工动作请求，把用户当作可调用的电脑/环境 MCP |

### CTF Skills

```text
$investigate-ctf   -> 总入口，先路由再下钻
$solve-ctf-re      -> 逆向工具图
$solve-ctf-pwn     -> Pwn 工具图
$solve-ctf-web     -> Web 工具图
```

`ctf_human_request` 要求模型先给出操作顺序，再给出每步的命令或指令；人类侧只回传 `log`、`screenshot` 或 `ocr_text`，不再依赖自由文本补充。

`ctf_start` 还会返回结构化 `toolGraph`，其中包含当前类别的入口工具、节点、边和转移条件。RE、PWN、WEB 的图分别从 `ctf_re_profile`、`ctf_pwn_profile`、`ctf_http_request` 开始。

### CTF 工具安装与外部 MCP

CTF 插件只调用本机已安装程序、生成确定性脚本、检查外部 MCP 配置，并与车联网插件保持独立。运行 `ctf_tool_audit` 可以看到：

- `capabilities`：本机可执行文件和 Python 模块；
- `python`：实际选中的 Python、来源、venv 和 `bin` 路径；
- `mcp`：外部 MCP 是否在人工提供的配置中出现；
- `recommendations`：缺少能力时应调用的工具或 setup 请求。

Python 工具优先使用：

```text
/home/source/tools/PyVenv/CTF/bin/python
DSH_CTF_PYTHON
$VIRTUAL_ENV/bin/python
<workspace>/.venv/bin/python
PATH 中的 python3/python
```

因此在 CTF Python 环境中安装的新库会自动进入工具审计和命令搜索路径。当前环境已经检测到 pwntools、Z3、SymPy、PyCryptodome、gmpy2、requests、Pillow、Unicorn、Capstone、LIEF 和 BeautifulSoup；缺失的 Scapy、angr、Playwright 等会以推荐项显示。

需要人操作安装、启动长驻服务或编辑 MCP 客户端配置时，调用 `ctf_tool_setup`。每个 setup 请求都有严格的操作顺序；人类侧只返回 `log`、`screenshot` 或 `ocr_text`。

外部 MCP 配置示例位于：

```text
codex-plugin/plugins/ctf-security/mcp.external.example.json
```

复制后补齐 IDA/r2/GDB-Pwndbg 的实际 MCP 启动命令，再通过以下环境变量让 `ctf_tool_audit` 检测：

```bash
export DSH_CTF_MCP_CONFIG="$PWD/ctf-mcp.json"
# CTF_MCP_CONFIG 也可作为别名使用
```

更简单的方式是直接调用 `ctf_mcp_configure`：

```text
调用 ctf_mcp_configure。
如果 Tavily 尚未配置，只向我索取 TAVILY_API_KEY；不要让我手写 JSON、MCP command、路径或 env。
```

推荐初始化顺序：

```text
1. 调用 ctf_tool_audit。
2. 调用 ctf_mcp_configure；只在结果包含 requiredSecrets 时索取对应 key。
3. 如果 mcp-chrome 尚未连接，调用 ctf_tool_setup(target="chrome_mcp")，按顺序执行 doctor、权限修复、浏览器注册、扩展连接和 ping。
4. 重启 DSH/MCP host 后再次调用 ctf_tool_audit，确认 mcp.chrome 和 mcp.tavily 状态。
```

默认行为：

- `mcp-chrome` 优先写入本机已发现的 `mcp-chrome-stdio`，否则写入 `http://127.0.0.1:12306/mcp`；如果本机 bridge 使用其他端口，只填 `chromeUrl`；
- Tavily 写入 `npx -y tavily-mcp@latest`，只从工具参数或 `TAVILY_API_KEY` 环境变量读取 key；
- IDA MCP、r2 MCP、GDB/Pwndbg MCP 保留为外部服务器，由本机已有配置提供；
- `ctf_tool_audit` 只报告 configured/未 configured，不回显 key、完整 env 或敏感配置内容；
- 配置文件默认写入 `~/.config/dsh/ctf-mcp.json`，也可以通过 `DSH_CTF_MCP_CONFIG` 或 `configPath` 指定；
- 仓库内置的 `.mcp.json` 只启动 CTF 自身的本地 MCP，不会把外部 server 与车联网插件混在一起。

模型的默认调用顺序是：先 `ctf_tool_audit`，再根据工具图选择本机工具或外部 MCP。IDA MCP 已配置时不要求安装 IDA CLI；`ctf_re_ida_script` 仍然负责生成 IDAPython，CLI 仅用于需要 batch 执行的场景。Web 交互优先使用 `mcp-chrome`，无 MCP 时才回退到本机 Chromium/Chrome headless；CVE、漏洞版本和依赖资料优先使用 Tavily MCP。

### 推荐工具分工

| 工具 | 建议用途 | 插件行为 |
| --- | --- | --- |
| GDB + Pwndbg | Pwn 动态状态、堆、寄存器、映射 | `ctf_pwn_gdb_probe` 直接批处理调用 |
| radare2 | CLI 逆向、JSON 画像、xrefs | `ctf_re_r2_query` 直接调用 |
| IDA Pro + IDAPython | 深入函数、交叉引用、反编译器脚本 | `ctf_re_ida_script` 生成/可选执行脚本 |
| mcp-chrome | 页面、DOM、Console、网络、标签页、Cookie 和截图 | 交互浏览器主路径；不可用时回退 `ctf_web_browser_probe` |
| Tavily MCP | CVE、漏洞版本、框架/依赖资料搜索与页面提取 | 按需调用；只需提供 `TAVILY_API_KEY` |
| mitmproxy/mitmweb | 实时 HTTP(S) 拦截、重放和流量查看 | `ctf_web_capture_probe` 检查并交接长驻服务 |
| TShark | 离线 PCAP 协议和会话统计 | `ctf_pcap_profile` |
| pwntools、ROPgadget、ropper、checksec | Pwn 自动化、gadget 和保护检查 | 由 `ctf_tool_audit` 探测，缺失时再安装 |
| patchelf、strace、ltrace、seccomp-tools | ELF 元数据、系统调用、库调用和 seccomp | 由 `ctf_tool_audit` 探测 |
| ffuf、feroxbuster、httpx、sqlmap | Web 内容发现和结构化验证 | 由 `ctf_tool_audit` 探测；请求工具仍优先使用 curl |
| Ghidra、angr、Z3、Sage、capa、FLOSS | 复杂反编译、符号执行、约束和样本画像 | 作为后续能力，先审计后调用 |

官方安装/配置资料入口记录在源码和 setup 请求中，便于人工按当前发行版完成安装：

```text
https://pwndbg.re/
https://github.com/pwndbg/pwndbg
https://github.com/radareorg/radare2
https://docs.hex-rays.com/
https://github.com/hangwin/mcp-chrome
https://app.tavily.com/
https://docs.mitmproxy.org/
https://www.wireshark.org/docs/man-pages/tshark.html
https://blackarch.org/
```

### 安装到 Harness Web profile

默认组合包 `cordis.patch.yml` 会同时启用车联网和 CTF 插件：

```bash
cd /path/to/deepseek-harness-vehicle-security
npx @deepseek-ai/dsh@next plugin --profile web add .
npx @deepseek-ai/dsh@next web --dump-config
```

如果只需要 CTF 侧配置，可以参考 `cordis.ctf.patch.yml` 中的两个条目，只启用：

```yaml
- id: ctf-tools
  name: dsh-vehicle-security/ctf-tools
- id: ctf-skills
  name: dsh-vehicle-security/ctf-skills
```

从题目工作目录启动 DSH，这样文件类工具会使用当前会话的工作区：

```bash
cd /path/to/ctf-challenge
npx @deepseek-ai/dsh@next web
```

### CTF 调用示例

```text
先用 ctf_start 分析 chall，类别自动判断。
使用 ctf_tool_audit 检查本机 CTF 工具。
对 chall 做 ctf_pwn_profile，然后按 nextActions 选择 GDB 或 ROP 工具。
对 cipher.txt 做 ctf_crypto_probe，先不要写脚本。
对 capture.pcapng 做 ctf_pcap_profile。
对 http://127.0.0.1:8080/ 做 ctf_http_request，并用 ctf_http_diff 对比参数变化。
服务还没启动，生成 ctf_human_request 告诉我要做什么并返回哪些字段。
```

Codex 插件位于：

```text
codex-plugin/plugins/ctf-security
```

本地 marketplace 已包含 `ctf-security`。Codex 安装后优先使用 `$investigate-ctf`，再根据 `ctf_start` 返回的 `recommendedTool` 调用具体工具。
