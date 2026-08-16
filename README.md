# DeepSeek Harness 车联网安全插件

面向车联网比赛和本地样本分析的 DeepSeek Harness + Codex 组合包。当前版本提供一个正式调查流程和六个确定性工具：

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

Codex 中使用 `$investigate-vehicle-security` 作为总入口，使用 `$analyze-vehicle-security` 执行确定性采集和深入程序分析。详细规则随 Skill 分层加载，不会一次占满模型上下文。

## 设计边界

- 文件路径限定在 `workspaceRoot` 内，并通过真实路径检查符号链接越界。
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

从待分析项目目录启动，使默认的 `workspaceRoot: '.'` 指向该项目：

```bash
cd /path/to/competition-case
npx @deepseek-ai/dsh@next web
```

Web UI 默认地址是 `http://127.0.0.1:3080`。

## 配置

组合包的默认配置位于 `cordis.patch.yml`：

```yaml
- insert:
    - id: vehicle-security
      name: dsh-vehicle-security
      config:
        workspaceRoot: '.'
        maxFileBytes: 268435456
        maxOutputChars: 40000
        commandTimeoutMs: 20000
        enableBinwalk: true
```

比赛固件超过 256 MiB 时提高 `maxFileBytes`。禁用 `enableBinwalk` 后，初检仍会返回大小、SHA-256、采样熵和 `file` 类型。

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
