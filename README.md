# DeepSeek Harness 车联网安全插件

面向车联网比赛和本地样本分析的 DeepSeek Harness 组合包。当前版本提供四个只读工具：

| 工具 | 用途 |
| --- | --- |
| `vehicle_tool_audit` | 检查 CAN、固件、逆向、Android、RF 工具的路径和版本 |
| `vehicle_can_log_summary` | 解析 candump 和 Vector ASC 日志，统计 CAN ID、通道与时间范围 |
| `vehicle_uds_decode` | 解码 UDS 请求、正响应、负响应和常见 ISO-TP 前缀 |
| `vehicle_artifact_triage` | 计算固件哈希、采样熵、文件类型并执行只读 Binwalk 签名扫描 |

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
cd /home/source/Tmp/deepseek-harness-vehicle-security
pnpm install
pnpm test
pnpm run check
```

源码使用严格模式 TypeScript，`pnpm run build` 将 Harness 产物编译到 `lib/`，并把同一套分析模块同步到 Codex 技能的 `runtime/`。这样可以获得插件配置、工具参数和分析结果的静态类型检查，同时避免 Harness 与 Codex 各自维护一份解析逻辑。

## 安装到 Harness Web profile

当前 Harness 使用 `next` 发布标签。把本目录作为本地组合包链接到内置 `web` profile：

```bash
cd /home/source/Tmp/deepseek-harness-vehicle-security
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
使用 vehicle_tool_audit 检查当前车联网工具环境。
分析 logs/drive.asc，只统计 0x7E0 和 0x7E8。
解码 UDS 报文 03 22 F1 90。
对 firmware/gateway.bin 做只读固件初检。
```

## Codex / GPT-5.4

仓库同时包含一个模型无关的 Codex 插件，可用于 GPT-5.4 及其他支持 Codex 技能的模型。入口位于：

```text
codex-plugin/plugins/vehicle-security
```

本地 marketplace 位于 `codex-plugin/marketplace.json`。安装后在对话中调用 `$analyze-vehicle-security`，也可以直接验证其确定性命令行助手：

```bash
SKILL_DIR="$PWD/codex-plugin/plugins/vehicle-security/skills/analyze-vehicle-security"
node "$SKILL_DIR/scripts/vehicle_security.mjs" audit
node "$SKILL_DIR/scripts/vehicle_security.mjs" uds-decode --payload '03 22 F1 90'
node "$SKILL_DIR/scripts/vehicle_security.mjs" can-summary --path fixtures/candump.log
node "$SKILL_DIR/scripts/vehicle_security.mjs" artifact-triage --path firmware/gateway.bin
```

Codex 版本复用编译后的 TypeScript 核心模块；修改 `src/*.ts` 后执行 `pnpm run build` 即可同步运行时。

## 打包分发

该项目将 TypeScript 编译为原生 ESM，并同时生成类型声明。生成的 tarball 可直接安装：

```bash
pnpm pack
npx @deepseek-ai/dsh@next plugin --profile web add ./dsh-vehicle-security-0.1.0.tgz
```

后续适合增加的模块是 DBC 信号解码、DoIP/SOME-IP 报文分析、UDS 会话日志重建和 IDA 导出结果解析。
