---
name: investigate-ctf
description: Tool-first CTF investigation for RE, pwn, crypto, misc, and web challenges. Use when a challenge file, source tree, binary, pcap, archive, URL, or short CTF prompt is provided and Codex should inspect local capabilities before writing scripts.
---

# Investigate CTF

Use the tool layer before writing a solver. When the local capability state or artifact category is unknown, call `ctf_tool_audit` and/or `ctf_start`; when the target and required backend are already known, call the relevant category tool directly. For focused work, switch to `$solve-ctf-re`, `$solve-ctf-pwn`, or `$solve-ctf-web`.

## Language and Pwn startup rules

- 除工具名、命令、路径、代码、协议字段和原始日志外，模型必须使用中文交流。
- 对 Pwn 二进制，`ctf_pwninit` 是第一项模型可见的 Pwn 动作。调用 `ctf_start` 后，按其返回的 `recommendedTool` 和 `toolChoices[0]` 调用 `ctf_pwninit`；不要先调用 `ctf_pwn_profile`、GDB、r2 或自写 Python。
- `ctf_pwninit` 没有匹配的 `ld`/`libc` 时会自动执行 `--only-init`，随后再进入画像和运行时选择；这不是跳过该首步的理由。
- 所有 Python 命令、脚本执行和模块检查必须使用 `/home/source/tools/PyVenv/CTF/bin/python`，不得回退到 `python`、`python3`、`$VIRTUAL_ENV` 或工作区虚拟环境。优先调用 `ctf_python_exec` 执行内联代码或工作区脚本。

## Core Rule

1. Use `ctf_tool_audit` when capability state is unknown or stale; it reports callable local tool bindings, backend dependencies, paths, and example arguments.
2. Use the reported Python interpreter, venv, executable paths, and MCP state as the capability inventory.
3. Use `ctf_start` when routing or a ranked set of tool choices is useful; pass the known `path`, `url`, `category`, `objective`, and `context`.
4. Choose among `toolChoices`, `recommendedTool`, `nextActions`, and the tool graph according to the evidence question. These are recommendations, not a fixed execution order.
5. Use `/home/source/tools/PyVenv/CTF/bin/python` and its installed modules for every Python action.
6. Prefer `mcp.ida_pro` for IDA database/decompiler operations, `mcp.chrome` for interactive browser state, and `mcp.tavily` for CVE/version/reference lookup when configured.
7. If a tool returns `humanRequired`, present the request as a structured action with its exact ordered operations and wait for only `log`, `screenshot`, or `ocr_text`.
8. If `TAVILY_API_KEY` is the only missing value, call `ctf_mcp_configure`; do not ask the user to hand-write JSON or paths.
9. Write a new script only after the relevant local tool or configured MCP has been considered and leaves a concrete gap.
10. When a structured local tool is reported ready, call it directly before reproducing the same operation with `bash`; use the shell only after an explicit tool failure or a clearly documented missing operation.

## Tool Map

- Intake: `ctf_start`, `ctf_tool_audit`, `ctf_artifact_profile`
- RE/Pwn: `ctf_re_profile`, `ctf_pwn_profile`, `ctf_pwninit`, `ctf_pwn_debug_probe`, `ctf_pwn_gdb_probe`, `ctf_re_r2_query`, `ctf_re_ida_script`, `ctf_rop_search`, `ctf_seccomp_profile`, `ctf_python_exec`
- Crypto/Misc: `ctf_crypto_probe`, `ctf_misc_triage`, `ctf_pcap_profile`
- Web: `ctf_http_request`, `ctf_http_diff`, `ctf_web_browser_probe`, `ctf_web_capture_probe`
- MCP/configuration: `ctf_mcp_configure`, `mcp.ida_pro`, `mcp.r2`, `mcp.gdb_pwndbg`, `mcp.chrome`, `mcp.tavily`
- Human actions: `ctf_human_request`

`ctf_tool_audit.toolBindings` describes which plugin tools are callable, what local backend they use, and an example argument object. It describes availability and fallbacks; it does not mandate calling every listed tool.
 
## Skill Routing

- Use `$solve-ctf-re` for binaries, decompilation, string/import tracing, and implementation recovery.
- Use `$solve-ctf-pwn` for mitigations, runtime probing, gadget search, and exploit validation.
- Use `$solve-ctf-web` for HTTP baselines, response diffs, and service handoff.

## Evidence

Keep the same lightweight model across categories:

- `E-*`: observation from a tool, command, artifact, response, trace, or user-provided state.
- `H-*`: hypothesis with a specific validation action.
- `V-*`: one tool call or one human action with expected signal.
- `F-*`: reproduced flag, exploit condition, decoded payload, or recovered value.

Prefer short tool calls that answer one question. Preserve exact paths, hashes, command argv, endpoint, status code, and important offsets. Never include API keys in observations, command records, screenshots, OCR returns, or reports.
