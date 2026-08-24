---
name: solve-ctf-re
description: Tool-first reverse-engineering CTF skill. Use when the challenge is an ELF, PE, Mach-O, script, or source-like artifact and the agent should profile the file, pick installed tools first, and avoid writing a solver script too early.
---

# Solve CTF RE

除工具名、命令、路径、代码和原始日志外，使用中文交流。所有 Python 命令必须使用 `/home/source/tools/PyVenv/CTF/bin/python`。

1. Call `ctf_tool_audit` when local capability state is unknown or stale. Use `ctf_start` when routing or ranked choices are useful; both are optional when the artifact and backend are already known.
2. Use `ctf_re_profile` on the highest-value binary or source artifact.
3. Use `ctf_re_r2_query` for fast headless analysis, JSON metadata, xrefs, and focused disassembly.
4. For PE/Windows artifacts, use `ctf_re_pe_profile` before runtime Wine or deeper IDA/r2 work.
5. For APK/DEX artifacts, use `ctf_re_android_profile` before `ctf_re_android_jadx` or emulator/device interaction.
6. Use `ctf_re_android_jadx` when Java/XML source output is needed; keep the generated workspace directory as evidence.
7. For ARM/AArch64 and other non-native artifacts, use `ctf_re_arch_profile` before QEMU or debugger work.
8. Use `ctf_re_qemu_probe` only after architecture identification and only with bounded arguments.
9. Use `mcp.ida_pro` when configured for the IDA database, decompiler, functions, types, and xrefs. Use `ctf_re_ida_script` to generate a focused IDAPython script for that MCP or the IDA UI.
10. Set `execute: true` on `ctf_re_ida_script` only when IDA CLI batch execution is specifically needed and `re.ida_cli` is available.
11. Use `ctf_pwn_gdb_probe` or `ctf_pwn_debug_probe` only when runtime state, anti-debug, or branch behavior matters.
12. Use `ctf_rop_search` when mitigation state suggests gadget work.
13. Use `mcp.tavily` for CVE, vulnerable-version, dependency, protocol, or tool documentation lookup when the local evidence requires external context.
14. Use `ctf_tool_setup` only when the selected IDA/r2/debugger/backend is missing or an optional CLI fallback is needed; the human returns only logs, screenshots, or OCR text.
15. Use `ctf_human_request` only when a user must launch a service, click a UI, attach a device, or return logs/screenshots/OCR text.

## Tool Graph

```text
artifact -> ctf_artifact_profile -> ctf_re_profile
prompt-only -> ctf_start -> ctf_tool_audit -> ctf_re_profile
static query -> ctf_re_r2_query
PE/Windows -> ctf_re_pe_profile -> ctf_re_r2_query / mcp.ida_pro / Wine
APK/DEX -> ctf_re_android_profile -> ctf_re_android_jadx / mcp.ida_pro / ctf_human_request
ARM/AArch64 -> ctf_re_arch_profile -> ctf_re_qemu_probe / ctf_re_r2_query / mcp.ida_pro
IDA MCP -> mcp.ida_pro -> ctf_re_ida_script
IDA batch fallback -> ctf_re_ida_script(execute=true) -> ctf_tool_setup(ida_pro)
runtime state -> ctf_pwn_gdb_probe -> ctf_pwn_debug_probe
need gadget -> ctf_rop_search
need CVE/version context -> mcp.tavily
need human -> ctf_human_request
```

## Notes

- Prefer the relevant installed tool among `readelf`, `llvm-readobj`, `llvm-objdump`, `strings`, `nm`, `objdump`, `r2`, IDA MCP, JADX, aapt2, QEMU, or GDB-backed probes before any generated script.
- Preserve hashes, offsets, imports, strings, and exact command argv.
- Promote a hypothesis only after a tool returns a reproducible signal.
