---
name: solve-ctf-re
description: Tool-first reverse-engineering CTF skill. Use when the challenge is an ELF, PE, Mach-O, script, or source-like artifact and the agent should profile the file, pick installed tools first, and avoid writing a solver script too early.
---

# Solve CTF RE

1. Call `ctf_tool_audit` when local capability state is unknown or stale. Use `ctf_start` when routing or ranked choices are useful; both are optional when the artifact and backend are already known.
2. Use `ctf_re_profile` on the highest-value binary or source artifact.
3. Use `ctf_re_r2_query` for fast headless analysis, JSON metadata, xrefs, and focused disassembly.
4. Use `mcp.ida_pro` when configured for the IDA database, decompiler, functions, types, and xrefs. Use `ctf_re_ida_script` to generate a focused IDAPython script for that MCP or the IDA UI.
5. Set `execute: true` on `ctf_re_ida_script` only when IDA CLI batch execution is specifically needed and `re.ida_cli` is available.
6. Use `ctf_pwn_gdb_probe` or `ctf_pwn_debug_probe` only when runtime state, anti-debug, or branch behavior matters.
7. Use `ctf_rop_search` when mitigation state suggests gadget work.
8. Use `mcp.tavily` for CVE, vulnerable-version, dependency, protocol, or tool documentation lookup when the local evidence requires external context.
9. Use `ctf_tool_setup` only when the selected IDA/r2/debugger backend is missing or an optional CLI fallback is needed; the human returns only logs, screenshots, or OCR text.
10. Use `ctf_human_request` only when a user must launch a service, click a UI, attach a device, or return logs/screenshots/OCR text.

## Tool Graph

```text
artifact -> ctf_artifact_profile -> ctf_re_profile
prompt-only -> ctf_start -> ctf_tool_audit -> ctf_re_profile
static query -> ctf_re_r2_query
IDA MCP -> mcp.ida_pro -> ctf_re_ida_script
IDA batch fallback -> ctf_re_ida_script(execute=true) -> ctf_tool_setup(ida_pro)
runtime state -> ctf_pwn_gdb_probe -> ctf_pwn_debug_probe
need gadget -> ctf_rop_search
need CVE/version context -> mcp.tavily
need human -> ctf_human_request
```

## Notes

- Prefer the relevant installed tool among `readelf`, `strings`, `nm`, `objdump`, `r2`, IDA MCP, or GDB-backed probes before any generated script.
- Preserve hashes, offsets, imports, strings, and exact command argv.
- Promote a hypothesis only after a tool returns a reproducible signal.
