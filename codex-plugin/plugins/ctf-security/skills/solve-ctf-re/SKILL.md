---
name: solve-ctf-re
description: Tool-first reverse-engineering CTF skill. Use when the challenge is an ELF, PE, Mach-O, script, or source-like artifact and the agent should profile the file, pick installed tools first, and avoid writing a solver script too early.
---

# Solve CTF RE

1. Call `ctf_start` or `ctf_tool_audit` first.
2. Use `ctf_re_profile` on the highest-value binary or source artifact.
3. Use `ctf_re_r2_query` for fast headless analysis, JSON metadata, xrefs, and focused disassembly.
4. Use `ctf_re_ida_script` to generate an IDAPython script; set `execute: true` only after IDA CLI is detected.
5. Use `ctf_pwn_gdb_probe` or `ctf_pwn_debug_probe` only when runtime state, anti-debug, or branch behavior matters.
6. Use `ctf_rop_search` when mitigation state suggests gadget work.
7. Use `ctf_tool_setup` when IDA or an external RE MCP is missing; the human must install/configure it and return only logs, screenshots, or OCR text.
8. Use `ctf_human_request` only when a user must launch a service, click a UI, attach a device, or return logs/screenshots/OCR text.

## Tool Graph

```text
artifact -> ctf_artifact_profile -> ctf_re_profile
prompt-only -> ctf_start -> ctf_tool_audit -> ctf_re_profile
static query -> ctf_re_r2_query
IDA workflow -> ctf_re_ida_script -> ctf_tool_setup(ida_pro)
runtime state -> ctf_pwn_gdb_probe -> ctf_pwn_debug_probe
need gadget -> ctf_rop_search
need human -> ctf_human_request
```

## Notes

- Prefer `readelf`, `strings`, `nm`, `objdump`, `r2`, or GDB-backed probes before any generated script.
- Preserve hashes, offsets, imports, strings, and exact command argv.
- Promote a hypothesis only after a tool returns a reproducible signal.
