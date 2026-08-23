---
name: solve-ctf-pwn
description: Tool-first pwn skill for binaries, heap, stack, ROP, and debugger-driven validation. Use when the next step should be checksec, GDB, gadget search, or runtime probing instead of a handwritten exploit script.
---

# Solve CTF Pwn

除工具名、命令、路径、代码和原始日志外，使用中文交流。

1. Call `ctf_tool_audit` when local capability state is unknown or stale. Use `ctf_start` when category routing or ranked choices are useful; both are optional when the target and backend are already known.
2. For every Pwn binary, call `ctf_pwninit` first with `mode: "prepare"`. It performs the local initialization and switches matching `ld`/`libc` when available; without a runtime source it automatically runs the non-interactive `--only-init` path.
3. After `ctf_pwninit`, use `ctf_pwn_profile` to collect mitigation state, imports, and strings.
4. Choose `mcp.gdb_pwndbg` for configured interactive debugger state, or `ctf_pwn_gdb_probe` for bounded local Pwndbg context.
5. Choose `ctf_pwn_debug_probe` for generic GDB registers, stack, breakpoints, or bounded custom commands.
6. Choose `ctf_re_r2_query` for headless functions, xrefs, metadata, or focused disassembly.
7. Choose `ctf_rop_search` for gadget enumeration when the mitigation and control-flow hypothesis calls for it.
8. Use `mcp.tavily` for libc, CVE, package-version, or debugger-reference lookup when required.
9. Use `ctf_tool_setup` with `gdb_pwndbg` when the selected local debugger backend is missing.
10. Use `ctf_human_request` when the program needs a user-run service, device, GUI, or screenshot/log/OCR return.

## Tool Graph

```text
binary -> ctf_artifact_profile -> ctf_pwninit -> ctf_pwn_profile
runtime state -> mcp.gdb_pwndbg or ctf_pwn_gdb_probe or ctf_pwn_debug_probe
headless RE -> ctf_re_r2_query
gadget search -> ctf_rop_search
libc/CVE/version context -> mcp.tavily
missing debugger -> ctf_tool_setup(gdb_pwndbg)
service missing -> ctf_human_request
prompt-only -> ctf_start -> ctf_tool_audit -> ctf_pwn_profile
```

## Notes

- Prefer installed tooling like `checksec`, `gdb`, `ROPgadget`, `ropper`, and `pwntools`.
- `ctf_pwninit` is mandatory before other Pwn analysis actions. It auto-detects sibling `ld-*` and `libc-*` files, runs initialization when no pair exists, and uses pwninit backups before patching.
- After `ctf_pwninit`, rerun a debugger probe only when runtime evidence is needed; use the patched binary so the observed loader and libc match the challenge files.
- Every Python command must use `/home/source/tools/PyVenv/CTF/bin/python`.
- Record exact argv, breakpoint names, register dumps, and observed transitions.
- Use scripts only after the debugger or gadget tools leave a real gap.
