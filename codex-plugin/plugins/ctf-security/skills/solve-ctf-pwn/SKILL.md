---
name: solve-ctf-pwn
description: Tool-first pwn skill for binaries, heap, stack, ROP, and debugger-driven validation. Use when the next step should be checksec, GDB, gadget search, or runtime probing instead of a handwritten exploit script.
---

# Solve CTF Pwn

1. Call `ctf_start` or `ctf_tool_audit` first.
2. Use `ctf_pwn_profile` to collect mitigation state, imports, and strings.
3. Use `ctf_pwn_gdb_probe` for Pwndbg context, vmmap, registers, and backtrace.
4. Use `ctf_pwn_debug_probe` for generic GDB fallback or additional bounded commands.
5. Use `ctf_rop_search` for gadget enumeration.
6. Use `ctf_tool_setup` with `gdb_pwndbg` when the local debugger capability is missing.
7. Use `ctf_human_request` when the program needs a user-run service, device, GUI, or screenshot/log/OCR return.

## Tool Graph

```text
binary -> ctf_artifact_profile -> ctf_pwn_profile
mitigation/runtime -> ctf_pwn_gdb_probe -> ctf_pwn_debug_probe
gadget search -> ctf_rop_search
missing debugger -> ctf_tool_setup(gdb_pwndbg)
service missing -> ctf_human_request
prompt-only -> ctf_start -> ctf_tool_audit -> ctf_pwn_profile
```

## Notes

- Prefer installed tooling like `checksec`, `gdb`, `ROPgadget`, `ropper`, and `pwntools`.
- Record exact argv, breakpoint names, register dumps, and observed transitions.
- Use scripts only after the debugger or gadget tools leave a real gap.
