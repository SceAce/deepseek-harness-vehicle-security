# MCP and Specialist Tool Playbook

## Vehicle Security MCP

Use the plugin-provided `vehicle-security` stdio MCP first. It exposes:

- `vehicle_investigation_plan`
- `vehicle_tool_audit`
- `vehicle_can_log_summary`
- `vehicle_uds_decode`
- `vehicle_program_analyze`
- `vehicle_artifact_triage`

Always pass `workspaceRoot` and a relative `path` for file-based calls. This keeps the MCP configuration movable and avoids embedding a repository or home-directory path.

## IDA Pro MCP

Open the exact artifact identified in the case. Record the database/session and image base. Drive IDA with a question rather than a broad request:

1. Search a protocol constant, error string, import, service ID, DID, SID, method ID, or known address.
2. Resolve data/code cross-references and containing functions.
3. Inspect callers, callees, dispatch tables, switch cases, types, and pseudocode.
4. Rename or annotate only evidence-backed entities.
5. Return addresses, function names, relevant expressions, evidence IDs, and the next runtime observation point.

Use IDAPython when a repeatable query spans many functions or database objects. Keep scripts in the case `scripts/` directory.

## radare2/Rizin

Use headless commands for fast metadata, strings, functions, xrefs, graphs, and a second static opinion. Save the exact command and output. Prefer scripts or `-qc` commands over an opaque interactive session when results support a conclusion.

Use an r2 MCP when installed; otherwise use the local CLI. Treat disagreement with IDA as a signal to inspect boundaries, calling convention, base address, analysis completeness, or data types.

## Dynamic Tools

Before GDB/Pwndbg, Frida, tracing, emulation, or replay, state the process/image, input, breakpoint or hook, expected positive and negative signals, required runtime state, and stop condition. Save registers, buffers, branch outcomes, calls, syscalls, logs, packets, or outputs that distinguish the hypothesis.

Never use a decompiler rendering alone as proof of runtime reachability or external control.
