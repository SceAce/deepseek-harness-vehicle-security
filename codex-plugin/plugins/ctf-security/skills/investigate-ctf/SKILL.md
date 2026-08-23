---
name: investigate-ctf
description: Tool-first CTF investigation for RE, pwn, crypto, misc, and web challenges. Use when a challenge file, source tree, binary, pcap, archive, URL, or short CTF prompt is provided and Codex should inspect local capabilities before writing scripts.
---

# Investigate CTF

Use the tool layer before writing a solver. The first action for every CTF prompt is `ctf_tool_audit`; then call `ctf_start` with the artifact, URL, category, or challenge text. For focused work, switch to `$solve-ctf-re`, `$solve-ctf-pwn`, or `$solve-ctf-web`.

## Core Rule

1. Call `ctf_tool_audit` before any category tool or custom script.
2. Use the reported Python interpreter, venv, executable paths, and MCP state as the capability inventory.
3. Call `ctf_start` with the known `path`, `url`, `category`, `objective`, and `context`.
4. Follow `recommendedTool`, `recommendedArgs`, and the returned tool graph.
5. Prefer `/home/source/tools/PyVenv/CTF/bin/python` and its installed modules for Python actions.
6. Prefer `mcp.ida_pro` for IDA database/decompiler operations, `mcp.chrome` for interactive browser state, and `mcp.tavily` for CVE/version/reference lookup when configured.
7. If a tool returns `humanRequired`, present the request as a structured action with its exact ordered operations and wait for only `log`, `screenshot`, or `ocr_text`.
8. If `TAVILY_API_KEY` is the only missing value, call `ctf_mcp_configure`; do not ask the user to hand-write JSON or paths.
9. Write a new script only after the audit, local tools, and configured MCPs leave a concrete gap.

## Tool Map

- Intake: `ctf_start`, `ctf_tool_audit`, `ctf_artifact_profile`
- RE/Pwn: `ctf_re_profile`, `ctf_pwn_profile`, `ctf_pwninit`, `ctf_pwn_debug_probe`, `ctf_pwn_gdb_probe`, `ctf_rop_search`
- Crypto/Misc: `ctf_crypto_probe`, `ctf_misc_triage`, `ctf_pcap_profile`
- Web: `ctf_http_request`, `ctf_http_diff`, `ctf_web_browser_probe`, `ctf_web_capture_probe`
- MCP/configuration: `ctf_mcp_configure`, `mcp.ida_pro`, `mcp.r2`, `mcp.gdb_pwndbg`, `mcp.chrome`, `mcp.tavily`
- Human actions: `ctf_human_request`
 
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
