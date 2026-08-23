---
name: investigate-ctf
description: Tool-first CTF investigation for RE, pwn, crypto, misc, and web challenges. Use when a challenge file, source tree, binary, pcap, archive, URL, or short CTF prompt is provided and Codex should inspect local capabilities before writing scripts.
---

# Investigate CTF

Use the tool layer before writing a solver. The first action for any CTF prompt is `ctf_start` when a file, URL, category, or challenge text is available; otherwise call `ctf_tool_audit` and request the missing input.

## Core Rule

1. Call `ctf_start` with the known `path`, `url`, `category`, `objective`, and `context`.
2. Follow `recommendedTool` and `recommendedArgs`.
3. If a tool returns `humanRequired`, present the request as a structured action for the user and wait for the returned fields.
4. Write a new script only after the tool audit shows no suitable local capability or the existing tools produced a concrete gap.

## Tool Map

- Intake: `ctf_start`, `ctf_tool_audit`, `ctf_artifact_profile`
- RE/Pwn: `ctf_re_profile`, `ctf_pwn_profile`, `ctf_pwn_debug_probe`, `ctf_rop_search`
- Crypto/Misc: `ctf_crypto_probe`, `ctf_misc_triage`, `ctf_pcap_profile`
- Web: `ctf_http_request`, `ctf_http_diff`
- Human actions: `ctf_human_request`

## Evidence

Keep the same lightweight model across categories:

- `E-*`: observation from a tool, command, artifact, response, trace, or user-provided state.
- `H-*`: hypothesis with a specific validation action.
- `V-*`: one tool call or one human action with expected signal.
- `F-*`: reproduced flag, exploit condition, decoded payload, or recovered value.

Prefer short tool calls that answer one question. Preserve exact paths, hashes, command argv, endpoint, status code, and important offsets.
