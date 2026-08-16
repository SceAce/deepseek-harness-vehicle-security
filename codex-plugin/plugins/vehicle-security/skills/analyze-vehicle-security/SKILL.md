---
name: analyze-vehicle-security
description: Analyze vehicle-security programs and artifacts with an evidence-driven workflow. Use for native executables, ECU or gateway binaries, firmware, Android components, CAN candump or Vector ASC logs, UDS/ISO-TP payloads, tool audits, reverse-engineering hypotheses, and validation with IDA Pro, radare2, GDB/Pwndbg, traces, or captures.
---

# Analyze Vehicle Security

Build conclusions from reproducible evidence. Use the bundled CLI for deterministic collection, then use specialist tools to test the resulting hypotheses.

For an attachment, short prompt, lab target, directory, or mixed vehicle attack chain that still needs routing, use the sibling `$investigate-vehicle-security` skill first.

## Core Loop

1. Define one concrete question, such as "where is UDS SecurityAccess authorized?" or "can a network field reach command execution?"
2. Preserve and hash the artifact. Run the narrowest deterministic command.
3. Separate records into `E-*` observations, `C-*` bounded conclusions, `H-*` hypotheses, and `V-*` validation steps.
4. Trace inputs through parsing, state changes, authorization checks, dangerous sinks, and outputs. Record addresses and function names.
5. Execute the corresponding `V-*` step with IDA Pro MCP, radare2, GDB/Pwndbg, syscall traces, or a saved bus/network capture.
6. Promote a hypothesis only when the success criteria are met. Otherwise retain it as a lead or record the counterevidence that rules it out.

Never equate an imported function, string, missing hardening flag, or decompiler guess with a vulnerability. A useful conclusion states the affected component, input, reachable path, observed behavior, conditions, evidence IDs, confidence, and remaining boundary.

For executables and libraries, read [references/program-analysis.md](references/program-analysis.md) before choosing deeper tools. For CAN/UDS, firmware, Android, and hardware captures, read [references/workflows.md](references/workflows.md).

## Deterministic Commands

```bash
node "$SKILL_DIR/scripts/vehicle_security.mjs" investigate --objective 'decode diagnostic traffic' --path logs/drive.asc
node "$SKILL_DIR/scripts/vehicle_security.mjs" audit
node "$SKILL_DIR/scripts/vehicle_security.mjs" program-analyze --path bin/gateway --focus 'diagnostic authentication'
node "$SKILL_DIR/scripts/vehicle_security.mjs" uds-decode --payload '03 22 F1 90'
node "$SKILL_DIR/scripts/vehicle_security.mjs" can-summary --path logs/drive.asc --id-filter 0x7E0,0x7E8
node "$SKILL_DIR/scripts/vehicle_security.mjs" artifact-triage --path firmware/gateway.bin
```

- `program-analyze --path PATH [--focus TEXT] [--max-strings N]`: collect program identity, ELF metadata and hardening, imports, tagged strings, bounded conclusions, hypotheses, and validation plans.
- `investigate --objective TEXT [--path PATH] [--input-kind KIND] [--context TEXT]`: rank investigation lanes and return phase gates, first validation actions, language choices, evidence rules, and stop conditions.
- `audit`: inventory CAN, firmware, reverse-engineering, Android, RF, and debugging tools.
- `uds-decode --payload PAYLOAD [--no-isotp]`: decode one UDS request or response.
- `can-summary --path PATH [--id-filter IDS] [--max-frames N]`: summarize saved candump or ASC traffic.
- `artifact-triage --path PATH [--no-binwalk]`: collect size, SHA-256, entropy, file type, and optional Binwalk signatures.

Keep all input paths inside `VEHICLE_WORKSPACE_ROOT` or the current workspace. Preserve raw tool output alongside the final report so another analyst can reproduce every promoted conclusion.
