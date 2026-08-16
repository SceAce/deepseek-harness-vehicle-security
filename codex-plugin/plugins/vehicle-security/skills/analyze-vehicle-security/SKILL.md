---
name: analyze-vehicle-security
description: Analyze local vehicle-security artifacts with deterministic helpers. Use for CAN candump or Vector ASC logs, UDS/ISO-TP payloads, firmware and binary triage, and auditing installed automotive and reverse-engineering tools.
---

# Analyze Vehicle Security

Use the bundled CLI for repeatable, read-only analysis. It runs against the current workspace and emits JSON suitable for further reasoning.

## Quick Start

Set `SKILL_DIR` to this skill directory, then run:

```bash
node "$SKILL_DIR/scripts/vehicle_security.mjs" audit
node "$SKILL_DIR/scripts/vehicle_security.mjs" uds-decode --payload '03 22 F1 90'
node "$SKILL_DIR/scripts/vehicle_security.mjs" can-summary --path fixtures/candump.log
node "$SKILL_DIR/scripts/vehicle_security.mjs" artifact-triage --path firmware/gateway.bin
```

## Workflow

1. Preserve the original artifact and establish its workspace-relative path.
2. Run the narrowest deterministic command first: `audit`, `uds-decode`, `can-summary`, or `artifact-triage`.
3. Report raw observations separately from interpretation. Include paths, IDs, timestamps, hashes, and tool versions.
4. Use [references/workflows.md](references/workflows.md) for follow-up CAN/UDS, firmware, Android, and hardware-dependent analysis.

The helpers reject missing files, oversized files, and symlink paths that escape the workspace. Firmware triage computes metadata and performs an optional read-only signature scan; it does not execute or modify samples. Do not transmit live CAN frames from this skill.

## Command Options

- `audit`: inspect common CAN, firmware, reverse-engineering, Android, RF, and debugging executables, including Pwndbg through GDB.
- `uds-decode --payload PAYLOAD [--no-isotp]`: decode UDS requests, positive responses, negative response codes, and common ISO-TP prefixes.
- `can-summary --path PATH [--id-filter IDS] [--max-frames N]`: parse candump or Vector ASC logs and summarize IDs, channels, counts, and timestamps.
- `artifact-triage --path PATH [--no-binwalk]`: return size, SHA-256, sampled entropy, `file` output, and optional Binwalk output.

When a command fails, preserve the error and inspect the input path or payload before retrying. Keep generated reports alongside the case artifacts.
