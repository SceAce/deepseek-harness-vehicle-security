---
name: investigate-vehicle-security
description: Route and execute evidence-driven vehicle-security investigations from an attachment, a short natural-language clue, a CTF or lab target, a directory, a capture, or a program. Use when Codex must decide how to begin, select between CAN/UDS, DoIP/SOME-IP/network, firmware, native program, Android, web/API, hardware/RF, or mixed attack-chain lanes, choose scripts and MCP tools, troubleshoot blockers, preserve data, validate hypotheses quickly, maintain case state, or plan the next operation.
---

# Investigate Vehicle Security

Turn an underspecified input into a small number of testable questions, collect reproducible evidence, and follow the highest-value path until the objective is answered or a concrete dependency is identified.

## Start Every Case

1. Restate the objective as one decision or question. Record known constraints and what success looks like.
2. Inventory attachments, paths, endpoints, captures, credentials, hardware, observed behavior, and existing notes. Treat absent evidence as a gap, not a negative result.
3. Call the `vehicle_investigation_plan` tool. For file inputs, use a path relative to the active workspace. If the tool is unavailable, run:

```bash
node "$SKILL_DIR/../analyze-vehicle-security/scripts/vehicle_security.mjs" investigate --objective 'QUESTION' --path 'RELATIVE_PATH'
```

4. Create a case directory using the returned `caseId` and the layout in [references/evidence-and-data.md](references/evidence-and-data.md). Keep the original under `raw/` or reference its immutable source path; place extracted, converted, patched, decoded, and replay-ready files under `working/`.
5. Select one primary lane. Read [references/routing.md](references/routing.md) for the selected lane and [references/formal-process.md](references/formal-process.md) for phase gates.

For broad directories, triage metadata and filenames first, then inspect only the ranked candidates. For a sentence-only input, make the first action collect a distinguishing artifact, response, capture, binary, configuration, or observable state.

## Investigation Loop

Maintain these records:

- `E-*`: direct observation with artifact identity, source, command/tool, time, and raw output path.
- `C-*`: bounded conclusion supported by one or more evidence IDs.
- `H-*`: open hypothesis with rationale, confidence, and competing explanations.
- `V-*`: one validation action with expected positive signal, negative signal, risk, and stop condition.
- `F-*`: reproducible finding with affected component, preconditions, impact, evidence, and verification.

For each iteration:

1. Rank at most three open hypotheses by expected information gain, relevance to the objective, execution cost, and dependency availability.
2. Run the cheapest `V-*` action that distinguishes the top hypothesis from its strongest alternative.
3. Save raw output before summarizing it. Record counterevidence and negative results.
4. Promote a hypothesis only after its success criteria are reproduced. Keep strings, imports, missing hardening, decompiler output, and protocol guesses as leads until reachability or behavior is observed.
5. Update `case.json`, select the next operation, and stop broad enumeration once one lane produces a concrete trust-boundary path.

## Tool Strategy

Use the plugin's `vehicle_*` tools for deterministic intake, hashing, CAN summaries, UDS decoding, program analysis, firmware triage, and tool inventory. Use the sibling `$analyze-vehicle-security` skill for exact CLI commands and detailed program-analysis rules.

Use specialist tools only after defining the expected signal:

- Use IDA Pro MCP for decompilation, cross-references, function and type recovery, callers/callees, dispatch tables, and annotated evidence.
- Use radare2 or Rizin for fast headless queries, scripting, function graphs, and a second static opinion.
- Use GDB/Pwndbg, tracing, emulation, or Frida for runtime values, branches, calls, syscalls, buffers, IPC, and state transitions.
- Use Wireshark/TShark for conversation and protocol hierarchy; use small Python decoders for repeatable field hypotheses.
- Use Binwalk and filesystem tools for discovery, then analyze extracted executables and configuration as one system.

Read [references/mcp-playbook.md](references/mcp-playbook.md) before a deep IDA/r2/debugger loop. Read [references/language-and-tools.md](references/language-and-tools.md) before writing a new script. Prefer an existing deterministic helper when it already answers the question.

## Recovery Rules

When a tool or analysis path fails, preserve the exact command, version, input identity, exit status, and error output. Classify the failure as input, format, environment, permission, dependency, timeout/size, protocol-state, tool limitation, or hypothesis failure. Then change one variable at a time using [references/troubleshooting.md](references/troubleshooting.md).

Do not loop on the same failing action. After two equivalent failures, switch representation or tool: convert the capture, narrow the file, use a second parser, inspect code references, move from static to dynamic observation, or explicitly record the missing dependency.

## Deliverable

Report:

1. Objective, case ID, inputs, hashes, environment, and selected lane.
2. Confirmed facts and conclusions with evidence IDs.
3. Ruled-out and open hypotheses with confidence.
4. Reproduction or validation steps and observed signals.
5. Data paths for raw evidence, working artifacts, scripts, and reports.
6. The next three operations ordered by information gain, including required dependencies and stop conditions.

Read [references/evidence-and-data.md](references/evidence-and-data.md) for the case state schema and reporting fields.
