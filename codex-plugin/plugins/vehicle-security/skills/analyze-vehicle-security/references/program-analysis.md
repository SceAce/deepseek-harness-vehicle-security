# Evidence-driven program analysis

## 1. Define the question

Turn “analyze this program” into a testable objective: identify a protocol handler, locate an authorization decision, explain an update-verification path, trace a configuration value, or validate whether a recorded input reaches a sensitive operation. State the expected output and stop condition.

## 2. Establish the baseline

Run `program-analyze` first. Treat its fields as follows:

- `observations`: tool-derived facts with `E-*` identifiers.
- `conclusions`: statements supported within an explicit boundary.
- `hypotheses`: plausible explanations or risks awaiting proof.
- `validationSteps`: reproducible tests with success criteria and required evidence.

Record SHA-256, tool versions, architecture, entry point, linkage, hardening, imports, strings, and any analysis database path. Missing PIE, NX, RELRO, or a canary changes conditions; it is not a defect by itself.

## 3. Build the program map

Map these elements before following individual instructions:

1. Inputs: CAN/ISO-TP, DoIP, SOME/IP, MQTT, network sockets, IPC, files, environment, CLI, update packages, hardware devices.
2. Decoders and dispatch: framing, length checks, service IDs, command IDs, state machines, deserialization, routing tables.
3. Decisions: session state, authentication, security level, role, signature/hash verification, freshness/replay checks, feature flags.
4. Sinks: memory writes, process execution, file/update writes, privilege changes, diagnostic routines, transmit paths, crypto/key use.
5. Outputs: responses, logs, persistent state, bus/network messages, process exit, reboot or update state.

Name functions by evidence and role, for example `uds_dispatch_candidate_0x401230`, until behavior is validated.

## 4. Validate with the right tool

### IDA Pro MCP

Use IDA for decompilation, call graphs, types, cross-references, data structures, and renamed semantic maps. For every important claim, record the image base, function address, original symbol, renamed label, caller/callee path, pseudocode excerpt, and xrefs to constants or strings. Inspect all xrefs rather than the first matching one.

### radare2

Create a baseline with the argument array emitted by `V-000`. Useful interactive commands include:

```text
iI                 binary information and hardening
ie                 entry points
afl                functions
iij                imports as JSON
izzq               strings with addresses
axt @ ADDRESS      cross-references
pdf @ FUNCTION     disassembly
agfj @ FUNCTION    function graph as JSON
```

Save raw output and use addresses to correlate with IDA. Differences between tools are a reason to inspect loading/base assumptions, not to select the preferred answer.

### GDB and Pwndbg

Use a working copy and a recorded input fixture. Break at a validated parser, decision, or sink address; then record arguments, buffers, lengths, state, backtrace, mappings, and return path. Useful commands include `starti`, `info files`, `break *ADDRESS`, `run`, `bt`, `x`, `disassemble`, `vmmap`, and `telescope`. Account for PIE rebasing before comparing static addresses.

### Syscall and protocol evidence

Use `strace`/`ltrace` or a controlled capture to confirm file, process, socket, and library behavior. For vehicle protocols, correlate code constants and branches with saved CAN/ASC/PCAP timestamps, IDs, directions, sessions, UDS SIDs/subfunctions, NRCs, and state transitions.

## 5. Promote or rule out

Use this minimum evidence ladder:

| State | Required support |
| --- | --- |
| Observation | Direct tool output, address, hash, log, or capture |
| Hypothesis | Observation plus a testable data/control-flow explanation |
| Validated behavior | Static call/data flow plus debugger, syscall, or capture correlation |
| Confirmed finding | Reproducible input, reachable behavior, impact, preconditions, and preserved evidence |
| Ruled out | All relevant call sites or paths checked, with counterevidence and scope recorded |

Example: an imported `system` symbol is an observation. A network parser calling it is a hypothesis after xref analysis. A controlled trace showing an input-derived argument at the call site validates reachability. A minimized fixture that produces a bounded unintended command with recorded preconditions supports a finding.

## 6. Report a useful conclusion

Write each conclusion as:

```text
[Status/confidence] COMPONENT accepts INPUT through PATH and reaches/does not reach BEHAVIOR under CONDITIONS. Evidence: E-..., address/function, tool trace or capture. Boundary: UNTESTED AREA.
```

Include ruled-out hypotheses and remaining unknowns. This prevents future analysis from repeating dead ends or overstating static indicators.
