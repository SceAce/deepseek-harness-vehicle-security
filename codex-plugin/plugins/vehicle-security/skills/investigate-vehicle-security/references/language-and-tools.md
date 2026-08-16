# Language and Tool Selection

## TypeScript

Use for DeepSeek Harness tools, Codex MCP servers, schemas, structured outputs, case orchestration, reusable parsers, and cross-platform automation. Keep long-lived plugin logic here so DSH and Codex share one implementation.

## Python

Use for rapid protocol and crypto experiments, Scapy, python-can, cantools, construct, IDAPython, angr, Unicorn/Qiling, Frida scripts, data science, and minimal reproducible validators. Promote stable generic parsers into typed TypeScript modules after their format is understood.

## Shell

Use for short, visible calls to `file`, `sha256sum`, `rg`, `readelf`, `objdump`, `r2`, `tshark`, or test runners. Avoid complex binary parsing, state machines, large pipelines, and quoting-sensitive payload generation.

## C/C++ or Rust

Use for native fuzz harnesses, ABI-accurate shims, target-side hooks, high-throughput parsers, and embedded reproductions. Delay this cost until the parser or function boundary and success signal are known.

## Selection Rule

Choose the smallest language that produces a rerunnable artifact and machine-readable result. A disposable interactive command is acceptable for discovery; any result used to support a conclusion must be saved as a command, script, test fixture, debugger trace, or MCP output.

Prefer tools in this order:

1. Existing plugin helper that emits structured evidence.
2. Format-native CLI with fixed arguments and saved output.
3. Small Python validator for an uncertain format or algorithm.
4. IDA/r2/debugger/Frida for a named hypothesis.
5. Native harness, emulator, or fuzzer after the boundary is established.
