# Vehicle-security workflows

## CAN and UDS

Start with `can-summary` to identify active IDs, channels, and time ranges. Filter likely diagnostic request/response pairs such as `0x7E0` and `0x7E8`, then decode extracted payloads with `uds-decode`. Treat byte-level results as observations; infer sessions only when the log contains enough temporal context.

## Firmware and binary artifacts

Run `artifact-triage` before extraction and `program-analyze` on identified executables. Record the SHA-256, size, file type, entropy, evidence IDs, hypotheses, and validation steps. Keep a copy of the original and use IDA Pro, radare2, GDB/Pwndbg, or other installed tools on a derived working copy. Correlate firmware services, init scripts, configuration, protocol handlers, and update logic rather than analyzing each binary in isolation. The helper's Binwalk mode is a signature scan and does not extract or execute content.

## Android and gateway applications

Use `audit` to locate `adb`, JADX, and Frida. Preserve APKs and pulled files, hash them, and document package, version, and architecture before static or dynamic inspection. Device-dependent actions remain explicit operator steps; this plugin only inventories the tools.

## Hardware-dependent work

For CAN interfaces, RF captures, logic analyzers, or Proxmark/HackRF devices, capture to a file first and analyze the saved artifact. Record interface, channel, bitrate, clock, and capture start time. Do not add live transmit commands to an automated report.
