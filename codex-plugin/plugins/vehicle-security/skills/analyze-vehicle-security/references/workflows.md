# Vehicle-security workflows

## CAN and UDS

Start with `can-summary` to identify active IDs, channels, and time ranges. Filter likely diagnostic request/response pairs such as `0x7E0` and `0x7E8`, then decode extracted payloads with `uds-decode`. Treat byte-level results as observations; infer sessions only when the log contains enough temporal context.

## Firmware and binary artifacts

Run `artifact-triage` before disassembly. Record the SHA-256, size, file type, and entropy. Keep a copy of the original and use IDA Pro, GDB/Pwndbg, or other installed tools on a derived working copy. The helper's Binwalk mode is a signature scan and does not extract or execute content.

## Android and gateway applications

Use `audit` to locate `adb`, JADX, and Frida. Preserve APKs and pulled files, hash them, and document package, version, and architecture before static or dynamic inspection. Device-dependent actions remain explicit operator steps; this plugin only inventories the tools.

## Hardware-dependent work

For CAN interfaces, RF captures, logic analyzers, or Proxmark/HackRF devices, capture to a file first and analyze the saved artifact. Record interface, channel, bitrate, clock, and capture start time. Do not add live transmit commands to an automated report.
