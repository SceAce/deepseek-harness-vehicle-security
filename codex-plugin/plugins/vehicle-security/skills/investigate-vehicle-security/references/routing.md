# Intake and Lane Routing

## Artifact or Directory

- CAN candump, ASC, BLF, DBC: select `can-uds`; measure parse coverage, rank IDs, reconstruct ISO-TP, then decode UDS or infer signals.
- PCAP/PCAPNG: select `network-protocol`; inventory conversations and protocol hierarchy before exporting a narrow stream.
- BIN/IMG/FW/HEX/SREC or update package: select `firmware`; hash, identify container/filesystem/compression, extract to `working/`, then correlate services, configuration, programs, and update logic.
- ELF/PE/Mach-O/SO/DLL: select `native-program`; collect identity, platform, protections, imports, strings, and program hypotheses before opening a decompiler.
- APK/AAB/DEX: select `android`; map manifest, exported components, permissions, deep links, storage, networking, JNI, and native libraries.
- Mixed directory: inventory file types and names, group by role, and rank candidates. Avoid running every tool on every file.

## Short Prompt

Extract nouns, verbs, interfaces, observed errors, identifiers, time/state conditions, and the user's desired decision. Select a lane only when the wording provides a distinguishing clue. Otherwise return `unknown` and collect the smallest useful artifact:

- protocol question: capture or representative request/response;
- firmware question: exact image and updater/manifest when available;
- program question: binary, architecture, runtime invocation, and sample input;
- vehicle-state question: before/after captures with synchronized event notes;
- API/lab question: endpoint, baseline request/response, roles, and observable behavior.

## Lab Target

Start with the exposed interface and a reproducible baseline. Record address, service/version, account or role, expected state, rate/stop constraints, and saved responses. Route web/API, network protocol, program, Android, or hardware evidence into the same case rather than creating disconnected analyses.

## Cross-Lane Pivots

- UDS `0x27` or proprietary challenge/response -> locate the handler and algorithm in firmware/program.
- Unknown CAN fields -> correlate controlled events, DBC candidates, and code constants.
- DoIP/SOME-IP method -> trace service IDs and deserializers into native programs.
- Android vehicle-control call -> trace API/IPC/JNI and then gateway/ECU protocol.
- Firmware service/configuration -> reproduce through a saved protocol or API input.

Pivot only when the current lane produces an address, identifier, endpoint, file, function, state transition, or specific evidence gap.
