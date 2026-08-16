import { createHash } from 'node:crypto';
import path from 'node:path';
import { triageArtifact } from './artifact.js';
const LANES = [
    'can-uds',
    'network-protocol',
    'firmware',
    'native-program',
    'android',
    'web-api',
    'hardware-rf',
];
const KEYWORDS = {
    'can-uds': /\bcan(?:\s*fd)?\b|candump|\.asc\b|uds|iso-?tp|dbc|lin\b|flexray|诊断|总线|报文/i,
    'network-protocol': /pcap|doip|some\/?ip|mqtt|ethernet|tcp|udp|wireshark|tshark|流量|网络协议/i,
    firmware: /firmware|固件|flash|ota|bootloader|升级包|文件系统|squashfs|ubifs|binwalk/i,
    'native-program': /\belf\b|executable|shared object|\.so\b|native|binary|implementation|handler|dispatcher|xref|decomp|逆向|反编译|程序|函数/i,
    android: /android|\.apk\b|\.aab\b|\.dex\b|jadx|车机应用|移动应用|jni/i,
    'web-api': /https?:\/\/|\bapi\b|web|cloud|t-?box|telematics|云端|接口/i,
    'hardware-rf': /\bble\b|bluetooth|wifi|nfc|sdr|hackrf|proxmark|logic analyzer|串口|射频|硬件/i,
};
export async function planInvestigation(input, file = null, options = {}) {
    const objective = input.objective.trim();
    if (!objective)
        throw new Error('objective must be a non-empty string');
    const context = input.context?.trim() ?? '';
    const inputKind = input.inputKind ?? (file ? 'artifact' : 'prompt');
    const artifact = file
        ? await triageArtifact(file, { ...options, enableBinwalk: options.enableBinwalk ?? false })
        : null;
    const candidates = rankLanes(`${objective}\n${context}`, file, artifact);
    const selectedLane = candidates[0]?.score ? candidates[0].lane : 'unknown';
    const identity = artifact?.sha256 ?? createHash('sha256').update(`${inputKind}\n${objective}\n${context}`).digest('hex');
    return {
        schemaVersion: '1.0',
        caseId: `vehicle-${identity.slice(0, 12)}`,
        objective,
        inputKind,
        artifact,
        selectedLane,
        laneCandidates: candidates,
        phases: investigationPhases(),
        firstActions: actionsForLane(selectedLane),
        languagePlan: languagesForLane(selectedLane),
        dataPlan: {
            directories: ['raw/', 'working/', 'evidence/', 'scripts/', 'reports/'],
            stateFile: 'case.json',
            namingRule: '<evidence-id>_<utc-time>_<tool>_<short-description>.<ext>',
            preservationRule: 'Keep raw inputs immutable; place extracted, patched, decoded, or replay-ready data under working/.',
        },
        evidenceModel: {
            prefixes: {
                'E-*': 'direct observation with source, timestamp, command or tool, and artifact identity',
                'C-*': 'bounded conclusion supported by evidence IDs',
                'H-*': 'ranked hypothesis that is still open',
                'V-*': 'one validation action with success and failure criteria',
                'F-*': 'confirmed finding with impact and reproduction evidence',
            },
            promotionRule: 'Promote H-* to C-* or F-* only after its V-* success criteria are reproduced; record counterevidence on failure.',
        },
        stopConditions: [
            'The objective is answered by reproducible evidence and remaining uncertainty is explicit.',
            'The next action needs unavailable hardware, credentials, keys, traffic, symbols, or a runtime environment.',
            'Two independent validation paths contradict each other; preserve both and reassess the hypothesis.',
            'An action would alter the only copy of an artifact or exceed the case constraints.',
        ],
        limitations: [
            'Lane ranking is a routing aid, not a security conclusion.',
            'A prompt-only intake requires evidence collection before any hypothesis can be promoted.',
            'Tool output must be linked to the exact artifact hash, capture, process, or target state it describes.',
        ],
    };
}
function rankLanes(text, file, artifact) {
    const scores = new Map();
    for (const lane of LANES)
        scores.set(lane, { lane, score: 0, reasons: [] });
    const add = (lane, score, reason) => {
        const item = scores.get(lane);
        if (!item)
            return;
        item.score += score;
        item.reasons.push(reason);
    };
    for (const [lane, regex] of Object.entries(KEYWORDS)) {
        if (regex.test(text))
            add(lane, 3, 'objective or context contains lane-specific terms');
    }
    if (/(locate|find|trace|recover|implementation|handler|dispatcher|定位|追踪|实现)/i.test(text)) {
        if (KEYWORDS.firmware.test(text))
            add('firmware', 4, 'objective asks to locate implementation inside firmware');
        else
            add('native-program', 2, 'objective asks for implementation-level tracing');
    }
    if (/(decode|reconstruct|timeline|traffic|capture|frame|signal|解码|重组|时序|流量|报文|信号)/i.test(text)) {
        if (KEYWORDS['can-uds'].test(text))
            add('can-uds', 3, 'objective asks for protocol or traffic reconstruction');
        else
            add('network-protocol', 2, 'objective asks for protocol or traffic reconstruction');
    }
    if (file) {
        const extension = path.extname(file.relativePath).toLowerCase();
        if (['.asc', '.blf', '.dbc'].includes(extension) || /candump|can.*log/i.test(file.relativePath))
            add('can-uds', 8, `artifact extension or name ${extension || file.relativePath}`);
        if (['.pcap', '.pcapng'].includes(extension))
            add('network-protocol', 8, `capture extension ${extension}`);
        if (['.apk', '.aab', '.dex'].includes(extension))
            add('android', 8, `Android extension ${extension}`);
        if (['.elf', '.so', '.exe', '.dll'].includes(extension))
            add('native-program', 8, `program extension ${extension}`);
        if (['.bin', '.img', '.fw', '.hex', '.srec', '.s19', '.ubi', '.squashfs'].includes(extension))
            add('firmware', 7, `firmware-like extension ${extension}`);
    }
    const fileType = artifact?.fileType ?? '';
    if (/ELF|PE32|Mach-O/i.test(fileType))
        add('native-program', 10, `file identified as ${fileType}`);
    if (/Android package|Dalvik/i.test(fileType))
        add('android', 10, `file identified as ${fileType}`);
    if (/pcap|capture file/i.test(fileType))
        add('network-protocol', 10, `file identified as ${fileType}`);
    if (/filesystem|firmware|boot sector|u-boot|squashfs|ubifs/i.test(fileType))
        add('firmware', 8, `file identified as ${fileType}`);
    return [...scores.values()]
        .filter(item => item.score > 0)
        .sort((left, right) => right.score - left.score || left.lane.localeCompare(right.lane));
}
function investigationPhases() {
    return [
        { id: 'P0', name: 'intake', exitCriteria: ['objective and constraints recorded', 'inputs inventoried', 'raw artifacts hashed or evidence gap recorded'] },
        { id: 'P1', name: 'rapid-map', exitCriteria: ['artifact or target type identified', 'attack surfaces ranked', 'one primary lane selected'] },
        { id: 'P2', name: 'hypothesis', exitCriteria: ['top hypotheses have evidence links', 'each hypothesis has one discriminating validation action'] },
        { id: 'P3', name: 'validation', exitCriteria: ['success or failure criteria observed', 'counterevidence retained', 'runtime state recorded where relevant'] },
        { id: 'P4', name: 'conclusion', exitCriteria: ['findings are reproducible', 'boundaries and remaining unknowns stated', 'next operations prioritized'] },
    ];
}
function actionsForLane(lane) {
    const action = (id, phase, tool, purpose, expectedSignal, nextIfPositive, nextIfNegative) => ({ id, phase, tool, purpose, expectedSignal, nextIfPositive, nextIfNegative });
    switch (lane) {
        case 'can-uds':
            return [
                action('V-001', 'P1', 'vehicle_can_log_summary', 'Measure parse coverage and rank IDs before decoding individual frames.', 'Stable format, time range, channels, and high-value IDs.', 'Filter event or diagnostic IDs and reconstruct request/response sequences.', 'Check bitrate, log format, timestamps, CAN FD flags, or convert the capture.'),
                action('V-002', 'P2', 'vehicle_uds_decode', 'Decode candidate diagnostic payloads after ISO-TP framing is understood.', 'UDS service, subfunction, DID, routine, or NRC with direction.', 'Build a session timeline and correlate state transitions.', 'Reassemble multi-frame ISO-TP or test a non-UDS protocol hypothesis.'),
                action('V-003', 'P3', 'Python: python-can/cantools or a small parser', 'Validate counters, checksums, timing, signal candidates, and replay-independent transformations.', 'A script reproduces the observed field or transition on saved data.', 'Link the transformation to code or create a minimal saved-capture test.', 'Record the failed model and rank the next field hypothesis.'),
            ];
        case 'network-protocol':
            return [
                action('V-001', 'P1', 'tshark/Wireshark', 'Inventory conversations and identify DoIP, SOME/IP, MQTT, HTTP, TLS, or unknown framing.', 'Endpoints, ports, sessions, protocol hierarchy, and extraction candidates.', 'Export the narrow stream and map request/response semantics.', 'Inspect entropy, framing, timing, and relevant program strings.'),
                action('V-002', 'P2', 'Python: Scapy or construct', 'Turn the candidate frame format into a repeatable decoder.', 'Saved packets decode into stable fields with length and boundary checks.', 'Add benign malformed fixtures and compare parser behavior.', 'Revise byte order, offsets, compression, or encryption hypothesis.'),
            ];
        case 'firmware':
            return [
                action('V-001', 'P1', 'vehicle_artifact_triage', 'Anchor identity and detect container, compression, or filesystem signatures.', 'Hash, size, file type, entropy, and optional Binwalk signatures.', 'Extract only into working/ and inventory the resulting tree.', 'Inspect headers, update metadata, and compare known image layouts.'),
                action('V-002', 'P2', 'binwalk/file/rg', 'Locate init, services, credentials, update verification, protocol handlers, and architecture-specific programs.', 'Ranked files with paths and evidence IDs.', 'Run vehicle_program_analyze on the highest-value executables.', 'Check encrypted/compressed regions and obtain a matching updater or loader.'),
                action('V-003', 'P3', 'IDA Pro MCP or radare2', 'Trace the selected trust boundary through parsing, checks, state changes, and sinks.', 'Named functions, addresses, callers, inputs, and a reproducible path.', 'Validate with an emulator, debugger, or saved input.', 'Record the ruled-out path and inspect the next ranked handler.'),
            ];
        case 'native-program':
            return [
                action('V-001', 'P1', 'vehicle_program_analyze', 'Collect identity, architecture, protections, imports, strings, and testable hypotheses.', 'E/C/H/V records tied to one artifact hash.', 'Choose the highest-value validation step, not the noisiest indicator.', 'Install or select one primary disassembler and repeat collection.'),
                action('V-002', 'P2', 'IDA Pro MCP or radare2', 'Resolve string/import references, callers, dispatch tables, and data flow.', 'A reachable input-to-check-or-sink path with addresses and pseudocode.', 'Rename evidence-backed functions and define a runtime observation point.', 'Search protocol constants, state values, error paths, and callers.'),
                action('V-003', 'P3', 'GDB/Pwndbg, trace, or emulator', 'Test the static hypothesis on a working copy with a saved input.', 'Breakpoint, buffer, branch, syscall, output, or crash matches the success criteria.', 'Promote the hypothesis and save the minimal reproducer.', 'Capture counterevidence and revise the data-flow model.'),
            ];
        case 'android':
            return [
                action('V-001', 'P1', 'jadx/apktool/aapt', 'Map manifest, exported components, permissions, deep links, storage, network config, and JNI.', 'Ranked Java/Kotlin and native entry points.', 'Trace the top component or vehicle-control call chain.', 'Check split APKs, packing, dynamic loading, and native libraries.'),
                action('V-002', 'P3', 'Frida/ADB on a test device', 'Observe the selected method, IPC, crypto, or native boundary.', 'Arguments, return values, call order, and device/app version recorded.', 'Reproduce with a minimal controlled input.', 'Adjust hook timing, overload, process, architecture, or anti-tamper assumptions.'),
            ];
        case 'web-api':
            return [
                action('V-001', 'P1', 'curl/browser/tshark', 'Map hosts, routes, authentication, roles, request schemas, and state transitions.', 'A reproducible baseline request and response with sanitized evidence.', 'Select one trust or authorization hypothesis.', 'Collect client code, API descriptions, logs, or a representative capture.'),
                action('V-002', 'P3', 'small Python or TypeScript client', 'Replay one bounded request variation and compare server behavior.', 'A deterministic response difference tied to one input change.', 'Promote or refine the finding with exact preconditions.', 'Record the negative result and test the next discriminating condition.'),
            ];
        case 'hardware-rf':
            return [
                action('V-001', 'P0', 'capture tool for the available interface', 'Record an immutable offline capture with channel, bitrate, clock, hardware, and start time.', 'Saved capture plus acquisition metadata and hash.', 'Analyze the saved artifact through CAN or network lanes.', 'Correct physical layer, channel, bitrate, trigger, or hardware setup.'),
            ];
        default:
            return [
                action('V-001', 'P0', 'vehicle_tool_audit and focused intake', 'Identify the input type, available evidence, and cheapest discriminating observation.', 'One primary lane and a concrete evidence source.', 'Run the selected lane first action.', 'Request or collect the smallest missing artifact, capture, response, or program.'),
            ];
    }
}
function languagesForLane(lane) {
    const result = [
        { language: 'TypeScript', useFor: 'DeepSeek Harness tools, Codex MCP, schemas, case orchestration, and reusable cross-platform parsers.', avoidFor: 'One-off debugger automation where the target tool already embeds Python.' },
        { language: 'Python', useFor: 'Fast protocol experiments, IDAPython, Scapy/python-can/cantools, crypto checks, emulation, and small reproducible validators.', avoidFor: 'Duplicating stable TypeScript plugin logic or untyped long-lived orchestration.' },
        { language: 'Shell', useFor: 'Short, visible invocations of existing tools and evidence capture.', avoidFor: 'Binary parsing, complex state, quoting-sensitive payload construction, or long pipelines.' },
    ];
    if (lane === 'native-program' || lane === 'firmware') {
        result.push({ language: 'C/C++ or Rust', useFor: 'Native fuzz harnesses, high-throughput parsers, ABI-accurate shims, and target-side instrumentation.', avoidFor: 'Initial triage and disposable analysis glue.' });
    }
    return result;
}
//# sourceMappingURL=investigation.js.map