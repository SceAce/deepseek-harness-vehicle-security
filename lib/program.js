import { triageArtifact } from './artifact.js';
import { findExecutable } from './paths.js';
import { runCommand } from './process.js';
const EXECUTION_IMPORTS = new Set(['system', 'popen', 'execl', 'execle', 'execlp', 'execv', 'execve', 'execvp']);
const MEMORY_IMPORTS = new Set(['gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf', 'scanf', 'sscanf']);
const NETWORK_IMPORTS = new Set(['socket', 'connect', 'bind', 'listen', 'accept', 'recv', 'recvfrom', 'send', 'sendto']);
export async function analyzeProgram(file, options = {}) {
    const maxStrings = normalizeInteger(options.maxStrings, 80, 1, 500, 'maxStrings');
    const minStringLength = normalizeInteger(options.minStringLength, 6, 4, 64, 'minStringLength');
    const artifact = await triageArtifact(file, { ...options, enableBinwalk: false });
    const format = detectFormat(artifact.fileType);
    const limitations = [];
    const observations = [
        {
            id: 'E-001',
            category: 'identity',
            statement: `Analyzed ${artifact.path} as an immutable input artifact.`,
            source: 'SHA-256 and file metadata',
            details: [`sha256=${artifact.sha256}`, `sizeBytes=${artifact.sizeBytes}`, `fileType=${artifact.fileType ?? 'unavailable'}`],
        },
    ];
    let elf = null;
    let imports = [];
    if (format === 'elf') {
        const readelf = await findExecutable('readelf');
        if (readelf) {
            const [header, programHeaders, dynamic, symbols] = await Promise.all([
                runCommand(readelf, ['-hW', '--', file.path], options),
                runCommand(readelf, ['-lW', '--', file.path], options),
                runCommand(readelf, ['-dW', '--', file.path], options),
                runCommand(readelf, ['-sW', '--', file.path], options),
            ]);
            elf = parseElfMetadata(header.ok ? header.stdout : '', programHeaders.ok ? programHeaders.stdout : '', dynamic.ok ? dynamic.stdout : '', symbols.ok ? symbols.stdout : '', artifact.fileType);
            imports = symbols.ok ? parseUndefinedSymbols(symbols.stdout) : [];
            observations.push(...elfObservations(elf, imports));
            for (const [label, capture] of Object.entries({ header, programHeaders, dynamic, symbols })) {
                if (!capture.ok)
                    limitations.push(`readelf ${label} exited with ${capture.exitCode ?? 'no status'}: ${capture.error ?? capture.stderr.trim()}`);
                if (capture.stdout.includes('...[truncated') || capture.stderr.includes('...[truncated')) {
                    limitations.push(`readelf ${label} output was truncated; derived lists or negative checks may be incomplete.`);
                }
            }
        }
        else {
            limitations.push('readelf is not installed; ELF metadata, imports, and hardening checks were skipped.');
        }
    }
    else {
        limitations.push(`Detailed parser for ${format} programs is not implemented yet; generic metadata and strings remain available.`);
    }
    let interestingStrings = [];
    const strings = await findExecutable('strings');
    if (strings) {
        const capture = await runCommand(strings, ['-a', '-t', 'x', '-n', String(minStringLength), '--', file.path], {
            ...options,
            maxOutputChars: Math.max(options.maxOutputChars ?? 40_000, 120_000),
        });
        interestingStrings = classifyStrings(capture.stdout, maxStrings);
        if (interestingStrings.length > 0) {
            observations.push({
                id: nextId(observations, 'E'),
                category: 'string',
                statement: `Found ${interestingStrings.length} strings with protocol, credential, execution, network, or device relevance.`,
                source: `strings -a -t x -n ${minStringLength}`,
                details: interestingStrings.slice(0, 20).map(item => `${item.offset}: [${item.tags.join(', ')}] ${item.value}`),
            });
        }
        if (!capture.ok)
            limitations.push(`strings exited with ${capture.exitCode ?? 'no status'}: ${capture.error ?? capture.stderr.trim()}`);
        if (capture.stdout.includes('...[truncated') || capture.stderr.includes('...[truncated')) {
            limitations.push('strings output was truncated; tagged indicators cover only the captured prefix.');
        }
    }
    else {
        limitations.push('strings is not installed; embedded text indicators were skipped.');
    }
    const { hypotheses, validationSteps } = buildValidationPlan(file.relativePath, imports, interestingStrings, observations);
    const conclusions = buildConclusions(format, elf, imports, interestingStrings, observations);
    limitations.push('Static indicators show reachability candidates, not runtime data flow or exploitability; promote a lead only after a validation step succeeds.');
    return {
        objective: options.focus?.trim() || 'general program behavior and attack-surface triage',
        artifact,
        format,
        elf,
        imports,
        interestingStrings,
        observations,
        conclusions,
        hypotheses,
        validationSteps,
        limitations,
    };
}
export function parseElfMetadata(header, programHeaders, dynamic, symbols, fileType) {
    const type = headerValue(header, 'Type');
    const stackLine = programHeaders.split(/\r?\n/).find(line => line.includes('GNU_STACK'));
    const stackFlags = stackLine?.trim().split(/\s+/).at(-2);
    const hasRelro = programHeaders.includes('GNU_RELRO');
    const bindNow = /\bBIND_NOW\b|Flags:\s+.*\bNOW\b/.test(dynamic);
    const hasInterpreter = programHeaders.includes('INTERP');
    const hasHeaderEvidence = header.trim().length > 0;
    const hasProgramHeaderEvidence = programHeaders.trim().length > 0;
    const hasDynamicEvidence = dynamic.trim().length > 0;
    const hasSymbolEvidence = symbols.trim().length > 0;
    const symbolsTruncated = symbols.includes('...[truncated');
    return {
        class: headerValue(header, 'Class'),
        data: headerValue(header, 'Data'),
        type,
        machine: headerValue(header, 'Machine'),
        entryPoint: headerValue(header, 'Entry point address'),
        interpreter: hasProgramHeaderEvidence ? hasInterpreter : null,
        protections: {
            pie: !hasHeaderEvidence ? 'unknown' : type?.startsWith('DYN') && hasInterpreter ? 'enabled' : type?.startsWith('EXEC') ? 'disabled' : 'unknown',
            nx: stackFlags ? (stackFlags.includes('E') ? 'disabled' : 'enabled') : 'unknown',
            relro: !hasProgramHeaderEvidence ? 'unknown' : hasRelro ? (!hasDynamicEvidence ? 'unknown' : bindNow ? 'full' : 'partial') : 'disabled',
            stackCanary: symbols.includes('__stack_chk_fail') ? 'enabled' : !hasSymbolEvidence || symbolsTruncated ? 'unknown' : 'disabled',
            stripped: fileType === null ? 'unknown' : /\bnot stripped\b/i.test(fileType) ? 'disabled' : /\bstripped\b/i.test(fileType) ? 'enabled' : 'unknown',
        },
    };
}
export function parseUndefinedSymbols(symbols) {
    const result = new Set();
    for (const line of symbols.split(/\r?\n/)) {
        const match = line.match(/\bUND\s+(\S+)/);
        if (!match)
            continue;
        const name = match[1].replace(/@.*$/, '');
        if (name)
            result.add(name);
    }
    return [...result].sort();
}
export function classifyStrings(output, maxStrings = 80) {
    const result = [];
    const seen = new Set();
    for (const line of output.split(/\r?\n/)) {
        const match = line.match(/^\s*([0-9A-Fa-f]+)\s+(.+)$/);
        if (!match)
            continue;
        const value = match[2].trim();
        const tags = stringTags(value);
        if (tags.length === 0 || seen.has(value))
            continue;
        seen.add(value);
        result.push({ offset: `0x${match[1].toUpperCase()}`, value, tags });
        if (result.length >= maxStrings)
            break;
    }
    return result;
}
function detectFormat(fileType) {
    if (!fileType)
        return 'unknown';
    if (/\bELF\b/i.test(fileType))
        return 'elf';
    if (/\bPE32\+?\b|MS-DOS executable/i.test(fileType))
        return 'pe';
    if (/\bMach-O\b/i.test(fileType))
        return 'macho';
    if (/script|text executable/i.test(fileType))
        return 'script';
    return 'unknown';
}
function elfObservations(elf, imports) {
    return [
        {
            id: 'E-002',
            category: 'platform',
            statement: `ELF platform is ${elf.class ?? 'unknown'} / ${elf.machine ?? 'unknown'} with entry point ${elf.entryPoint ?? 'unknown'}.`,
            source: 'readelf -hW',
            details: [`type=${elf.type ?? 'unknown'}`, `data=${elf.data ?? 'unknown'}`, `interpreter=${elf.interpreter}`],
        },
        {
            id: 'E-003',
            category: 'protection',
            statement: 'Recorded ELF hardening properties without treating their absence as a vulnerability.',
            source: 'readelf -hW/-lW/-dW/-sW and file',
            details: Object.entries(elf.protections).map(([name, state]) => `${name}=${state}`),
        },
        {
            id: 'E-004',
            category: 'import',
            statement: `Recovered ${imports.length} undefined symbols as candidate external call surfaces.`,
            source: 'readelf -sW',
            details: imports.slice(0, 60),
        },
    ];
}
function buildConclusions(format, elf, imports, strings, observations) {
    const conclusions = [{
            id: 'C-001',
            statement: `The artifact format is ${format}; its identity is anchored by SHA-256 and size.`,
            confidence: 'high',
            evidenceIds: ['E-001'],
            boundary: 'File identity and format only; this does not establish behavior.',
        }];
    if (elf) {
        conclusions.push({
            id: 'C-002',
            statement: `ELF hardening state: PIE ${elf.protections.pie}, NX ${elf.protections.nx}, RELRO ${elf.protections.relro}, stack canary ${elf.protections.stackCanary}, stripped ${elf.protections.stripped}.`,
            confidence: 'high',
            evidenceIds: ['E-002', 'E-003'],
            boundary: 'Hardening changes exploitation conditions; it neither proves nor rules out a defect.',
        });
    }
    const stringEvidence = observations.find(item => item.category === 'string')?.id;
    const importEvidence = observations.find(item => item.category === 'import')?.id;
    if (imports.length > 0 || strings.length > 0) {
        conclusions.push({
            id: `C-${String(conclusions.length + 1).padStart(3, '0')}`,
            statement: `Static imports and tagged strings expose ${imports.length} call-surface symbols and ${strings.length} investigation indicators for cross-reference analysis.`,
            confidence: 'medium',
            evidenceIds: [...(importEvidence ? [importEvidence] : []), ...(stringEvidence ? [stringEvidence] : [])],
            boundary: 'Names and strings are leads until a reachable call site and controlling input are demonstrated.',
        });
    }
    return conclusions;
}
export function buildValidationPlan(relativePath, imports, strings, observations) {
    const hypotheses = [];
    const validationSteps = [];
    const importEvidence = observations.find(item => item.category === 'import')?.id ?? 'E-004';
    const stringEvidence = observations.find(item => item.category === 'string')?.id;
    const lowerImports = new Map(imports.map(name => [name.toLowerCase(), name]));
    const matches = (set) => [...set].filter(name => lowerImports.has(name)).map(name => lowerImports.get(name));
    const execution = matches(EXECUTION_IMPORTS);
    const memory = matches(MEMORY_IMPORTS);
    const network = matches(NETWORK_IMPORTS);
    const credentialStrings = strings.filter(item => item.tags.includes('credential'));
    const vehicleStrings = strings.filter(item => item.tags.includes('vehicle'));
    function addHypothesis(title, rationale, evidenceIds, tool, actions, successCriteria) {
        const hypothesisId = `H-${String(hypotheses.length + 1).padStart(3, '0')}`;
        const stepId = `V-${String(validationSteps.length + 1).padStart(3, '0')}`;
        hypotheses.push({
            id: hypothesisId,
            title,
            rationale,
            confidence: 'low',
            evidenceIds,
            validationStepIds: [stepId],
        });
        validationSteps.push({
            id: stepId,
            hypothesisIds: [hypothesisId],
            tool,
            purpose: `Test ${hypothesisId} and either promote it with evidence or record it as ruled out.`,
            commands: [],
            actions,
            successCriteria,
            evidenceToRecord: ['function/address', 'input origin', 'call path', 'tool output or debugger trace', 'counterexample or stop condition'],
        });
    }
    if (execution.length > 0)
        addHypothesis('An externally influenced value may reach a process-execution sink.', `Imported execution functions: ${execution.join(', ')}. Import presence alone does not show a controllable call path.`, [importEvidence], 'IDA Pro MCP or radare2', [`Locate every cross-reference to ${execution.join(', ')}.`, 'Trace each argument backward to configuration, IPC, network, CAN/UDS, file, or constant sources.', 'Inspect quoting, allowlists, and direct exec argument construction.'], ['A reproducible path from a defined input to the sink is present, or every call site is shown to use constants/validated values.']);
    if (memory.length > 0)
        addHypothesis('A parser path may use a length-sensitive memory operation.', `Imported memory/string functions: ${memory.join(', ')}. Their use may be bounded and correct.`, [importEvidence], 'IDA Pro MCP plus GDB/Pwndbg', [`Find cross-references to ${memory.join(', ')} and identify source/destination bounds.`, 'Set breakpoints on the relevant call sites and replay a recorded local input fixture.', 'Record lengths, destination capacity, return path, and any crash/sanitizer evidence.'], ['A call-site proof establishes safe bounds, or a minimized local input demonstrates an out-of-bounds condition.']);
    if (network.length > 0)
        addHypothesis('The program exposes or consumes a network-facing message path.', `Imported network functions: ${network.join(', ')}.`, [importEvidence], 'IDA Pro MCP, radare2, and strace', [`Map cross-references to ${network.join(', ')} into listener/client initialization and message handlers.`, 'Run with a recorded test configuration and trace network syscalls in an isolated environment.', 'Correlate endpoint, framing, authentication, and parser functions.'], ['Static xrefs and a syscall trace agree on endpoint role and the first parser function.']);
    if (credentialStrings.length > 0 && stringEvidence)
        addHypothesis('Credential-like text may identify embedded defaults, field names, or authentication logic.', `Tagged strings include ${credentialStrings.slice(0, 5).map(item => `${item.offset}:${item.value}`).join(', ')}.`, [stringEvidence], 'IDA Pro MCP or radare2', ['Resolve cross-references for each credential-tagged string.', 'Classify each use as UI text, field name, test data, format string, or secret material.', 'Inspect the surrounding authentication/configuration data flow.'], ['Each indicator is classified by xref and context; secret material requires byte-level evidence rather than keyword matching.']);
    if (vehicleStrings.length > 0 && stringEvidence)
        addHypothesis('The program likely implements a vehicle bus or diagnostic protocol path.', `Vehicle-tagged strings include ${vehicleStrings.slice(0, 5).map(item => `${item.offset}:${item.value}`).join(', ')}.`, [stringEvidence], 'IDA Pro MCP, radare2, and capture correlation', ['Resolve xrefs to interface names, UDS services, CAN IDs, DoIP, SOME/IP, or MQTT topics.', 'Map initialization, receive, dispatch, authorization, and transmit functions.', 'Compare constants and branches with a saved CAN/ASC/PCAP trace.'], ['Code constants, dispatch logic, and recorded traffic agree on the protocol role and message direction.']);
    const allHypotheses = hypotheses.map(item => item.id);
    validationSteps.unshift({
        id: 'V-000',
        hypothesisIds: allHypotheses,
        tool: 'radare2',
        purpose: 'Create a reproducible static baseline before targeted decompilation or debugging.',
        commands: [{ program: 'r2', args: ['-A', '-q', '-c', 'iI;ie;afl;iij;izzq', relativePath] }],
        actions: ['Save the output as evidence.', 'Record tool version and artifact SHA-256.', 'Use addresses from this baseline in subsequent xref and debugger steps.'],
        successCriteria: ['Architecture, entry point, functions, imports, and strings are mapped to stable addresses.'],
        evidenceToRecord: ['r2 version', 'exact argument array', 'raw output path', 'artifact SHA-256'],
    });
    return { hypotheses, validationSteps };
}
function headerValue(output, label) {
    const line = output.split(/\r?\n/).find(candidate => candidate.trimStart().startsWith(`${label}:`));
    return line?.slice(line.indexOf(':') + 1).trim() || null;
}
function stringTags(value) {
    const tags = [];
    if (/(?:https?:\/\/|mqtt|socket|connect|listen|bind\(|tls|ssl|websocket)/i.test(value))
        tags.push('network');
    if (/(?:password|passwd|username|user_name|token|secret|api[_-]?key|credential|authorization)/i.test(value))
        tags.push('credential');
    if (/(?:\/bin\/(?:sh|bash)|(?:^|\W)(?:system|popen|execv|execve|execl|execlp)\s*\()/i.test(value))
        tags.push('execution');
    if (/(?:\bcan\d+\b|vcan|socketcan|isotp|iso-tp|\buds\b|doip|some\/?ip|obd|0x7e[0-9a-f])/i.test(value))
        tags.push('vehicle');
    if (/(?:\/dev\/(?:tty|can|i2c|spi)|\/sys\/class|\/proc\/|\/etc\/)/i.test(value))
        tags.push('device-or-config');
    if (/(?:assert|fatal|panic|debug|trace|error:|failed to)/i.test(value))
        tags.push('diagnostic');
    return tags;
}
function normalizeInteger(value, fallback, min, max, name) {
    if (value === undefined)
        return fallback;
    if (!Number.isInteger(value) || value < min || value > max)
        throw new Error(`${name} must be an integer between ${min} and ${max}`);
    return value;
}
function nextId(items, prefix) {
    return `${prefix}-${String(items.length + 1).padStart(3, '0')}`;
}
//# sourceMappingURL=program.js.map