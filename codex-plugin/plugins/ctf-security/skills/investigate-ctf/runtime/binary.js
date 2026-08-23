import { profileCtfArtifact } from './artifact.js';
import { findCtfExecutable } from './environment.js';
import { runCommand } from '../process.js';
import { commandRecord, emptyResult } from './types.js';
export async function profileReArtifact(file, options = {}) {
    const result = await collectBinaryFacts(file, options, false);
    result.nextActions.push(...reNextActions(result.artifact, result.binary));
    return result;
}
export async function profilePwnArtifact(file, options = {}) {
    const result = await collectBinaryFacts(file, options, true);
    result.nextActions.push(...pwnNextActions(result.artifact, result.binary));
    return result;
}
export async function debugPwnArtifact(file, args, options = {}) {
    const base = emptyResult();
    const gdb = await findCtfExecutable('gdb', options.cwd);
    if (!gdb) {
        base.status = 'missing_capability';
        base.limitations.push('gdb is not installed.');
        base.nextActions.push({ tool: 'ctf_tool_audit', args: {}, reason: 'Refresh local pwn debugging capabilities.' });
        return { ...base, debugger: { output: null } };
    }
    const gdbCommands = [
        'set pagination off',
        'set confirm off',
        `file ${file.path}`,
        ...(Array.isArray(args.argv) && args.argv.length > 0 ? [`set args ${args.argv.slice(0, 16).join(' ')}`] : []),
        ...(args.breakAt ? [`break ${args.breakAt}`] : []),
        'starti',
        'info files',
        'info registers',
        'x/16i $pc',
        'x/24gx $rsp',
        'x/24gx $sp',
        'bt',
        ...(args.extraGdbCommands ?? []).slice(0, 12),
    ];
    const argv = ['-q', '-batch', ...gdbCommands.flatMap(command => ['-ex', command])];
    const capture = await runCommand(gdb, argv, { ...options, maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 100_000) });
    base.commands.push(commandRecord(gdb, argv, capture, options.cwd));
    base.observations.push(capture.ok
        ? 'gdb batch probe reached starti and collected register/disassembly context.'
        : `gdb batch probe exited with ${capture.exitCode ?? 'no status'}.`);
    base.nextActions.push({ tool: 'ctf_pwn_profile', args: { path: file.relativePath }, reason: 'Correlate debugger output with static mitigations and imports.' });
    return { ...base, status: capture.ok ? 'ok' : 'failed', debugger: { output: [capture.stdout, capture.stderr].filter(Boolean).join('\n').trim() || null } };
}
export async function debugPwndbgArtifact(file, args, options = {}) {
    const base = emptyResult();
    const gdb = await findCtfExecutable('gdb', options.cwd);
    if (!gdb) {
        base.status = 'missing_capability';
        base.limitations.push('gdb is not installed; Pwndbg cannot be loaded.');
        base.nextActions.push({ tool: 'ctf_tool_setup', args: { target: 'gdb_pwndbg' }, reason: 'Install GDB and Pwndbg before running the Pwndbg probe.' });
        return { ...base, debugger: { output: null, frontend: 'pwndbg' } };
    }
    const gdbCommands = [
        'set pagination off',
        'set confirm off',
        `file ${quoteGdbCommandArgument(file.path)}`,
        ...(Array.isArray(args.argv) && args.argv.length > 0 ? [`set args ${args.argv.slice(0, 16).map(quoteGdbCommandArgument).join(' ')}`] : []),
        ...(args.breakAt ? [`break ${quoteGdbCommandArgument(args.breakAt)}`] : []),
        'starti',
        'context',
        'vmmap',
        'info registers',
        'bt',
        ...(args.extraCommands ?? []).slice(0, 12),
    ];
    const argv = ['-q', '-batch', ...gdbCommands.flatMap(command => ['-ex', command])];
    const capture = await runCommand(gdb, argv, {
        ...options,
        maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000),
    });
    base.commands.push(commandRecord(gdb, argv, capture, options.cwd));
    const output = [capture.stdout, capture.stderr].filter(Boolean).join('\n').trim() || null;
    const combinedOutput = output?.toLowerCase() ?? '';
    if (combinedOutput.includes('pwndbg') || combinedOutput.includes('context')) {
        base.observations.push('GDB batch probe executed Pwndbg-oriented context, vmmap, register, and backtrace commands.');
    }
    else {
        base.limitations.push('GDB ran, but the output does not confirm Pwndbg command output; inspect the raw debugger output.');
    }
    if (!capture.ok) {
        base.limitations.push(`Pwndbg GDB probe exited with ${capture.exitCode ?? 'no status'}: ${capture.error ?? capture.stderr.trim()}`);
    }
    base.nextActions.push({ tool: 'ctf_pwn_profile', args: { path: file.relativePath }, reason: 'Correlate Pwndbg runtime observations with static mitigations and imports.' });
    const pwndbgLoaded = combinedOutput.includes('pwndbg');
    return {
        ...base,
        status: capture.ok || pwndbgLoaded ? 'ok' : 'failed',
        debugger: { output, frontend: 'pwndbg' },
    };
}
export async function searchRopGadgets(file, args, options = {}) {
    const base = emptyResult();
    const ropGadget = await findCtfExecutable('ROPgadget', options.cwd);
    const ropper = await findCtfExecutable('ropper', options.cwd);
    const maxResults = normalizeInteger(args.maxResults, 80, 1, 500);
    if (ropGadget) {
        const argv = ['--binary', file.path, ...(args.query ? ['--only', args.query] : [])];
        const capture = await runCommand(ropGadget, argv, { ...options, maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000) });
        base.commands.push(commandRecord(ropGadget, argv, capture, options.cwd));
        const gadgets = parseGadgetLines(capture.stdout, maxResults);
        base.observations.push(`ROPgadget returned ${gadgets.length} candidate gadget lines.`);
        return { ...base, status: capture.ok ? 'ok' : 'failed', gadgets };
    }
    if (ropper) {
        const argv = ['--file', file.path, '--nocolor', ...(args.query ? ['--search', args.query] : [])];
        const capture = await runCommand(ropper, argv, { ...options, maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000) });
        base.commands.push(commandRecord(ropper, argv, capture, options.cwd));
        const gadgets = parseGadgetLines(capture.stdout, maxResults);
        base.observations.push(`ropper returned ${gadgets.length} candidate gadget lines.`);
        return { ...base, status: capture.ok ? 'ok' : 'failed', gadgets };
    }
    base.status = 'missing_capability';
    base.limitations.push('Neither ROPgadget nor ropper is installed.');
    base.nextActions.push({ tool: 'ctf_tool_audit', args: {}, reason: 'Refresh local pwn gadget-search capabilities.' });
    return { ...base, gadgets: [] };
}
async function collectBinaryFacts(file, options, includeChecksec) {
    const profile = await profileCtfArtifact(file, options);
    const base = emptyResult();
    base.commands.push(...profile.commands);
    base.artifacts.push(profile.artifact);
    base.observations.push(...profile.observations);
    base.limitations.push(...profile.limitations);
    const binary = {
        format: detectFormat(profile.artifact.fileType),
        arch: null,
        entryPoint: null,
        protections: {
            pie: 'unknown',
            nx: 'unknown',
            relro: 'unknown',
            canary: 'unknown',
            stripped: profile.artifact.fileType && /\bnot stripped\b/i.test(profile.artifact.fileType) ? 'disabled' : /\bstripped\b/i.test(profile.artifact.fileType ?? '') ? 'enabled' : 'unknown',
        },
        imports: [],
        interestingStrings: [],
        checksec: null,
    };
    if (binary.format === 'elf') {
        const readelf = await findCtfExecutable('readelf', options.cwd);
        if (readelf) {
            const header = await runCommand(readelf, ['-hW', '--', file.path], options);
            const programHeaders = await runCommand(readelf, ['-lW', '--', file.path], options);
            const dynamic = await runCommand(readelf, ['-dW', '--', file.path], options);
            const symbols = await runCommand(readelf, ['-sW', '--', file.path], { ...options, maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000) });
            base.commands.push(commandRecord(readelf, ['-hW', '--', file.path], header, options.cwd), commandRecord(readelf, ['-lW', '--', file.path], programHeaders, options.cwd), commandRecord(readelf, ['-dW', '--', file.path], dynamic, options.cwd), commandRecord(readelf, ['-sW', '--', file.path], symbols, options.cwd));
            Object.assign(binary, parseElfFacts(header.stdout, programHeaders.stdout, dynamic.stdout, symbols.stdout, profile.artifact.fileType));
            if (![header, programHeaders, dynamic, symbols].every(item => item.ok))
                base.limitations.push('One or more readelf probes failed; binary metadata may be incomplete.');
        }
        else {
            base.limitations.push('readelf is not installed; ELF metadata and imports were skipped.');
        }
    }
    const strings = await findCtfExecutable('strings', options.cwd);
    if (strings) {
        const capture = await runCommand(strings, ['-a', '-t', 'x', '-n', '5', '--', file.path], { ...options, maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000) });
        base.commands.push(commandRecord(strings, ['-a', '-t', 'x', '-n', '5', '--', file.path], capture, options.cwd));
        binary.interestingStrings = classifyStrings(capture.stdout, 120);
        base.observations.push(`found ${binary.interestingStrings.length} CTF-relevant strings.`);
    }
    else {
        base.limitations.push('strings is not installed; embedded string leads were skipped.');
    }
    if (includeChecksec) {
        const checksec = await findCtfExecutable('checksec', options.cwd);
        if (checksec) {
            const argv = ['--file', file.path];
            const capture = await runCommand(checksec, argv, options);
            base.commands.push(commandRecord(checksec, argv, capture, options.cwd));
            binary.checksec = [capture.stdout, capture.stderr].filter(Boolean).join('\n').trim() || null;
            base.observations.push('checksec output recorded for pwn mitigation summary.');
        }
        else {
            base.limitations.push('checksec is not installed; mitigation facts are derived from readelf only.');
        }
    }
    base.observations.push(`binary format=${binary.format} arch=${binary.arch ?? 'unknown'} entry=${binary.entryPoint ?? 'unknown'}`);
    base.observations.push(`protections pie=${binary.protections.pie} nx=${binary.protections.nx} relro=${binary.protections.relro} canary=${binary.protections.canary} stripped=${binary.protections.stripped}`);
    return { ...base, artifact: profile.artifact, binary };
}
function parseElfFacts(header, programHeaders, dynamic, symbols, fileType) {
    const type = headerValue(header, 'Type');
    const stackLine = programHeaders.split(/\r?\n/).find(line => line.includes('GNU_STACK'));
    const stackFlags = stackLine?.trim().split(/\s+/).at(-2);
    const hasInterpreter = programHeaders.includes('INTERP');
    const hasRelro = programHeaders.includes('GNU_RELRO');
    const bindNow = /\bBIND_NOW\b|Flags:\s+.*\bNOW\b/.test(dynamic);
    return {
        arch: headerValue(header, 'Machine'),
        entryPoint: headerValue(header, 'Entry point address'),
        protections: {
            pie: type?.startsWith('DYN') && hasInterpreter ? 'enabled' : type?.startsWith('EXEC') ? 'disabled' : 'unknown',
            nx: stackFlags ? (stackFlags.includes('E') ? 'disabled' : 'enabled') : 'unknown',
            relro: hasRelro ? (bindNow ? 'full' : 'partial') : 'disabled',
            canary: symbols.includes('__stack_chk_fail') ? 'enabled' : symbols.trim() ? 'disabled' : 'unknown',
            stripped: fileType && /\bnot stripped\b/i.test(fileType) ? 'disabled' : /\bstripped\b/i.test(fileType ?? '') ? 'enabled' : 'unknown',
        },
        imports: parseUndefinedSymbols(symbols),
    };
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
function headerValue(output, label) {
    const prefix = `${label}:`;
    const line = output.split(/\r?\n/).find(item => item.trimStart().startsWith(prefix));
    return line ? line.slice(line.indexOf(':') + 1).trim() : null;
}
function parseUndefinedSymbols(symbols) {
    const result = new Set();
    for (const line of symbols.split(/\r?\n/)) {
        const match = line.match(/\bUND\s+(\S+)/);
        if (!match)
            continue;
        result.add(match[1].replace(/@.*$/, ''));
    }
    return [...result].filter(Boolean).sort();
}
function classifyStrings(output, maxStrings) {
    const result = [];
    const seen = new Set();
    for (const line of output.split(/\r?\n/)) {
        const match = line.match(/^\s*([0-9A-Fa-f]+)\s+(.+)$/);
        if (!match)
            continue;
        const value = match[2].trim();
        if (seen.has(value))
            continue;
        const tags = stringTags(value);
        if (tags.length === 0)
            continue;
        seen.add(value);
        result.push({ offset: `0x${match[1].toUpperCase()}`, value, tags });
        if (result.length >= maxStrings)
            break;
    }
    return result;
}
function stringTags(value) {
    const tags = [];
    if (/flag|ctf|key|serial|license|password|passwd|token|secret/i.test(value))
        tags.push('secret-or-flag');
    if (/strcmp|strncmp|memcmp|scanf|gets|printf|system|exec|shell|\/bin\/sh/i.test(value))
        tags.push('pwn-or-check');
    if (/encrypt|decrypt|cipher|rsa|aes|xor|md5|sha|base64/i.test(value))
        tags.push('crypto');
    if (/http|cookie|jwt|sql|select|union|admin|upload/i.test(value))
        tags.push('web');
    if (/%[0-9.*]*[psxnud]/.test(value))
        tags.push('format-string');
    return tags;
}
function pwnNextActions(artifact, binary) {
    const actions = [
        { tool: 'ctf_pwninit', args: { path: artifact.path }, reason: 'Use pwninit to select matching workspace ld/libc and create a reproducible patched runtime before final debugger or exploit validation.' },
        { tool: 'ctf_re_r2_query', args: { path: artifact.path, commands: ['aaa', 'ij', 'afl'] }, reason: 'Use radare2 headless analysis for a compact function and metadata pass instead of reproducing it with shell commands.' },
        { tool: 'ctf_pwn_gdb_probe', args: { path: artifact.path }, reason: 'Use the installed GDB/Pwndbg path first for runtime context before writing debugger code.' },
        { tool: 'ctf_pwn_debug_probe', args: { path: artifact.path }, reason: 'Collect register, entrypoint, stack, and mapping context under gdb.' },
    ];
    if (binary.protections.nx !== 'disabled') {
        actions.push({ tool: 'ctf_rop_search', args: { path: artifact.path, query: 'pop|ret' }, reason: 'NX is enabled or unknown, so ROP candidates are useful before exploit scripting.' });
    }
    if (binary.imports.some(name => ['gets', 'strcpy', 'sprintf', 'scanf', 'read', 'recv'].includes(name))) {
        actions.push({ tool: 'ctf_pwn_debug_probe', args: { path: artifact.path, breakAt: 'main' }, reason: 'Input-handling imports exist; inspect runtime state near main and input reads.' });
    }
    return actions;
}
function reNextActions(artifact, binary) {
    const actions = [
        { tool: 'ctf_re_r2_query', args: { path: artifact.path, commands: ['aaa', 'ij', 'afl'] }, reason: 'Use radare2 headless analysis and JSON metadata before generating custom reverse-engineering code.' },
        { tool: 'ctf_re_ida_script', args: { path: artifact.path, focus: binary.interestingStrings.slice(0, 8).map(item => item.value).join(' ') }, reason: 'Generate a focused IDAPython script for functions, strings, and xrefs when deeper RE evidence is needed.' },
        { tool: 'ctf_crypto_probe', args: { path: artifact.path }, reason: 'Check whether extracted constants or text point to a common encoding or crypto path.' },
    ];
    if (binary.imports.some(name => ['strcmp', 'strncmp', 'memcmp'].includes(name))) {
        actions.push({ tool: 'ctf_pwn_debug_probe', args: { path: artifact.path, breakAt: 'main' }, reason: 'Comparison imports exist; debugger breakpoints can validate candidate input checks.' });
    }
    return actions;
}
function parseGadgetLines(output, maxResults) {
    return output.split(/\r?\n/)
        .map(line => line.trim())
        .filter(line => /^0x[0-9a-f]+/i.test(line))
        .slice(0, maxResults);
}
function normalizeInteger(value, fallback, min, max) {
    if (value === undefined)
        return fallback;
    if (!Number.isInteger(value) || value < min || value > max)
        throw new Error(`integer must be in range ${min}..${max}`);
    return value;
}
function quoteGdbCommandArgument(value) {
    return `'${value.replaceAll('\\', '\\\\').replaceAll("'", "\\'")}'`;
}
//# sourceMappingURL=binary.js.map