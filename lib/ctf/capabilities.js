import { findExecutable } from '../paths.js';
import { runCommand } from '../process.js';
import { commandRecord } from './types.js';
const PROBES = [
    { id: 'core.file', category: 'core', executable: 'file', args: ['--version'], operations: ['artifact type detection'] },
    { id: 'core.strings', category: 'core', executable: 'strings', args: ['--version'], operations: ['printable string extraction'] },
    { id: 'core.binwalk', category: 'misc', executable: 'binwalk', args: ['--version'], operations: ['firmware and archive signature scan'] },
    { id: 'core.exiftool', category: 'misc', executable: 'exiftool', args: ['-ver'], operations: ['metadata extraction'] },
    { id: 'core.7z', category: 'misc', executable: '7z', args: [], operations: ['archive listing and extraction'] },
    { id: 'misc.tshark', category: 'misc', executable: 'tshark', args: ['--version'], operations: ['pcap protocol inventory'] },
    { id: 'misc.zsteg', category: 'misc', executable: 'zsteg', args: ['--version'], operations: ['png/bmp steganography scan'] },
    { id: 'misc.foremost', category: 'misc', executable: 'foremost', args: ['-V'], operations: ['file carving'] },
    { id: 're.readelf', category: 're', executable: 'readelf', args: ['--version'], operations: ['ELF header, section, symbol, and dynamic metadata'] },
    { id: 're.objdump', category: 're', executable: 'objdump', args: ['--version'], operations: ['disassembly and relocation inspection'] },
    { id: 're.nm', category: 're', executable: 'nm', args: ['--version'], operations: ['symbol listing'] },
    { id: 're.r2', category: 're', executable: 'r2', args: ['-v'], operations: ['headless reverse-engineering queries'] },
    { id: 're.ghidra', category: 're', executable: 'analyzeHeadless', args: [], operations: ['Ghidra headless analysis'] },
    { id: 'pwn.checksec', category: 'pwn', executable: 'checksec', args: ['--version'], operations: ['binary mitigation summary'] },
    { id: 'pwn.gdb', category: 'pwn', executable: 'gdb', args: ['--version'], operations: ['batch debugging, registers, stack, maps'] },
    { id: 'pwn.ropgadget', category: 'pwn', executable: 'ROPgadget', args: ['--version'], operations: ['ROP gadget search'] },
    { id: 'pwn.ropper', category: 'pwn', executable: 'ropper', args: ['--version'], operations: ['ROP gadget search'] },
    { id: 'pwn.one_gadget', category: 'pwn', executable: 'one_gadget', args: ['--version'], operations: ['libc one_gadget search'] },
    { id: 'crypto.sage', category: 'crypto', executable: 'sage', args: ['--version'], operations: ['number theory and symbolic math'] },
    { id: 'crypto.gp', category: 'crypto', executable: 'gp', args: ['--version'], operations: ['PARI/GP number theory'] },
    { id: 'web.curl', category: 'web', executable: 'curl', args: ['--version'], operations: ['HTTP request baseline'] },
    { id: 'web.httpx', category: 'web', executable: 'httpx', args: ['--version'], operations: ['HTTP probing'] },
    { id: 'web.sqlmap', category: 'web', executable: 'sqlmap', args: ['--version'], operations: ['SQL injection verification on local challenge targets'] },
    { id: 'web.chromium', category: 'web', executable: 'chromium', args: ['--version'], operations: ['browser-backed observation'] },
];
const PYTHON_MODULES = [
    { module: 'pwntools', importName: 'pwn', category: 'pwn', operations: ['process interaction, tube IO, cyclic patterns, packing, ELF metadata'] },
    { module: 'z3', importName: 'z3', category: 'crypto', operations: ['constraint solving'] },
    { module: 'sympy', importName: 'sympy', category: 'crypto', operations: ['symbolic math and integer number theory'] },
    { module: 'pycryptodome', importName: 'Crypto', category: 'crypto', operations: ['block ciphers, hashes, public-key primitives'] },
    { module: 'gmpy2', importName: 'gmpy2', category: 'crypto', operations: ['fast big integer arithmetic'] },
    { module: 'requests', importName: 'requests', category: 'web', operations: ['structured HTTP client'] },
    { module: 'scapy', importName: 'scapy.all', category: 'misc', operations: ['packet parsing and generation'] },
    { module: 'PIL', importName: 'PIL', category: 'misc', operations: ['image parsing and transforms'] },
];
export async function auditCtfTools(options = {}) {
    const capabilities = [];
    const commands = [];
    for (const probe of PROBES) {
        const resolved = await findExecutable(probe.executable);
        if (!resolved) {
            capabilities.push({
                id: probe.id,
                category: probe.category,
                executable: probe.executable,
                available: false,
                path: null,
                version: null,
                operations: probe.operations,
                features: probe.features ?? [],
            });
            continue;
        }
        let version = null;
        if (probe.args.length > 0) {
            const result = await runCommand(resolved, probe.args, options);
            commands.push(commandRecord(resolved, probe.args, result, options.cwd));
            version = firstLine(result.stdout, result.stderr);
        }
        capabilities.push({
            id: probe.id,
            category: probe.category,
            executable: probe.executable,
            available: true,
            path: resolved,
            version,
            operations: probe.operations,
            features: probe.features ?? [],
        });
    }
    const python = await probePython(options);
    return {
        schemaVersion: '1.0',
        available: capabilities.filter(item => item.available).length + python.modules.filter(item => item.available).length,
        missing: capabilities.filter(item => !item.available).length + python.modules.filter(item => !item.available).length,
        capabilities,
        python: {
            executable: python.executable,
            version: python.version,
            modules: python.modules,
        },
        commands: [...commands, ...python.commands],
        recommendations: recommendations(capabilities, python.modules),
    };
}
export function hasCapability(audit, id) {
    return [...audit.capabilities, ...audit.python.modules].some(item => item.id === id && item.available);
}
async function probePython(options) {
    const python = await findExecutable('python3') ?? await findExecutable('python');
    const commands = [];
    if (!python) {
        return {
            executable: null,
            version: null,
            commands,
            modules: PYTHON_MODULES.map(item => ({
                id: `python.${item.module}`,
                category: item.category,
                executable: item.importName,
                available: false,
                path: null,
                version: null,
                operations: item.operations,
                features: [],
            })),
        };
    }
    const versionResult = await runCommand(python, ['--version'], options);
    commands.push(commandRecord(python, ['--version'], versionResult, options.cwd));
    const modules = [];
    for (const moduleProbe of PYTHON_MODULES) {
        const result = await runCommand(python, ['-c', `import ${moduleProbe.importName}; print("ok")`], options);
        commands.push(commandRecord(python, ['-c', `import ${moduleProbe.importName}; print("ok")`], result, options.cwd));
        modules.push({
            id: `python.${moduleProbe.module}`,
            category: moduleProbe.category,
            executable: moduleProbe.importName,
            available: result.ok,
            path: result.ok ? python : null,
            version: result.ok ? 'import ok' : null,
            operations: moduleProbe.operations,
            features: [],
        });
    }
    return {
        executable: python,
        version: firstLine(versionResult.stdout, versionResult.stderr),
        modules,
        commands,
    };
}
function firstLine(stdout, stderr) {
    return `${stdout}\n${stderr}`.split(/\r?\n/).map(line => line.trim()).find(Boolean) ?? null;
}
function recommendations(capabilities, modules) {
    const available = new Set([...capabilities, ...modules].filter(item => item.available).map(item => item.id));
    const result = [];
    if (!available.has('core.file'))
        result.push('Install file for reliable artifact type detection.');
    if (!available.has('re.readelf'))
        result.push('Install binutils for ELF analysis.');
    if (!available.has('pwn.gdb'))
        result.push('Install gdb for pwn runtime probes.');
    if (!available.has('python.pwntools'))
        result.push('Install pwntools for pwn process automation.');
    if (!available.has('web.curl') && !available.has('python.requests'))
        result.push('Install curl or requests for web challenge baselines.');
    if (!available.has('misc.tshark'))
        result.push('Install tshark for PCAP triage.');
    if (!available.has('crypto.sage') && !available.has('python.z3') && !available.has('python.sympy')) {
        result.push('Install Sage, z3, or SymPy for crypto challenge solving.');
    }
    return result;
}
//# sourceMappingURL=capabilities.js.map