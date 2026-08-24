import path from 'node:path';
import { ctfCommandOptions, discoverCtfPython, findCtfExecutable, findCtfIdaExecutable } from './environment.js';
import { runCommand } from '../process.js';
import { discoverCtfMcpConfiguration } from './mcp.js';
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
    { id: 're.llvm_objdump', category: 're', executable: 'llvm-objdump', args: ['--version'], operations: ['PE/COFF and multi-architecture disassembly'] },
    { id: 're.llvm_readobj', category: 're', executable: 'llvm-readobj', args: ['--version'], operations: ['PE/COFF headers, imports, exports, and architecture metadata'] },
    { id: 're.gdb_multiarch', category: 're', executable: 'gdb-multiarch', args: ['--version'], operations: ['multi-architecture debugging'] },
    { id: 're.qemu_arm', category: 're', executable: 'qemu-arm', args: ['--version'], operations: ['ARM user-mode emulation'] },
    { id: 're.qemu_aarch64', category: 're', executable: 'qemu-aarch64', args: ['--version'], operations: ['AArch64 user-mode emulation'] },
    { id: 're.wine', category: 're', executable: 'wine', args: ['--version'], operations: ['Windows PE runtime observation'] },
    { id: 're.winedbg', category: 're', executable: 'winedbg', args: ['--version'], operations: ['Windows runtime debugger'] },
    { id: 're.mingw_objdump', category: 're', executable: 'x86_64-w64-mingw32-objdump', args: ['--version'], operations: ['MinGW PE/COFF inspection'] },
    { id: 're.android_aapt2', category: 're', executable: 'aapt2', args: ['version'], operations: ['APK manifest and resource metadata'] },
    { id: 're.android_jadx', category: 're', executable: 'jadx', args: ['--version'], operations: ['DEX/APK decompilation'] },
    { id: 're.android_adb', category: 're', executable: 'adb', args: ['version'], operations: ['Android device/emulator bridge'] },
    { id: 're.android_frida', category: 're', executable: 'frida', args: ['--version'], operations: ['Android runtime instrumentation'] },
    { id: 're.patchelf', category: 're', executable: 'patchelf', args: ['--version'], operations: ['ELF interpreter, RPATH, and metadata inspection'] },
    { id: 're.strace', category: 're', executable: 'strace', args: ['-V'], operations: ['syscall tracing'] },
    { id: 're.ltrace', category: 're', executable: 'ltrace', args: ['-V'], operations: ['library call tracing'] },
    { id: 'pwn.checksec', category: 'pwn', executable: 'checksec', args: ['--version'], operations: ['binary mitigation summary'] },
    { id: 'pwn.gdb', category: 'pwn', executable: 'gdb', args: ['--version'], operations: ['batch debugging, registers, stack, maps'] },
    { id: 'pwn.ropgadget', category: 'pwn', executable: 'ROPgadget', args: ['--version'], operations: ['ROP gadget search'] },
    { id: 'pwn.ropper', category: 'pwn', executable: 'ropper', args: ['--version'], operations: ['ROP gadget search'] },
    { id: 'pwn.one_gadget', category: 'pwn', executable: 'one_gadget', args: ['--version'], operations: ['libc one_gadget search'] },
    { id: 'pwn.seccomp_tools', category: 'pwn', executable: 'seccomp-tools', args: ['--version'], operations: ['seccomp rule dump and inspection'] },
    { id: 'pwn.pwninit', category: 'pwn', executable: 'pwninit', args: ['--version'], operations: ['loader/libc selection', 'patchelf runtime setup', 'backup and restore', 'patched runtime diagnosis'], features: ['glibc-switch', 'backup-restore', 'doctor'] },
    { id: 'crypto.sage', category: 'crypto', executable: 'sage', args: ['--version'], operations: ['number theory and symbolic math'] },
    { id: 'crypto.gp', category: 'crypto', executable: 'gp', args: ['--version'], operations: ['PARI/GP number theory'] },
    { id: 'web.curl', category: 'web', executable: 'curl', args: ['--version'], operations: ['HTTP request baseline'] },
    { id: 'web.httpx', category: 'web', executable: 'httpx', args: ['--version'], operations: ['HTTP probing'] },
    { id: 'web.sqlmap', category: 'web', executable: 'sqlmap', args: ['--version'], operations: ['SQL injection verification on local challenge targets'] },
    { id: 'web.chromium', category: 'web', executable: 'chromium', args: ['--version'], operations: ['browser-backed observation'] },
    { id: 'web.mcp_chrome_bridge', category: 'web', executable: 'mcp-chrome-bridge', args: ['--version'], operations: ['Chrome native-messaging bridge and MCP HTTP service'] },
    { id: 'web.ffuf', category: 'web', executable: 'ffuf', args: ['-V'], operations: ['content and parameter discovery'] },
    { id: 'web.feroxbuster', category: 'web', executable: 'feroxbuster', args: ['--version'], operations: ['content discovery'] },
    { id: 'web.mitmproxy', category: 'web', executable: 'mitmproxy', args: ['--version'], operations: ['HTTP(S) proxy capture and replay'] },
    { id: 'web.mitmweb', category: 'web', executable: 'mitmweb', args: ['--version'], operations: ['interactive HTTP(S) proxy capture'] },
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
    { module: 'angr', importName: 'angr', category: 're', operations: ['symbolic execution and binary exploration'] },
    { module: 'unicorn', importName: 'unicorn', category: 're', operations: ['CPU emulation'] },
    { module: 'capstone', importName: 'capstone', category: 're', operations: ['multi-architecture disassembly'] },
    { module: 'lief', importName: 'lief', category: 're', operations: ['binary format parsing and patch planning'] },
    { module: 'androguard', importName: 'androguard', category: 're', operations: ['Android APK/DEX static analysis'] },
    { module: 'frida', importName: 'frida', category: 're', operations: ['runtime instrumentation client'] },
    { module: 'pyelftools', importName: 'elftools', category: 're', operations: ['ELF parsing and architecture metadata'] },
    { module: 'beautifulsoup4', importName: 'bs4', category: 'web', operations: ['HTML parsing'] },
    { module: 'playwright', importName: 'playwright', category: 'web', operations: ['browser automation fallback'] },
];
export async function auditCtfTools(options = {}) {
    const capabilities = [];
    const commands = [];
    const python = await probePython(options);
    for (const probe of PROBES) {
        const resolved = await findCtfExecutable(probe.executable, options.cwd);
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
        let available = true;
        if (probe.args.length > 0) {
            const result = await runCommand(resolved, probe.args, ctfCommandOptions(resolved, options));
            commands.push(commandRecord(resolved, probe.args, result, options.cwd));
            available = result.ok;
            version = result.ok ? firstLine(result.stdout, result.stderr) : null;
        }
        capabilities.push({
            id: probe.id,
            category: probe.category,
            executable: probe.executable,
            available,
            path: available ? resolved : null,
            version,
            operations: probe.operations,
            features: probe.features ?? [],
        });
    }
    const pwndbg = await probePwndbg(options);
    const ida = await probeIdaCli();
    const mcp = await probeMcpConfiguration();
    capabilities.push(pwndbg, ida);
    return {
        schemaVersion: '1.0',
        available: capabilities.filter(item => item.available).length + python.modules.filter(item => item.available).length,
        missing: capabilities.filter(item => !item.available).length + python.modules.filter(item => !item.available).length,
        capabilities,
        python: {
            policy: python.policy,
            requiredExecutable: python.requiredExecutable,
            executable: python.executable,
            source: python.source,
            venv: python.venv,
            bin: python.bin,
            version: python.version,
            modules: python.modules,
        },
        mcp,
        toolBindings: buildToolBindings(capabilities, python.modules, Boolean(python.executable)),
        commands: [...commands, ...python.commands, ...pwndbg.commands],
        recommendations: recommendations(capabilities, python.modules, mcp),
    };
}
export function hasCapability(audit, id) {
    return [...audit.capabilities, ...audit.python.modules].some(item => item.id === id && item.available);
}
async function probePython(options) {
    const environment = await discoverCtfPython(options.cwd);
    const commands = [];
    if (!environment.executable) {
        return {
            policy: environment.policy,
            requiredExecutable: environment.requiredExecutable,
            executable: null,
            source: environment.source,
            venv: null,
            bin: null,
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
    const versionResult = await runCommand(environment.executable, ['--version'], options);
    commands.push(commandRecord(environment.executable, ['--version'], versionResult, options.cwd));
    const modules = [];
    for (const moduleProbe of PYTHON_MODULES) {
        const argv = ['-c', `import ${moduleProbe.importName}; print("ok")`];
        const result = await runCommand(environment.executable, argv, options);
        commands.push(commandRecord(environment.executable, argv, result, options.cwd));
        modules.push({
            id: `python.${moduleProbe.module}`,
            category: moduleProbe.category,
            executable: moduleProbe.importName,
            available: result.ok,
            path: result.ok ? environment.executable : null,
            version: result.ok ? 'import ok' : null,
            operations: moduleProbe.operations,
            features: [],
        });
    }
    return {
        policy: environment.policy,
        requiredExecutable: environment.requiredExecutable,
        executable: environment.executable,
        source: environment.source,
        venv: environment.venv,
        bin: environment.bin,
        version: firstLine(versionResult.stdout, versionResult.stderr),
        modules,
        commands,
    };
}
async function probePwndbg(options) {
    const gdb = await findCtfExecutable('gdb', options.cwd);
    if (!gdb) {
        return {
            id: 'pwn.pwndbg',
            category: 'pwn',
            executable: 'gdb',
            available: false,
            path: null,
            version: null,
            operations: ['context view', 'pwndbg vmmap', 'heap and register helpers'],
            features: [],
            commands: [],
        };
    }
    const argv = ['-q', '-batch', '-ex', 'python import pwndbg; print("pwndbg-loaded")'];
    const result = await runCommand(gdb, argv, options);
    return {
        id: 'pwn.pwndbg',
        category: 'pwn',
        executable: 'gdb',
        available: result.ok && `${result.stdout}\n${result.stderr}`.includes('pwndbg-loaded'),
        path: result.ok ? gdb : null,
        version: result.ok ? 'loaded through gdb' : null,
        operations: ['context view', 'pwndbg vmmap', 'heap and register helpers'],
        features: result.ok ? ['python', 'pwndbg'] : [],
        commands: [commandRecord(gdb, argv, result, options.cwd)],
    };
}
async function probeIdaCli() {
    const executable = await findCtfIdaExecutable();
    if (executable) {
        return {
            id: 're.ida_cli',
            category: 're',
            executable: path.basename(executable),
            available: true,
            path: executable,
            version: 'CLI detected',
            operations: ['IDAPython script execution', 'batch analysis'],
            features: ['idapython', 'batch', 'absolute-path'],
        };
    }
    return {
        id: 're.ida_cli',
        category: 're',
        executable: 'idat64',
        available: false,
        path: null,
        version: null,
        operations: ['IDAPython script execution', 'batch analysis'],
        features: [],
    };
}
async function probeMcpConfiguration() {
    const discovery = await discoverCtfMcpConfiguration();
    const definitions = [
        { id: 'mcp.ida_pro', category: 're', names: ['ida-pro', 'ida', 'ida-pro-mcp'], operations: ['IDAPython script dispatch', 'functions', 'xrefs', 'decompiler queries'] },
        { id: 'mcp.r2', category: 're', names: ['r2', 'radare2', 'radare2-mcp'], operations: ['r2 command dispatch', 'analysis JSON', 'xrefs', 'debugger queries'] },
        { id: 'mcp.chrome', category: 'web', names: ['mcp-chrome', 'chrome-mcp', 'chrome', 'chrome-devtools', 'chrome-devtools-mcp'], operations: ['browser navigation', 'DOM', 'network', 'console', 'screenshots', 'tabs', 'cookies'] },
        { id: 'mcp.gdb_pwndbg', category: 'pwn', names: ['gdb-pwndbg', 'pwndbg', 'gdb-mcp'], operations: ['breakpoints', 'registers', 'memory', 'pwndbg context'] },
        { id: 'mcp.tavily', category: 'web', names: ['tavily', 'tavily-mcp', 'tavily-remote-mcp'], operations: ['CVE search', 'vulnerability version lookup', 'web search', 'page extraction'] },
    ];
    return definitions.map(definition => {
        const matchedName = definition.names.find(name => isConfiguredServer(discovery.configuredServers[name]));
        const envKey = `DSH_CTF_${definition.id.slice(4).toUpperCase().replaceAll('.', '_')}_MCP`;
        const envValue = process.env[envKey]?.trim();
        const envConfigured = Boolean(envValue)
            || definition.id === 'mcp.tavily' && Boolean(process.env.TAVILY_API_KEY?.trim())
            || definition.id === 'mcp.chrome' && Boolean(process.env.DSH_CTF_CHROME_MCP_URL?.trim());
        const source = matchedName
            ? `${discovery.serverSources[matchedName] ?? 'MCP config'}:${matchedName}`
            : envValue
                ? envKey
                : definition.id === 'mcp.tavily' && process.env.TAVILY_API_KEY?.trim()
                    ? 'TAVILY_API_KEY'
                    : definition.id === 'mcp.chrome' && process.env.DSH_CTF_CHROME_MCP_URL?.trim()
                        ? 'DSH_CTF_CHROME_MCP_URL'
                        : null;
        return {
            id: definition.id,
            category: definition.category,
            configured: Boolean(matchedName || envConfigured),
            configSource: source,
            command: envValue || (matchedName ? 'configured in MCP JSON' : null),
            operations: definition.operations,
            limitation: matchedName || envConfigured ? null : 'MCP server must be installed and configured before DSH/Codex can use its external operations.',
        };
    });
}
function isConfiguredServer(value) {
    if (value === undefined || value === null)
        return false;
    if (typeof value === 'string')
        return value.trim() !== '' && !value.startsWith('REPLACE_WITH_');
    if (typeof value !== 'object')
        return false;
    const command = value.command;
    const url = value.url;
    if ((typeof command !== 'string' || command.trim() === '' || command.startsWith('REPLACE_WITH_'))
        && (typeof url !== 'string' || url.trim() === '' || url.startsWith('REPLACE_WITH_')))
        return false;
    const args = value.args;
    if (Array.isArray(args) && args.some(item => typeof item === 'string' && item.startsWith('REPLACE_WITH_')))
        return false;
    const env = value.env;
    if (env && typeof env === 'object') {
        for (const [key, item] of Object.entries(env)) {
            if (typeof item !== 'string' || item.trim() === '' || isSecretPlaceholder(key, item))
                return false;
        }
    }
    return true;
}
function firstLine(stdout, stderr) {
    return `${stdout}\n${stderr}`.split(/\r?\n/).map(line => line.trim()).find(Boolean) ?? null;
}
function recommendations(capabilities, modules, mcp) {
    const available = new Set([...capabilities, ...modules].filter(item => item.available).map(item => item.id));
    const result = [];
    if (!available.has('core.file'))
        result.push('Install file for reliable artifact type detection.');
    if (!available.has('re.readelf'))
        result.push('Install binutils for ELF analysis.');
    if (!available.has('re.r2'))
        result.push('Install radare2 for fast headless RE queries and JSON output.');
    if (!available.has('re.llvm_readobj') && !available.has('re.llvm_objdump'))
        result.push('Install LLVM tools for PE/COFF headers, imports, exports, and multi-architecture disassembly.');
    if (!available.has('re.gdb_multiarch'))
        result.push('Install gdb-multiarch when ARM or other non-native runtime debugging is required.');
    if (!available.has('re.qemu_arm') || !available.has('re.qemu_aarch64'))
        result.push('Install qemu-user for ARM/AArch64 user-mode emulation.');
    if (!available.has('re.android_aapt2') && !available.has('re.android_jadx'))
        result.push('Install Android build-tools/aapt2 and jadx for APK/DEX analysis.');
    if (!available.has('re.android_adb'))
        result.push('Install android-tools when an Android emulator or device is part of the challenge.');
    if (!available.has('re.android_frida') && !available.has('python.frida'))
        result.push('Install Frida tools or the fixed Python frida module for Android runtime instrumentation.');
    if (!available.has('pwn.gdb'))
        result.push('Install gdb for pwn runtime probes.');
    if (!available.has('pwn.pwndbg'))
        result.push('Configure pwndbg inside gdb for context, vmmap, heap, and register views.');
    if (!available.has('pwn.checksec'))
        result.push('Install checksec for a concise mitigation summary.');
    if (!available.has('pwn.pwninit'))
        result.push('Install or expose pwninit for deterministic loader/libc selection, patching, backup, and restore.');
    if (!available.has('python.pwntools'))
        result.push('Install pwntools for pwn process automation.');
    if (!available.has('pwn.ropgadget') && !available.has('pwn.ropper'))
        result.push('Install ROPgadget or ropper for gadget enumeration.');
    if (!available.has('pwn.one_gadget'))
        result.push('Install one_gadget for libc one-gadget candidate enumeration.');
    if (!available.has('re.ida_cli') && !mcp.some(item => item.id === 'mcp.ida_pro' && item.configured)) {
        result.push('IDA CLI is optional: use the configured IDA MCP for IDAPython/decompiler work, or expose idat64/idat only for batch fallback.');
    }
    if (!available.has('re.patchelf'))
        result.push('Install patchelf for ELF interpreter and RPATH inspection.');
    if (!available.has('re.strace') && !available.has('re.ltrace'))
        result.push('Install strace or ltrace for runtime syscall/library tracing.');
    if (!available.has('web.curl') && !available.has('python.requests'))
        result.push('Install curl or requests for web challenge baselines.');
    if (!available.has('web.chromium')
        && !available.has('web.mcp_chrome_bridge')
        && !mcp.some(item => item.id === 'mcp.chrome' && item.configured)) {
        result.push('Install Chromium/Chrome for the local headless fallback, or install/configure the mcp-chrome browser bridge.');
    }
    else if (!mcp.some(item => item.id === 'mcp.chrome' && item.configured)) {
        result.push('Configure the detected mcp-chrome bridge before interactive browser operations.');
    }
    if (!available.has('misc.tshark'))
        result.push('Install tshark for PCAP triage.');
    if (!available.has('web.mitmproxy'))
        result.push('Install mitmproxy for live HTTP(S) capture; tshark remains the offline PCAP tool.');
    if (!available.has('web.ffuf') && !available.has('web.feroxbuster'))
        result.push('Install ffuf or feroxbuster for controlled Web content discovery.');
    if (!mcp.some(item => item.id === 'mcp.tavily' && item.configured)) {
        result.push('When CVE or version research is needed, provide TAVILY_API_KEY to ctf_mcp_configure; the key must not be pasted into logs or JSON shown to the model.');
    }
    if (!available.has('crypto.sage') && !available.has('crypto.gp') && !available.has('python.z3') && !available.has('python.sympy')) {
        result.push('Install Sage, PARI/GP, z3, or SymPy for crypto challenge solving.');
    }
    for (const item of mcp.filter(item => !item.configured)) {
        if (item.id === 'mcp.tavily' || item.id === 'mcp.chrome')
            continue;
        result.push(`Configure ${item.id} through ctf_mcp_configure or the host MCP client before using its external server.`);
    }
    return result;
}
const TOOL_BINDINGS = [
    {
        tool: 'ctf_crypto_probe',
        category: 'crypto',
        purpose: 'Detect common encodings, entropy, hashes, and single-byte XOR candidates before a solver is written.',
        when: 'Text or a small crypto artifact needs structured first-pass classification.',
        backendCapabilities: [],
        fallbackTool: 'ctf_tool_audit',
        exampleArgs: { text: '414243' },
    },
    {
        tool: 'ctf_python_exec',
        category: 'auto',
        purpose: 'Run inline Python or a workspace script through the fixed CTF Python interpreter.',
        when: 'A Python helper is required after the installed CTF tools leave a concrete gap.',
        backendCapabilities: ['python.fixed'],
        exampleArgs: { code: 'print("ctf-python-ready")' },
    },
    {
        tool: 'ctf_artifact_profile',
        category: 'auto',
        purpose: 'Hash and identify one local challenge artifact.',
        when: 'The file type, path, or integrity is not yet established.',
        backendCapabilities: ['core.file'],
        exampleArgs: { path: 'chall' },
    },
    {
        tool: 'ctf_re_profile',
        category: 're',
        purpose: 'Collect ELF/PE metadata, imports, strings, and protection facts.',
        when: 'A binary or source-like artifact needs a compact static overview.',
        backendCapabilities: ['core.file', 'core.strings', 're.readelf'],
        fallbackTool: 'ctf_artifact_profile',
        exampleArgs: { path: 'chall' },
    },
    {
        tool: 'ctf_re_r2_query',
        category: 're',
        purpose: 'Run bounded radare2 commands and return raw plus parseable JSON output.',
        when: 'Functions, xrefs, disassembly, sections, or JSON metadata are useful.',
        backendCapabilities: ['re.r2'],
        fallbackTool: 'ctf_re_profile',
        exampleArgs: { path: 'chall', commands: ['aaa', 'ij', 'afl'] },
    },
    {
        tool: 'ctf_re_ida_script',
        category: 're',
        purpose: 'Generate focused IDAPython for an IDA MCP/UI or optional CLI batch run.',
        when: 'Decompiler-side types, xrefs, or IDA database state is valuable.',
        backendCapabilities: [],
        fallbackTool: 'ctf_re_r2_query',
        exampleArgs: { path: 'chall', focus: 'flag strcmp', execute: false },
    },
    {
        tool: 'ctf_re_pe_profile',
        category: 're',
        purpose: 'Profile Windows PE headers, sections, imports, exports, and loader metadata with LLVM tools.',
        when: 'The artifact is PE/COFF or Windows-specific metadata is the next evidence question.',
        backendCapabilities: ['re.llvm_readobj', 're.llvm_objdump'],
        anyBackend: true,
        fallbackTool: 'ctf_re_profile',
        exampleArgs: { path: 'chall.exe' },
    },
    {
        tool: 'ctf_re_android_profile',
        category: 're',
        purpose: 'Profile APK metadata and discover JADX, ADB, and Frida runtime backends.',
        when: 'The artifact is an APK or Android runtime evidence is required.',
        backendCapabilities: ['re.android_aapt2', 're.android_jadx'],
        anyBackend: true,
        fallbackTool: 'ctf_tool_setup',
        exampleArgs: { path: 'app.apk' },
    },
    {
        tool: 'ctf_re_arch_profile',
        category: 're',
        purpose: 'Identify non-x86 architecture evidence and report LLVM/readelf plus QEMU user-mode backends.',
        when: 'The artifact is ARM, AArch64, MIPS, RISC-V, or another non-native architecture.',
        backendCapabilities: ['re.readelf', 're.llvm_readobj'],
        anyBackend: true,
        fallbackTool: 'ctf_tool_setup',
        exampleArgs: { path: 'chall.arm' },
    },
    {
        tool: 'ctf_re_android_jadx',
        category: 're',
        purpose: 'Decompile APK/DEX through JADX and return generated workspace files.',
        when: 'Android static analysis needs Java/XML source output after package capability detection.',
        backendCapabilities: ['re.android_jadx'],
        fallbackTool: 'ctf_tool_setup',
        exampleArgs: { path: 'app.apk' },
    },
    {
        tool: 'ctf_re_qemu_probe',
        category: 're',
        purpose: 'Execute ARM/AArch64 artifacts through QEMU user mode with bounded arguments.',
        when: 'Architecture-specific runtime behavior must be observed after static architecture identification.',
        backendCapabilities: ['re.qemu_arm', 're.qemu_aarch64'],
        fallbackTool: 'ctf_tool_setup',
        exampleArgs: { path: 'chall.arm', architecture: 'arm' },
    },
    {
        tool: 'ctf_pwn_profile',
        category: 'pwn',
        purpose: 'Summarize mitigations, imports, strings, and likely pwn entry points.',
        when: 'A local executable is the challenge artifact.',
        backendCapabilities: ['core.file', 'core.strings', 're.readelf'],
        fallbackTool: 'ctf_artifact_profile',
        exampleArgs: { path: 'pwn' },
    },
    {
        tool: 'ctf_pwninit',
        category: 'pwn',
        purpose: 'Select and patch the challenge loader/libc with backup and restore support.',
        when: 'Matching libc/ld files, a dependency directory, or a known glibc source exists.',
        backendCapabilities: ['pwn.pwninit', 're.patchelf'],
        fallbackTool: 'ctf_pwn_profile',
        exampleArgs: { path: 'pwn', mode: 'prepare' },
    },
    {
        tool: 'ctf_pwn_gdb_probe',
        category: 'pwn',
        purpose: 'Run a bounded GDB session with Pwndbg context, vmmap, registers, and backtrace.',
        when: 'Heap layout, runtime mappings, breakpoints, or debugger state needs inspection.',
        backendCapabilities: ['pwn.gdb', 'pwn.pwndbg'],
        fallbackTool: 'ctf_pwn_debug_probe',
        exampleArgs: { path: 'pwn', breakAt: 'main' },
    },
    {
        tool: 'ctf_pwn_debug_probe',
        category: 'pwn',
        purpose: 'Run generic bounded GDB commands when Pwndbg is unavailable or a custom probe is needed.',
        when: 'Registers, stack, entrypoint, or a specific breakpoint must be checked.',
        backendCapabilities: ['pwn.gdb'],
        fallbackTool: 'ctf_tool_setup',
        exampleArgs: { path: 'pwn', breakAt: 'main' },
    },
    {
        tool: 'ctf_rop_search',
        category: 'pwn',
        purpose: 'Enumerate gadgets through ROPgadget or ropper.',
        when: 'NX is enabled, a ROP chain is plausible, or gadget availability is unknown.',
        backendCapabilities: ['pwn.ropgadget', 'pwn.ropper'],
        anyBackend: true,
        fallbackTool: 'ctf_pwn_profile',
        exampleArgs: { path: 'pwn', query: 'pop|ret', maxResults: 80 },
    },
    {
        tool: 'ctf_one_gadget',
        category: 'pwn',
        purpose: 'Enumerate libc one-gadget offsets, invocation forms, and constraints.',
        when: 'A matching libc is available and a ret2libc or libc-base control-flow hypothesis is plausible.',
        backendCapabilities: ['pwn.one_gadget'],
        fallbackTool: 'ctf_pwn_profile',
        exampleArgs: { path: 'pwn', libcPath: 'libc.so.6', level: 0, maxResults: 80 },
    },
    {
        tool: 'ctf_seccomp_profile',
        category: 'pwn',
        purpose: 'Dump seccomp filters and extract syscall names through the installed seccomp-tools backend.',
        when: 'The binary imports prctl/seccomp, mentions sandboxing, or runtime behavior suggests syscall restrictions.',
        backendCapabilities: ['pwn.seccomp_tools'],
        fallbackTool: 'ctf_pwn_profile',
        exampleArgs: { path: 'pwn', format: 'disasm', limit: 1 },
    },
    {
        tool: 'ctf_sage_exec',
        category: 'crypto',
        purpose: 'Run SageMath code or a workspace script for number theory, finite fields, elliptic curves, and symbolic crypto calculations.',
        when: 'Crypto evidence calls for Sage-specific algebra or number-theory operations.',
        backendCapabilities: ['crypto.sage'],
        fallbackTool: 'ctf_python_exec',
        exampleArgs: { code: 'print(factor(2^64 - 1))' },
    },
    {
        tool: 'ctf_gp_exec',
        category: 'crypto',
        purpose: 'Run PARI/GP code or a workspace script for fast integer arithmetic, factorization, and algebraic number theory.',
        when: 'PARI/GP is a better fit than Sage or Python for the concrete arithmetic query.',
        backendCapabilities: ['crypto.gp'],
        fallbackTool: 'ctf_sage_exec',
        exampleArgs: { code: 'factor(2^64 - 1)' },
    },
    {
        tool: 'ctf_http_request',
        category: 'web',
        purpose: 'Capture one structured HTTP baseline with status, hash, preview, and exact argv.',
        when: 'A challenge URL or local service endpoint is available.',
        backendCapabilities: ['web.curl'],
        fallbackTool: 'ctf_human_request',
        exampleArgs: { url: 'http://HOST:PORT/', method: 'GET' },
    },
    {
        tool: 'ctf_web_browser_probe',
        category: 'web',
        purpose: 'Inspect rendered DOM and optional screenshot through local browser automation.',
        when: 'Client-side JavaScript or rendered browser state matters.',
        backendCapabilities: ['web.chromium', 'python.playwright'],
        anyBackend: true,
        fallbackTool: 'ctf_human_request',
        exampleArgs: { url: 'http://HOST:PORT/', captureScreenshot: true },
    },
];
function buildToolBindings(capabilities, modules, fixedPythonAvailable) {
    const available = new Set([...capabilities, ...modules].filter(item => item.available).map(item => item.id));
    if (fixedPythonAvailable)
        available.add('python.fixed');
    return TOOL_BINDINGS.map(spec => {
        const availableCapabilities = spec.anyBackend
            ? spec.backendCapabilities.filter(item => available.has(item))
            : spec.backendCapabilities.filter(item => available.has(item));
        const missingCapabilities = spec.anyBackend
            ? availableCapabilities.length > 0 ? [] : spec.backendCapabilities
            : spec.backendCapabilities.filter(item => !available.has(item));
        const availability = spec.backendCapabilities.length === 0
            ? 'ready'
            : availableCapabilities.length === 0
                ? 'missing_backend'
                : missingCapabilities.length > 0
                    ? 'partial'
                    : 'ready';
        return {
            tool: spec.tool,
            category: spec.category,
            kind: 'local',
            callable: true,
            purpose: spec.purpose,
            when: spec.when,
            backendCapabilities: spec.backendCapabilities,
            availableCapabilities,
            missingCapabilities,
            availability,
            exampleArgs: spec.exampleArgs,
            fallbackTool: spec.fallbackTool ?? null,
        };
    });
}
function isSecretPlaceholder(key, value) {
    return value.startsWith('REPLACE_WITH_')
        || key === 'TAVILY_API_KEY' && (value === 'TAVILY_API_KEY' || value === 'REPLACE_WITH_TAVILY_API_KEY');
}
//# sourceMappingURL=capabilities.js.map