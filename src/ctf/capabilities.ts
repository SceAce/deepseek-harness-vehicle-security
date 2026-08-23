import { discoverCtfPython, findCtfExecutable } from './environment.js'
import { runCommand, type CommandOptions } from '../process.js'
import { discoverCtfMcpConfiguration } from './mcp.js'
import { commandRecord, type ToolInvocationRecord } from './types.js'

export type CtfCapabilityCategory = 'core' | 're' | 'pwn' | 'crypto' | 'misc' | 'web'

export interface CapabilityProbe {
  id: string
  category: CtfCapabilityCategory
  executable: string
  args: readonly string[]
  operations: string[]
  features?: string[]
}

export interface CtfCapability {
  id: string
  category: CtfCapabilityCategory
  executable: string
  available: boolean
  path: string | null
  version: string | null
  operations: string[]
  features: string[]
}

export interface PythonModuleProbe {
  module: string
  importName: string
  category: CtfCapabilityCategory
  operations: string[]
}

export interface CtfToolAuditResult {
  schemaVersion: '1.0'
  available: number
  missing: number
  capabilities: CtfCapability[]
  python: {
    executable: string | null
    source: string | null
    venv: string | null
    bin: string | null
    version: string | null
    modules: CtfCapability[]
  }
  mcp: CtfMcpCapability[]
  commands: ToolInvocationRecord[]
  recommendations: string[]
}

export interface CtfMcpCapability {
  id: string
  category: CtfCapabilityCategory
  configured: boolean
  configSource: string | null
  command: string | null
  operations: string[]
  limitation: string | null
}

const PROBES: CapabilityProbe[] = [
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
]

const PYTHON_MODULES: PythonModuleProbe[] = [
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
  { module: 'beautifulsoup4', importName: 'bs4', category: 'web', operations: ['HTML parsing'] },
  { module: 'playwright', importName: 'playwright', category: 'web', operations: ['browser automation fallback'] },
]

export async function auditCtfTools(options: CommandOptions = {}): Promise<CtfToolAuditResult> {
  const capabilities: CtfCapability[] = []
  const commands: ToolInvocationRecord[] = []
  const python = await probePython(options)

  for (const probe of PROBES) {
    const resolved = await findCtfExecutable(probe.executable, options.cwd)
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
      })
      continue
    }

    let version: string | null = null
    if (probe.args.length > 0) {
      const result = await runCommand(resolved, probe.args, options)
      commands.push(commandRecord(resolved, probe.args, result, options.cwd))
      version = firstLine(result.stdout, result.stderr)
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
    })
  }

  const pwndbg = await probePwndbg(options)
  const ida = await probeIdaCli()
  const mcp = await probeMcpConfiguration()
  capabilities.push(pwndbg, ida)
  return {
    schemaVersion: '1.0',
    available: capabilities.filter(item => item.available).length + python.modules.filter(item => item.available).length,
    missing: capabilities.filter(item => !item.available).length + python.modules.filter(item => !item.available).length,
    capabilities,
    python: {
      executable: python.executable,
      source: python.source,
      venv: python.venv,
      bin: python.bin,
      version: python.version,
      modules: python.modules,
    },
    mcp,
    commands: [...commands, ...python.commands, ...pwndbg.commands],
    recommendations: recommendations(capabilities, python.modules, mcp),
  }
}

export function hasCapability(audit: CtfToolAuditResult, id: string): boolean {
  return [...audit.capabilities, ...audit.python.modules].some(item => item.id === id && item.available)
}

async function probePython(options: CommandOptions): Promise<{
  executable: string | null
  source: string | null
  venv: string | null
  bin: string | null
  version: string | null
  modules: CtfCapability[]
  commands: ToolInvocationRecord[]
}> {
  const environment = await discoverCtfPython(options.cwd)
  const commands: ToolInvocationRecord[] = []
  if (!environment.executable) {
    return {
      executable: null,
      source: null,
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
    }
  }

  const versionResult = await runCommand(environment.executable, ['--version'], options)
  commands.push(commandRecord(environment.executable, ['--version'], versionResult, options.cwd))
  const modules: CtfCapability[] = []
  for (const moduleProbe of PYTHON_MODULES) {
    const argv = ['-c', `import ${moduleProbe.importName}; print("ok")`]
    const result = await runCommand(environment.executable, argv, options)
    commands.push(commandRecord(environment.executable, argv, result, options.cwd))
    modules.push({
      id: `python.${moduleProbe.module}`,
      category: moduleProbe.category,
      executable: moduleProbe.importName,
      available: result.ok,
      path: result.ok ? environment.executable : null,
      version: result.ok ? 'import ok' : null,
      operations: moduleProbe.operations,
      features: [],
    })
  }

  return {
    executable: environment.executable,
    source: environment.source,
    venv: environment.venv,
    bin: environment.bin,
    version: firstLine(versionResult.stdout, versionResult.stderr),
    modules,
    commands,
  }
}

async function probePwndbg(options: CommandOptions): Promise<CtfCapability & { commands: ToolInvocationRecord[] }> {
  const gdb = await findCtfExecutable('gdb', options.cwd)
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
    }
  }
  const argv = ['-q', '-batch', '-ex', 'python import pwndbg; print("pwndbg-loaded")']
  const result = await runCommand(gdb, argv, options)
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
  }
}

async function probeIdaCli(): Promise<CtfCapability> {
  const candidates = ['idat64', 'idat', 'ida64', 'ida']
  for (const candidate of candidates) {
    const executable = await findCtfExecutable(candidate)
    if (!executable) continue
    return {
      id: 're.ida_cli',
      category: 're',
      executable: candidate,
      available: true,
      path: executable,
      version: 'CLI detected',
      operations: ['IDAPython script execution', 'batch analysis'],
      features: ['idapython', 'batch'],
    }
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
  }
}

async function probeMcpConfiguration(): Promise<CtfMcpCapability[]> {
  const discovery = await discoverCtfMcpConfiguration()

  const definitions = [
    { id: 'mcp.ida_pro', category: 're' as const, names: ['ida-pro', 'ida', 'ida-pro-mcp'], operations: ['IDAPython script dispatch', 'functions', 'xrefs', 'decompiler queries'] },
    { id: 'mcp.r2', category: 're' as const, names: ['r2', 'radare2', 'radare2-mcp'], operations: ['r2 command dispatch', 'analysis JSON', 'xrefs', 'debugger queries'] },
    { id: 'mcp.chrome', category: 'web' as const, names: ['mcp-chrome', 'chrome-mcp', 'chrome', 'chrome-devtools', 'chrome-devtools-mcp'], operations: ['browser navigation', 'DOM', 'network', 'console', 'screenshots', 'tabs', 'cookies'] },
    { id: 'mcp.gdb_pwndbg', category: 'pwn' as const, names: ['gdb-pwndbg', 'pwndbg', 'gdb-mcp'], operations: ['breakpoints', 'registers', 'memory', 'pwndbg context'] },
    { id: 'mcp.tavily', category: 'web' as const, names: ['tavily', 'tavily-mcp', 'tavily-remote-mcp'], operations: ['CVE search', 'vulnerability version lookup', 'web search', 'page extraction'] },
  ]

  return definitions.map(definition => {
    const matchedName = definition.names.find(name => isConfiguredServer(discovery.configuredServers[name]))
    const envKey = `DSH_CTF_${definition.id.slice(4).toUpperCase().replaceAll('.', '_')}_MCP`
    const envValue = process.env[envKey]?.trim()
    const envConfigured = Boolean(envValue)
      || definition.id === 'mcp.tavily' && Boolean(process.env.TAVILY_API_KEY?.trim())
      || definition.id === 'mcp.chrome' && Boolean(process.env.DSH_CTF_CHROME_MCP_URL?.trim())
    const source = matchedName
      ? `${discovery.serverSources[matchedName] ?? 'MCP config'}:${matchedName}`
      : envValue
        ? envKey
        : definition.id === 'mcp.tavily' && process.env.TAVILY_API_KEY?.trim()
          ? 'TAVILY_API_KEY'
          : definition.id === 'mcp.chrome' && process.env.DSH_CTF_CHROME_MCP_URL?.trim()
            ? 'DSH_CTF_CHROME_MCP_URL'
            : null
    return {
      id: definition.id,
      category: definition.category,
      configured: Boolean(matchedName || envConfigured),
      configSource: source,
      command: envValue || (matchedName ? 'configured in MCP JSON' : null),
      operations: definition.operations,
      limitation: matchedName || envConfigured ? null : 'MCP server must be installed and configured before DSH/Codex can use its external operations.',
    }
  })
}

function isConfiguredServer(value: unknown): boolean {
  if (value === undefined || value === null) return false
  if (typeof value === 'string') return value.trim() !== '' && !value.startsWith('REPLACE_WITH_')
  if (typeof value !== 'object') return false
  const command = (value as { command?: unknown }).command
  const url = (value as { url?: unknown }).url
  if (
    (typeof command !== 'string' || command.trim() === '' || command.startsWith('REPLACE_WITH_'))
    && (typeof url !== 'string' || url.trim() === '' || url.startsWith('REPLACE_WITH_'))
  ) return false
  const args = (value as { args?: unknown }).args
  if (Array.isArray(args) && args.some(item => typeof item === 'string' && item.startsWith('REPLACE_WITH_'))) return false
  const env = (value as { env?: unknown }).env
  if (env && typeof env === 'object') {
    for (const [key, item] of Object.entries(env)) {
      if (typeof item !== 'string' || item.trim() === '' || isSecretPlaceholder(key, item)) return false
    }
  }
  return true
}

function firstLine(stdout: string, stderr: string): string | null {
  return `${stdout}\n${stderr}`.split(/\r?\n/).map(line => line.trim()).find(Boolean) ?? null
}

function recommendations(capabilities: CtfCapability[], modules: CtfCapability[], mcp: CtfMcpCapability[]): string[] {
  const available = new Set([...capabilities, ...modules].filter(item => item.available).map(item => item.id))
  const result: string[] = []
  if (!available.has('core.file')) result.push('Install file for reliable artifact type detection.')
  if (!available.has('re.readelf')) result.push('Install binutils for ELF analysis.')
  if (!available.has('re.r2')) result.push('Install radare2 for fast headless RE queries and JSON output.')
  if (!available.has('pwn.gdb')) result.push('Install gdb for pwn runtime probes.')
  if (!available.has('pwn.pwndbg')) result.push('Configure pwndbg inside gdb for context, vmmap, heap, and register views.')
  if (!available.has('pwn.checksec')) result.push('Install checksec for a concise mitigation summary.')
  if (!available.has('pwn.pwninit')) result.push('Install or expose pwninit for deterministic loader/libc selection, patching, backup, and restore.')
  if (!available.has('python.pwntools')) result.push('Install pwntools for pwn process automation.')
  if (!available.has('pwn.ropgadget') && !available.has('pwn.ropper')) result.push('Install ROPgadget or ropper for gadget enumeration.')
  if (!available.has('re.ida_cli') && !mcp.some(item => item.id === 'mcp.ida_pro' && item.configured)) {
    result.push('IDA CLI is optional: use the configured IDA MCP for IDAPython/decompiler work, or expose idat64/idat only for batch fallback.')
  }
  if (!available.has('re.patchelf')) result.push('Install patchelf for ELF interpreter and RPATH inspection.')
  if (!available.has('re.strace') && !available.has('re.ltrace')) result.push('Install strace or ltrace for runtime syscall/library tracing.')
  if (!available.has('web.curl') && !available.has('python.requests')) result.push('Install curl or requests for web challenge baselines.')
  if (
    !available.has('web.chromium')
    && !available.has('web.mcp_chrome_bridge')
    && !mcp.some(item => item.id === 'mcp.chrome' && item.configured)
  ) {
    result.push('Install Chromium/Chrome for the local headless fallback, or install/configure the mcp-chrome browser bridge.')
  } else if (!mcp.some(item => item.id === 'mcp.chrome' && item.configured)) {
    result.push('Configure the detected mcp-chrome bridge before interactive browser operations.')
  }
  if (!available.has('misc.tshark')) result.push('Install tshark for PCAP triage.')
  if (!available.has('web.mitmproxy')) result.push('Install mitmproxy for live HTTP(S) capture; tshark remains the offline PCAP tool.')
  if (!available.has('web.ffuf') && !available.has('web.feroxbuster')) result.push('Install ffuf or feroxbuster for controlled Web content discovery.')
  if (!mcp.some(item => item.id === 'mcp.tavily' && item.configured)) {
    result.push('When CVE or version research is needed, provide TAVILY_API_KEY to ctf_mcp_configure; the key must not be pasted into logs or JSON shown to the model.')
  }
  if (!available.has('crypto.sage') && !available.has('python.z3') && !available.has('python.sympy')) {
    result.push('Install Sage, z3, or SymPy for crypto challenge solving.')
  }
  for (const item of mcp.filter(item => !item.configured)) {
    if (item.id === 'mcp.tavily' || item.id === 'mcp.chrome') continue
    result.push(`Configure ${item.id} through ctf_mcp_configure or the host MCP client before using its external server.`)
  }
  return result
}

function isSecretPlaceholder(key: string, value: string): boolean {
  return value.startsWith('REPLACE_WITH_')
    || key === 'TAVILY_API_KEY' && (value === 'TAVILY_API_KEY' || value === 'REPLACE_WITH_TAVILY_API_KEY')
}
