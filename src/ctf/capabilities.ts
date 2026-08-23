import { readFile } from 'node:fs/promises'
import { findExecutable } from '../paths.js'
import { runCommand, type CommandOptions } from '../process.js'
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
  { id: 'crypto.sage', category: 'crypto', executable: 'sage', args: ['--version'], operations: ['number theory and symbolic math'] },
  { id: 'crypto.gp', category: 'crypto', executable: 'gp', args: ['--version'], operations: ['PARI/GP number theory'] },
  { id: 'web.curl', category: 'web', executable: 'curl', args: ['--version'], operations: ['HTTP request baseline'] },
  { id: 'web.httpx', category: 'web', executable: 'httpx', args: ['--version'], operations: ['HTTP probing'] },
  { id: 'web.sqlmap', category: 'web', executable: 'sqlmap', args: ['--version'], operations: ['SQL injection verification on local challenge targets'] },
  { id: 'web.chromium', category: 'web', executable: 'chromium', args: ['--version'], operations: ['browser-backed observation'] },
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
]

export async function auditCtfTools(options: CommandOptions = {}): Promise<CtfToolAuditResult> {
  const capabilities: CtfCapability[] = []
  const commands: ToolInvocationRecord[] = []

  for (const probe of PROBES) {
    const resolved = await findExecutable(probe.executable)
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

  const python = await probePython(options)
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
  version: string | null
  modules: CtfCapability[]
  commands: ToolInvocationRecord[]
}> {
  const python = await findExecutable('python3') ?? await findExecutable('python')
  const commands: ToolInvocationRecord[] = []
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
    }
  }

  const versionResult = await runCommand(python, ['--version'], options)
  commands.push(commandRecord(python, ['--version'], versionResult, options.cwd))
  const modules: CtfCapability[] = []
  for (const moduleProbe of PYTHON_MODULES) {
    const result = await runCommand(python, ['-c', `import ${moduleProbe.importName}; print("ok")`], options)
    commands.push(commandRecord(python, ['-c', `import ${moduleProbe.importName}; print("ok")`], result, options.cwd))
    modules.push({
      id: `python.${moduleProbe.module}`,
      category: moduleProbe.category,
      executable: moduleProbe.importName,
      available: result.ok,
      path: result.ok ? python : null,
      version: result.ok ? 'import ok' : null,
      operations: moduleProbe.operations,
      features: [],
    })
  }

  return {
    executable: python,
    version: firstLine(versionResult.stdout, versionResult.stderr),
    modules,
    commands,
  }
}

async function probePwndbg(options: CommandOptions): Promise<CtfCapability & { commands: ToolInvocationRecord[] }> {
  const gdb = await findExecutable('gdb')
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
    const executable = await findExecutable(candidate)
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
  const configPath = process.env.DSH_CTF_MCP_CONFIG?.trim() || process.env.CTF_MCP_CONFIG?.trim()
  let configuredServers: Record<string, unknown> = {}
  if (configPath) {
    try {
      const parsed = JSON.parse(await readFile(configPath, 'utf8')) as { mcpServers?: Record<string, unknown> }
      configuredServers = parsed.mcpServers ?? {}
    } catch {
      configuredServers = {}
    }
  }

  const definitions = [
    { id: 'mcp.ida_pro', category: 're' as const, names: ['ida-pro', 'ida', 'ida-pro-mcp'], operations: ['IDAPython script dispatch', 'functions', 'xrefs', 'decompiler queries'] },
    { id: 'mcp.r2', category: 're' as const, names: ['r2', 'radare2', 'radare2-mcp'], operations: ['r2 command dispatch', 'analysis JSON', 'xrefs', 'debugger queries'] },
    { id: 'mcp.chrome_devtools', category: 'web' as const, names: ['chrome-devtools', 'chrome-devtools-mcp'], operations: ['browser navigation', 'DOM', 'network', 'console', 'screenshots'] },
    { id: 'mcp.gdb_pwndbg', category: 'pwn' as const, names: ['gdb-pwndbg', 'pwndbg', 'gdb-mcp'], operations: ['breakpoints', 'registers', 'memory', 'pwndbg context'] },
  ]

  return definitions.map(definition => {
    const matchedName = definition.names.find(name => isConfiguredServer(configuredServers[name]))
    const envKey = `DSH_CTF_${definition.id.slice(4).toUpperCase().replaceAll('.', '_')}_MCP`
    const envValue = process.env[envKey]?.trim()
    return {
      id: definition.id,
      category: definition.category,
      configured: Boolean(matchedName || envValue),
      configSource: matchedName ? `${configPath ?? 'MCP config'}:${matchedName}` : envValue ? envKey : null,
      command: envValue || (matchedName ? 'configured in MCP JSON' : null),
      operations: definition.operations,
      limitation: matchedName || envValue ? null : 'MCP server must be installed and configured by the human before DSH/Codex can use it.',
    }
  })
}

function isConfiguredServer(value: unknown): boolean {
  if (value === undefined || value === null) return false
  if (typeof value === 'string') return value.trim() !== '' && !value.startsWith('REPLACE_WITH_')
  if (typeof value !== 'object') return false
  const command = (value as { command?: unknown }).command
  if (typeof command !== 'string' || command.trim() === '' || command.startsWith('REPLACE_WITH_')) return false
  const args = (value as { args?: unknown }).args
  if (Array.isArray(args) && args.some(item => typeof item === 'string' && item.startsWith('REPLACE_WITH_'))) return false
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
  if (!available.has('python.pwntools')) result.push('Install pwntools for pwn process automation.')
  if (!available.has('re.ida_cli')) result.push('Expose IDA idat64/idat on PATH for IDAPython batch scripts.')
  if (!available.has('web.curl') && !available.has('python.requests')) result.push('Install curl or requests for web challenge baselines.')
  if (!available.has('misc.tshark')) result.push('Install tshark for PCAP triage.')
  if (!available.has('web.mitmproxy')) result.push('Install mitmproxy for live HTTP(S) capture; tshark remains the offline PCAP tool.')
  if (!available.has('crypto.sage') && !available.has('python.z3') && !available.has('python.sympy')) {
    result.push('Install Sage, z3, or SymPy for crypto challenge solving.')
  }
  for (const item of mcp.filter(item => !item.configured)) {
    result.push(`Configure ${item.id} through DSH_CTF_MCP_CONFIG or the host MCP client before using its external server.`)
  }
  return result
}
