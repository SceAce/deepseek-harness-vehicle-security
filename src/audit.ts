import { findExecutable } from './paths.js'
import { runCommand, type CommandOptions } from './process.js'

const PROBES: ReadonlyArray<readonly [string, readonly string[]]> = [
  ['candump', ['-h']],
  ['binwalk', ['--version']],
  ['gdb', ['--version']],
  ['qemu-system-arm', ['--version']],
  ['r2', ['-v']],
  ['tshark', ['--version']],
  ['jadx', ['--version']],
  ['adb', ['version']],
  ['frida', ['--version']],
  ['mosquitto_pub', ['--help']],
  ['urh', ['--version']],
  ['hackrf_info', ['--version']],
  ['proxmark3', ['--version']],
  ['pulseview', ['--version']],
]

export interface ToolAuditRow {
  name: string
  available: boolean
  path: string | null
  version: string | null
}

export interface ToolAuditResult {
  available: number
  missing: number
  tools: ToolAuditRow[]
}

export async function auditTools(options: CommandOptions = {}): Promise<ToolAuditResult> {
  const rows: ToolAuditRow[] = []
  for (const [toolName, args] of PROBES) {
    const executable = await findExecutable(toolName)
    if (!executable) {
      rows.push({ name: toolName, available: false, path: null, version: null })
      continue
    }
    const result = await runCommand(executable, args, options)
    const firstLine = `${result.stdout}\n${result.stderr}`.split(/\r?\n/).find(Boolean) ?? null
    rows.push({ name: toolName, available: true, path: executable, version: firstLine })
  }

  rows.push(await probePwndbg(options))
  return {
    available: rows.filter(row => row.available).length,
    missing: rows.filter(row => !row.available).length,
    tools: rows,
  }
}

async function probePwndbg(options: CommandOptions): Promise<ToolAuditRow> {
  const gdb = await findExecutable('gdb')
  if (!gdb) return { name: 'pwndbg', available: false, path: null, version: null }
  const script = 'import pwndbg; print(getattr(pwndbg, "__version__", "loaded"))'
  const result = await runCommand(gdb, ['-q', '-batch', '-ex', `pi ${script}`], options)
  const output = `${result.stdout}\n${result.stderr}`
  const available = result.ok && !output.includes('ModuleNotFoundError')
  return {
    name: 'pwndbg',
    available,
    path: available ? gdb : null,
    version: available ? output.split(/\r?\n/).find(Boolean) ?? 'loaded' : null,
  }
}
