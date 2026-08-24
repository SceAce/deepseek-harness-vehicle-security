import type { ResolvedWorkspaceFile } from '../paths.js'
import { runCommand, type CommandOptions } from '../process.js'
import { findCtfExecutable } from './environment.js'
import { commandRecord, emptyResult, type CtfToolResultBase } from './types.js'

export type SeccompDumpFormat = 'disasm' | 'raw' | 'inspect'

export interface SeccompProfileArgs {
  argv?: string[]
  format?: SeccompDumpFormat
  limit?: number
}

export interface SeccompProfileResult extends CtfToolResultBase {
  executable: string | null
  target: {
    path: string
    argv: string[]
  }
  dump: {
    format: SeccompDumpFormat
    limit: number
    rawOutput: string | null
    rules: string[]
    syscalls: string[]
  }
}

export async function profileSeccomp(
  file: ResolvedWorkspaceFile,
  args: SeccompProfileArgs = {},
  options: CommandOptions = {},
): Promise<SeccompProfileResult> {
  const base = emptyResult()
  const executable = await findCtfExecutable('seccomp-tools', options.cwd)
  const format = args.format ?? 'disasm'
  const limit = normalizeLimit(args.limit)
  const targetArgv = Array.isArray(args.argv) ? args.argv.slice(0, 32).map(String) : []
  const target = { path: file.relativePath, argv: targetArgv }
  const emptyDump = {
    format,
    limit,
    rawOutput: null,
    rules: [],
    syscalls: [],
  }

  if (!executable) {
    base.status = 'missing_capability'
    base.limitations.push('seccomp-tools is not installed.')
    base.nextActions.push({
      tool: 'ctf_tool_setup',
      args: { target: 'seccomp_tools' },
      reason: 'Install seccomp-tools before dumping the challenge seccomp filter.',
    })
    return {
      ...base,
      executable: null,
      target,
      dump: emptyDump,
    }
  }

  const argv = buildDumpArgv(file.path, targetArgv, format, limit)
  const capture = await runCommand(executable, argv, {
    ...options,
    maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000),
  })
  const rawOutput = [capture.stdout, capture.stderr].filter(Boolean).join('\n').trim() || null
  const rules = parseRules(rawOutput)
  const syscalls = parseSyscalls(rules)
  base.commands.push(commandRecord(executable, argv, capture, options.cwd))
  base.observations.push(`seccomp-tools executed against ${file.relativePath} with format=${format}, limit=${limit}.`)
  if (capture.ok) {
    base.observations.push(`seccomp dump returned ${rules.length} rule lines and ${syscalls.length} syscall names.`)
  } else {
    base.status = 'failed'
    base.limitations.push(`seccomp-tools exited with ${capture.exitCode ?? 'no status'}: ${capture.error ?? capture.stderr.trim()}`)
    if (/operation not permitted|ptrace|permission denied/i.test(`${capture.error ?? ''}\n${capture.stderr}`)) {
      base.limitations.push('The host denied ptrace-based seccomp inspection; run the same command in a session with ptrace permission.')
    }
  }
  base.nextActions.push({
    tool: 'ctf_pwn_profile',
    args: { path: file.relativePath },
    reason: 'Correlate seccomp rules with imported prctl/syscall paths and the binary protections.',
  })
  return {
    ...base,
    status: capture.ok ? 'ok' : 'failed',
    executable,
    target,
    dump: {
      format,
      limit,
      rawOutput,
      rules,
      syscalls,
    },
  }
}

function buildDumpArgv(
  targetPath: string,
  targetArgv: string[],
  format: SeccompDumpFormat,
  limit: number,
): string[] {
  const options = ['dump', '--format', format, '--limit', String(limit)]
  if (targetArgv.length === 0) return [...options, '--', targetPath]
  const command = [targetPath, ...targetArgv].map(shellQuote).join(' ')
  return [...options, '--sh-exec', `exec -- ${command}`]
}

function parseRules(rawOutput: string | null): string[] {
  if (!rawOutput) return []
  return rawOutput
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line.length > 0 && !/^seccompTools Version/i.test(line))
}

function parseSyscalls(rules: string[]): string[] {
  const names = new Set<string>()
  for (const rule of rules) {
    for (const match of rule.matchAll(/\b(?:allow|deny|kill|trap|errno|trace|notify)\s*\(?\s*([a-z_][a-z0-9_]*)/gi)) {
      if (match[1]) names.add(match[1].toLowerCase())
    }
    for (const match of rule.matchAll(/\b([a-z_][a-z0-9_]*)\s*\(/gi)) {
      if (match[1] && !['if', 'else', 'return'].includes(match[1].toLowerCase())) names.add(match[1].toLowerCase())
    }
  }
  return [...names].sort()
}

function normalizeLimit(value: number | undefined): number {
  if (value === undefined) return 1
  if (!Number.isInteger(value) || value < 1 || value > 32) throw new Error('limit must be an integer in range 1..32')
  return value
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`
}
