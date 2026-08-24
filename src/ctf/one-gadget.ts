import { readdir, stat } from 'node:fs/promises'
import path from 'node:path'
import { resolveWorkspaceFile, type ResolvedWorkspaceFile } from '../paths.js'
import { ctfCommandOptions, findCtfExecutable, isRubyGemBackendFailure } from './environment.js'
import { runCommand, type CommandOptions } from '../process.js'
import { commandRecord, emptyResult, type CtfToolResultBase } from './types.js'

export interface OneGadgetArgs {
  libcPath?: string
  level?: number
  near?: string
  raw?: boolean
  maxResults?: number
}

export interface OneGadgetResult extends CtfToolResultBase {
  executable: string | null
  anchor: string
  target: {
    path: string | null
    source: 'explicit' | 'anchor' | 'sibling' | 'none'
  }
  options: {
    level: number
    near: string | null
    raw: boolean
    maxResults: number
  }
  rawOutput: string | null
  gadgets: Array<{
    offset: string
    invocation: string | null
    constraints: string[]
  }>
}

export interface OneGadgetOptions extends CommandOptions {
  maxFileBytes?: number
}

export async function searchOneGadgets(
  file: ResolvedWorkspaceFile,
  args: OneGadgetArgs = {},
  options: OneGadgetOptions = {},
): Promise<OneGadgetResult> {
  const base = emptyResult()
  const level = normalizeInteger(args.level, 0, 0, 5)
  const maxResults = normalizeInteger(args.maxResults, 80, 1, 500)
  const near = normalizeNear(args.near)
  const raw = args.raw === true
  const resolved = await resolveLibcTarget(file, args.libcPath, options.maxFileBytes ?? 128 * 1024 * 1024)
  const empty = {
    executable: null,
    anchor: file.relativePath,
    target: resolved,
    options: { level, near, raw, maxResults },
    rawOutput: null,
    gadgets: [],
  }

  if (!resolved.path) {
    base.status = 'missing_capability'
    base.limitations.push('No libc artifact was found. Pass libcPath or keep libc-*.so beside the challenge binary.')
    base.nextActions.push({
      tool: 'ctf_pwninit',
      args: { path: file.relativePath, mode: 'prepare' },
      reason: 'Initialize the challenge first so a matching libc path can be selected or reported.',
    })
    return { ...base, ...empty }
  }

  const executable = await findCtfExecutable('one_gadget', options.cwd)
  if (!executable) {
    base.status = 'missing_capability'
    base.limitations.push('one_gadget is not installed or is not visible in the CTF tool search path.')
    base.nextActions.push({
      tool: 'ctf_tool_setup',
      args: { target: 'one_gadget' },
      reason: 'Install the Ruby one_gadget gem before searching libc gadgets.',
    })
    return { ...base, ...empty, target: resolved }
  }

  const argv = [
    '--level', String(level),
    ...(near ? ['--near', near] : []),
    ...(raw ? ['--raw'] : []),
    '--',
    resolved.path,
  ]
  const capture = await runCommand(executable, argv, {
    ...ctfCommandOptions(executable, options),
    cwd: file.root,
    maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000),
  })
  const rawOutput = [capture.stdout, capture.stderr].filter(Boolean).join('\n').trim() || null
  const gadgets = parseGadgets(rawOutput, maxResults)
  base.commands.push(commandRecord(executable, argv, capture, file.root))
  base.observations.push(`one_gadget searched ${resolved.path} at level=${level}${near ? ` near=${near}` : ''}.`)
  if (capture.ok) {
    base.observations.push(`one_gadget returned ${gadgets.length} candidate gadgets.`)
  } else {
    base.status = isRubyGemBackendFailure(capture) ? 'missing_capability' : 'failed'
    if (base.status === 'missing_capability') {
      base.limitations.push('The one_gadget wrapper was found, but its Ruby gem backend is missing from the active RubyGems environment.')
      base.nextActions.push({
        tool: 'ctf_tool_setup',
        args: { target: 'one_gadget' },
        reason: 'Restore the one_gadget Ruby gem and verify the wrapper with the same GEM_HOME/GEM_PATH.',
      })
    } else {
      base.limitations.push(`one_gadget exited with ${capture.exitCode ?? 'no status'}: ${capture.error ?? capture.stderr.trim()}`)
    }
  }
  base.nextActions.push({
    tool: 'ctf_pwn_gdb_probe',
    args: { path: file.relativePath },
    reason: 'Validate the selected gadget constraints against the actual libc base and register state.',
  })
  return {
    ...base,
    status: capture.ok ? 'ok' : base.status,
    executable,
    anchor: file.relativePath,
    target: resolved,
    options: { level, near, raw, maxResults },
    rawOutput,
    gadgets,
  }
}

async function resolveLibcTarget(
  file: ResolvedWorkspaceFile,
  libcPath: string | undefined,
  maxFileBytes: number,
): Promise<OneGadgetResult['target']> {
  if (libcPath?.trim()) {
    const target = await resolveWorkspaceFile(file.root, libcPath, maxFileBytes)
    return { path: target.path, source: 'explicit' }
  }

  if (isLibcName(path.basename(file.path))) {
    return { path: file.path, source: 'anchor' }
  }

  const entries = await readdir(path.dirname(file.path))
  const candidates: string[] = []
  for (const entry of entries.sort()) {
    if (!/^libc(?:\.so(?:\..*)?|-[^/]+\.so(?:\..*)?)$/.test(entry)) continue
    const candidate = path.join(path.dirname(file.path), entry)
    try {
      if ((await stat(candidate)).isFile()) candidates.push(candidate)
    } catch {
      // Ignore files removed during discovery.
    }
  }
  return candidates[0]
    ? { path: candidates[0], source: 'sibling' }
    : { path: null, source: 'none' }
}

function parseGadgets(
  rawOutput: string | null,
  maxResults: number,
): OneGadgetResult['gadgets'] {
  if (!rawOutput) return []
  const gadgets: OneGadgetResult['gadgets'] = []
  let current: OneGadgetResult['gadgets'][number] | null = null
  let inConstraints = false

  for (const rawLine of rawOutput.split(/\r?\n/)) {
    const line = rawLine.trim()
    const match = line.match(/^(0x[0-9a-f]+)\s*(.*)$/i)
    if (match) {
      if (current) gadgets.push(current)
      current = {
        offset: match[1],
        invocation: match[2].trim() || null,
        constraints: [],
      }
      inConstraints = false
      if (gadgets.length >= maxResults) break
      continue
    }
    if (!current) continue
    if (/^constraints:?\s*$/i.test(line)) {
      inConstraints = true
      continue
    }
    if (inConstraints && line) {
      current.constraints.push(line.replace(/^#\s*/, '').trim())
    }
  }
  if (current && gadgets.length < maxResults) gadgets.push(current)
  return gadgets
}

function isLibcName(name: string): boolean {
  return /^libc(?:\.so(?:\..*)?|-[^/]+\.so(?:\..*)?)$/.test(name)
}

function normalizeNear(value: string | undefined): string | null {
  if (value === undefined) return null
  const normalized = value.trim()
  if (normalized.length === 0 || normalized.length > 200) throw new Error('near must contain 1..200 characters when provided')
  return normalized
}

function normalizeInteger(value: number | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined) return fallback
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`integer must be in range ${min}..${max}`)
  }
  return value
}
