import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { readdir, realpath, stat } from 'node:fs/promises'
import path from 'node:path'
import { assertInside, resolveWorkspaceFile, type ResolvedWorkspaceFile } from '../paths.js'
import { findCtfExecutable } from './environment.js'
import { runCommand, type CommandOptions } from '../process.js'
import { commandRecord, emptyResult, type CtfToolResultBase } from './types.js'

export type PwninitMode = 'prepare' | 'doctor' | 'restore' | 'list_backups'

export interface PwninitArgs {
  mode?: PwninitMode
  libcPath?: string
  ldPath?: string
  dependencyDir?: string
  libcVersion?: string
  libcIndex?: number
  onlyLibc?: boolean
  onlyInit?: boolean
  generateExp?: boolean
  forceExp?: boolean
  debug?: boolean
}

export interface PwninitOptions extends CommandOptions {
  maxFileBytes?: number
}

export interface CtfPwninitResult extends CtfToolResultBase {
  pwninit: {
    mode: PwninitMode
    executable: string | null
    binary: string
    command: string[]
    selectedLibc: string | null
    selectedLd: string | null
    initializationOnly: boolean
    beforeSha256: string | null
    afterSha256: string | null
    changed: boolean
  }
}

export async function runPwninit(
  file: ResolvedWorkspaceFile,
  args: PwninitArgs = {},
  options: PwninitOptions = {},
): Promise<CtfPwninitResult> {
  const base = emptyResult()
  const mode = args.mode ?? 'prepare'
  const beforeSha256 = await hashFile(file.path)
  const executable = await findCtfExecutable('pwninit', options.cwd)
  const selected = await resolveRuntimeSources(file, args, options.maxFileBytes ?? 128 * 1024 * 1024)
  const initializationOnly = mode === 'prepare' && !args.onlyInit && !selected.source
  const pwninit = {
    mode,
    executable,
    binary: file.relativePath,
    command: [] as string[],
    selectedLibc: selected.libc ? relativePath(file.root, selected.libc) : null,
    selectedLd: selected.ld ? relativePath(file.root, selected.ld) : null,
    initializationOnly,
    beforeSha256,
    afterSha256: beforeSha256,
    changed: false,
  }

  if (!executable) {
    base.status = 'missing_capability'
    base.limitations.push('pwninit is not installed or is not visible in the CTF tool search path.')
    base.nextActions.push({ tool: 'ctf_tool_audit', args: {}, reason: 'Refresh the local Pwn capability inventory.' })
    return { ...base, pwninit }
  }

  const effectiveArgs = initializationOnly ? { ...args, onlyInit: true } : args
  const argv = buildPwninitArgs(mode, file.path, selected, effectiveArgs)
  pwninit.command = [executable, ...argv]
  const capture = await runCommand(executable, argv, {
    ...options,
    cwd: file.root,
    maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000),
  })
  base.commands.push(commandRecord(executable, argv, capture, file.root))
  base.observations.push(`pwninit mode=${mode} binary=${file.relativePath}`)
  if (initializationOnly) {
    base.observations.push('No matching libc/ld source was found; pwninit ran its non-interactive initialization step first.')
    base.limitations.push('No libc source was selected, so the binary was initialized but not patched. Provide libcPath, ldPath, dependencyDir, or libcVersion for runtime switching.')
  }
  if (selected.libc) base.observations.push(`selected libc=${relativePath(file.root, selected.libc)}`)
  if (selected.ld) base.observations.push(`selected ld=${relativePath(file.root, selected.ld)}`)
  if (capture.ok) {
    base.observations.push('pwninit completed without a non-zero exit status.')
  } else {
    base.status = 'failed'
    base.limitations.push(`pwninit exited with ${capture.exitCode ?? 'no status'}: ${capture.error ?? capture.stderr.trim()}`)
  }

  const afterSha256 = await hashFile(file.path)
  pwninit.afterSha256 = afterSha256
  pwninit.changed = beforeSha256 !== afterSha256
  if (pwninit.changed) {
    base.observations.push(`binary hash changed from ${beforeSha256} to ${afterSha256}.`)
  } else {
    base.observations.push('binary hash did not change.')
  }

  base.artifacts.push({
    kind: 'pwninit',
    mode,
    binary: file.relativePath,
    libc: pwninit.selectedLibc,
    ld: pwninit.selectedLd,
  })
  if (mode === 'prepare' && capture.ok) {
    base.nextActions.push({
      tool: 'ctf_pwn_profile',
      args: { path: file.relativePath },
      reason: initializationOnly
        ? 'Profile the initialized binary while the matching libc/ld source is still unresolved.'
        : 'Re-profile the binary after pwninit selected the intended loader and libc.',
    })
    if (!initializationOnly) {
      base.nextActions.push({
        tool: 'ctf_pwn_gdb_probe',
        args: { path: file.relativePath },
        reason: 'Probe the challenge again after pwninit selected the intended loader and libc.',
      })
      base.nextActions.push({
        tool: 'ctf_pwn_debug_probe',
        args: { path: file.relativePath, breakAt: 'main' },
        reason: 'Inspect main and input handling under the patched runtime.',
      })
    }
  } else if (mode === 'restore' && capture.ok) {
    base.nextActions.push({
      tool: 'ctf_pwn_profile',
      args: { path: file.relativePath },
      reason: 'Re-profile the restored original binary before further runtime work.',
    })
  }
  return { ...base, status: capture.ok ? 'ok' : 'failed', pwninit }
}

interface RuntimeSources {
  source: boolean
  libc: string | null
  ld: string | null
  dependencyDir: string | null
  libcVersion: string | null
  libcIndex: number | null
}

async function resolveRuntimeSources(
  file: ResolvedWorkspaceFile,
  args: PwninitArgs,
  maxFileBytes: number,
): Promise<RuntimeSources> {
  const sourceKinds = [
    Boolean(args.dependencyDir),
    Boolean(args.libcPath),
    Boolean(args.ldPath),
    Boolean(args.libcVersion),
  ].filter(Boolean).length
  if (sourceKinds > 2 || args.dependencyDir && (args.libcPath || args.ldPath || args.libcVersion)) {
    throw new Error('Choose one libc source: dependencyDir, libcPath/ldPath, or libcVersion.')
  }
  if (args.libcIndex !== undefined && (!Number.isInteger(args.libcIndex) || args.libcIndex < 1)) {
    throw new Error('libcIndex must be a positive integer.')
  }

  let libc = args.libcPath
    ? (await resolveWorkspaceFile(file.root, args.libcPath, maxFileBytes)).path
    : null
  let ld = args.ldPath
    ? (await resolveWorkspaceFile(file.root, args.ldPath, maxFileBytes)).path
    : null
  const dependencyDir = args.dependencyDir ? await resolveWorkspaceDirectory(file.root, args.dependencyDir) : null

  if (!dependencyDir && (!args.libcVersion || libc || ld)) {
    const discovered = await discoverSiblingRuntimeFiles(file.path)
    libc ??= discovered.libc
    ld ??= discovered.ld
  }

  const source = Boolean(dependencyDir || args.libcVersion || libc || ld)
  return {
    source,
    libc,
    ld,
    dependencyDir,
    libcVersion: args.libcVersion ?? null,
    libcIndex: args.libcIndex ?? null,
  }
}

function buildPwninitArgs(
  mode: PwninitMode,
  binary: string,
  sources: RuntimeSources,
  args: PwninitArgs,
): string[] {
  if (mode === 'doctor') return ['--doctor', binary]
  if (mode === 'restore') return ['--restore', binary]
  if (mode === 'list_backups') return ['--list-backups', binary]

  const argv = ['--skip-venv-check', '--skip-checksec']
  if (args.debug) argv.push('--debug')
  if (args.onlyInit) {
    argv.push('--only-init')
  } else if (args.onlyLibc ?? true) {
    argv.push('--only-libc')
  }
  if (args.generateExp) {
    if (args.forceExp) argv.push('--force-exp')
  } else {
    argv.push('--skip-exp')
  }
  argv.push(binary)
  if (sources.dependencyDir) {
    argv.push('-M', sources.dependencyDir)
  } else if (sources.ld && sources.libc) {
    argv.push('-W', sources.ld, sources.libc)
  } else if (sources.libc) {
    argv.push('--libc', sources.libc)
    if (sources.libcIndex !== null) argv.push('--libc-index', String(sources.libcIndex))
    if (sources.libcVersion) argv.push('--libc-version', sources.libcVersion)
  } else if (sources.libcVersion) {
    argv.push(sources.libcVersion)
  }
  return argv
}

async function discoverSiblingRuntimeFiles(binary: string): Promise<{ libc: string | null; ld: string | null }> {
  const directory = path.dirname(binary)
  const entries = await readdir(directory)
  const libcCandidates = await existingFiles(directory, entries.filter(name => /^libc(?:\.so(?:\..*)?|-[^/]+\.so(?:\..*)?)$/.test(name)))
  const ldCandidates = await existingFiles(directory, entries.filter(name => /^ld(?:-linux[^/]*|-[^/]+)?\.so(?:\..*)?$/.test(name)))
  return {
    libc: libcCandidates[0] ?? null,
    ld: ldCandidates[0] ?? null,
  }
}

async function existingFiles(directory: string, names: string[]): Promise<string[]> {
  const result: string[] = []
  for (const name of names.sort()) {
    const candidate = path.join(directory, name)
    try {
      if ((await stat(candidate)).isFile()) result.push(candidate)
    } catch {
      // Ignore broken symlinks and files removed during discovery.
    }
  }
  return result
}

async function resolveWorkspaceDirectory(workspaceRoot: string, inputPath: string): Promise<string> {
  if (inputPath.trim() === '') throw new Error('dependencyDir must be a non-empty string')
  const root = await realpath(path.resolve(workspaceRoot))
  const candidate = await realpath(path.resolve(root, inputPath))
  assertInside(root, candidate)
  if (!(await stat(candidate)).isDirectory()) throw new Error(`dependencyDir is not a directory: ${inputPath}`)
  return candidate
}

function relativePath(root: string, candidate: string): string {
  return path.relative(root, candidate)
}

function hashFile(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256')
    const stream = createReadStream(filePath)
    stream.on('error', reject)
    stream.on('data', (chunk: string | Buffer) => hash.update(chunk))
    stream.on('end', () => resolve(hash.digest('hex')))
  })
}
