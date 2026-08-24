import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { resolveWorkspaceFile, type ResolvedWorkspaceFile } from '../paths.js'
import { runCommand, type CommandOptions } from '../process.js'
import { findCtfExecutable } from './environment.js'
import { commandRecord, emptyResult, type CtfToolResultBase } from './types.js'

export type CtfCryptoEngine = 'sage' | 'gp'

export interface CtfCryptoExecArgs {
  code?: string
  scriptPath?: string
  argv?: string[]
}

export interface CtfCryptoExecOptions extends CommandOptions {
  workspaceRoot?: string
  maxFileBytes?: number
}

export interface CtfCryptoExecResult extends CtfToolResultBase {
  engine: {
    name: CtfCryptoEngine
    executable: string | null
    argv: string[]
    scriptPath: string | null
  }
  output: string | null
}

export async function runCtfCryptoEngine(
  engine: CtfCryptoEngine,
  args: CtfCryptoExecArgs,
  options: CtfCryptoExecOptions = {},
): Promise<CtfCryptoExecResult> {
  const base = emptyResult()
  const executable = await findCtfExecutable(engine, options.cwd)
  const script = args.scriptPath
    ? await resolveScript(options.workspaceRoot, args.scriptPath, options.maxFileBytes ?? 128 * 1024 * 1024)
    : null
  const code = typeof args.code === 'string' ? args.code : ''
  const argv = normalizeArgv(args.argv)

  if (!script && code.trim() === '') {
    throw new Error('Provide either code or scriptPath.')
  }

  if (!executable) {
    base.status = 'missing_capability'
    base.limitations.push(`${engine} is not installed or is not visible in the CTF tool search path.`)
    base.nextActions.push({
      tool: 'ctf_tool_setup',
      args: { target: engine === 'sage' ? 'sage' : 'pari_gp' },
      reason: `Install or expose ${engine} before running a CTF crypto solver.`,
    })
    return {
      ...base,
      engine: {
        name: engine,
        executable: null,
        argv: [],
        scriptPath: script?.relativePath ?? null,
      },
      output: null,
    }
  }

  const temporary = script ? null : await materializeInlineScript(engine, code)
  const executionScriptPath = script?.path ?? temporary?.path
  if (!executionScriptPath) throw new Error('Crypto execution script was not created.')
  const commandArgv = script
    ? [quietFlag(engine), script.path, ...argv]
    : [quietFlag(engine), executionScriptPath, ...argv]
  const executionRoot = script?.root ?? options.cwd ?? options.workspaceRoot
  let capture
  try {
    capture = await runCommand(executable, commandArgv, {
      ...options,
      cwd: executionRoot,
      maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000),
    })
  } finally {
    if (temporary) await rm(temporary.root, { recursive: true, force: true })
  }

  const output = [capture.stdout, capture.stderr].filter(Boolean).join('\n').trim() || null
  base.commands.push(commandRecord(executable, commandArgv, capture, executionRoot))
  base.observations.push(`Executed ${engine} with ${script ? `workspace script ${script.relativePath}` : 'inline code'}.`)
  if (!capture.ok) {
    base.status = 'failed'
    base.limitations.push(`${engine} exited with ${capture.exitCode ?? 'no status'}: ${capture.error ?? capture.stderr.trim()}`)
  }
  return {
    ...base,
    status: capture.ok ? 'ok' : 'failed',
    engine: {
      name: engine,
      executable,
      argv: commandArgv,
      scriptPath: script?.relativePath ?? null,
    },
    output,
  }
}

async function materializeInlineScript(
  engine: CtfCryptoEngine,
  code: string,
): Promise<{ root: string; path: string }> {
  const root = await mkdtemp(path.join(os.tmpdir(), `dsh-ctf-${engine}-`))
  const extension = engine === 'sage' ? '.sage' : '.gp'
  const scriptPath = path.join(root, `inline${extension}`)
  await writeFile(scriptPath, `${code}\n`, 'utf8')
  return { root, path: scriptPath }
}

async function resolveScript(
  workspaceRoot: string | undefined,
  inputPath: string,
  maxFileBytes: number,
): Promise<ResolvedWorkspaceFile> {
  if (!workspaceRoot) throw new Error('workspaceRoot is required when scriptPath is provided.')
  return resolveWorkspaceFile(workspaceRoot, inputPath, maxFileBytes)
}

function quietFlag(engine: CtfCryptoEngine): string {
  return engine === 'sage' ? '-q' : '-q'
}

function normalizeArgv(argv: string[] | undefined): string[] {
  return Array.isArray(argv) ? argv.slice(0, 32).map(String) : []
}
