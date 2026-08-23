import { resolveWorkspaceFile, type ResolvedWorkspaceFile } from '../paths.js'
import { runCommand, type CommandOptions } from '../process.js'
import { discoverCtfPython } from './environment.js'
import { commandRecord, emptyResult, type CtfToolResultBase } from './types.js'

export interface CtfPythonExecArgs {
  code?: string
  scriptPath?: string
  argv?: string[]
}

export interface CtfPythonExecOptions extends CommandOptions {
  workspaceRoot?: string
  maxFileBytes?: number
}

export interface CtfPythonExecResult extends CtfToolResultBase {
  python: {
    executable: string | null
    argv: string[]
    scriptPath: string | null
  }
  output: string | null
}

export async function runCtfPython(
  args: CtfPythonExecArgs,
  options: CtfPythonExecOptions = {},
): Promise<CtfPythonExecResult> {
  const base = emptyResult()
  const environment = await discoverCtfPython(options.cwd)
  const script = args.scriptPath
    ? await resolveScript(options.workspaceRoot, args.scriptPath, options.maxFileBytes ?? 128 * 1024 * 1024)
    : null
  const code = typeof args.code === 'string' ? args.code : ''

  if (!script && code.trim() === '') {
    throw new Error('Provide either code or scriptPath.')
  }

  const reportedArgv = script
    ? [script.relativePath, ...(args.argv ?? []).slice(0, 32)]
    : ['-c', code, ...(args.argv ?? []).slice(0, 32)]
  const commandArgv = script
    ? [script.path, ...(args.argv ?? []).slice(0, 32)]
    : reportedArgv
  const python = {
    executable: environment.executable,
    argv: commandArgv,
    scriptPath: script?.relativePath ?? null,
  }

  if (!environment.executable) {
    base.status = 'missing_capability'
    base.limitations.push(`The fixed CTF Python interpreter is missing: ${environment.requiredExecutable}`)
    base.nextActions.push({
      tool: 'ctf_tool_setup',
      args: { target: 'python_ctf_env' },
      reason: 'Install or restore the required fixed CTF Python environment.',
    })
    return { ...base, python, output: null }
  }

  const capture = await runCommand(environment.executable, commandArgv, {
    ...options,
    cwd: script?.root ?? options.cwd,
  })
  base.commands.push(commandRecord(environment.executable, commandArgv, capture, script?.root ?? options.cwd))
  base.observations.push(`Executed the fixed CTF Python interpreter: ${environment.executable}`)
  if (!capture.ok) {
    base.status = 'failed'
    base.limitations.push(`Python exited with ${capture.exitCode ?? 'no status'}: ${capture.error ?? capture.stderr.trim()}`)
  }
  return {
    ...base,
    status: capture.ok ? 'ok' : 'failed',
    python,
    output: [capture.stdout, capture.stderr].filter(Boolean).join('\n').trim() || null,
  }
}

async function resolveScript(
  workspaceRoot: string | undefined,
  inputPath: string,
  maxFileBytes: number,
): Promise<ResolvedWorkspaceFile> {
  if (!workspaceRoot) throw new Error('workspaceRoot is required when scriptPath is provided.')
  return resolveWorkspaceFile(workspaceRoot, inputPath, maxFileBytes)
}
