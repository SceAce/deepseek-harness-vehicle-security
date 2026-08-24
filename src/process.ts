import { execFile } from 'node:child_process'

export interface CommandOptions {
  signal?: AbortSignal
  timeoutMs?: number
  maxOutputChars?: number
  cwd?: string
  env?: NodeJS.ProcessEnv
}

export interface CommandResult {
  ok: boolean
  exitCode: number | null
  stdout: string
  stderr: string
  error: string | null
}

export function runCommand(
  command: string,
  args: readonly string[],
  options: CommandOptions = {},
): Promise<CommandResult> {
  const {
    signal,
    timeoutMs = 20_000,
    maxOutputChars = 40_000,
    cwd,
    env,
  } = options

  return new Promise((resolve, reject) => {
    execFile(command, [...args], {
      cwd,
      env: env ? { ...process.env, ...env } : undefined,
      signal,
      timeout: timeoutMs,
      encoding: 'utf8',
      maxBuffer: Math.max(64 * 1024, maxOutputChars * 4),
      windowsHide: true,
    }, (error, stdout, stderr) => {
      if (error?.name === 'AbortError') {
        reject(error)
        return
      }

      resolve({
        ok: error === null,
        exitCode: typeof error?.code === 'number' ? error.code : error ? null : 0,
        stdout: truncate(stdout, maxOutputChars),
        stderr: truncate(stderr, maxOutputChars),
        error: error ? error.message : null,
      })
    })
  })
}

export function truncate(value: string, maxChars: number): string {
  if (value.length <= maxChars) return value
  return `${value.slice(0, maxChars)}\n...[truncated ${value.length - maxChars} chars]`
}
