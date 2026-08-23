import type { CommandResult } from '../process.js'

export type CtfCategory = 'auto' | 're' | 'pwn' | 'crypto' | 'misc' | 'web'

export type ResolvedCtfCategory = Exclude<CtfCategory, 'auto'> | 'unknown'

export type CtfToolStatus = 'ok' | 'missing_capability' | 'human_required' | 'failed'

export interface ToolInvocationRecord {
  executable: string
  argv: string[]
  cwd?: string
  ok: boolean
  exitCode: number | null
  stdout?: string
  stderr?: string
  error?: string | null
}

export interface CtfNextAction {
  tool: string
  args: Record<string, unknown>
  reason: string
}

export interface CtfToolChoice extends CtfNextAction {
  availability: 'ready' | 'partial' | 'missing_backend' | 'host_dependent'
  backendCapabilities: string[]
  missingCapabilities: string[]
}

export interface CtfToolBinding {
  tool: string
  category: CtfCategory
  kind: 'local'
  callable: true
  purpose: string
  when: string
  backendCapabilities: string[]
  availableCapabilities: string[]
  missingCapabilities: string[]
  availability: 'ready' | 'partial' | 'missing_backend'
  exampleArgs: Record<string, unknown>
  fallbackTool: string | null
}

export type CtfHumanReturnType = 'log' | 'screenshot' | 'ocr_text'

export interface CtfHumanOperation {
  order: number
  kind: 'command' | 'instruction'
  title: string
  command?: string
  instruction?: string
  expectedSignal: string
}

export interface CtfHumanRequest {
  type: 'attach_device' | 'start_service' | 'perform_gui_action' | 'provide_data' | 'observe_state' | 'confirm'
  title: string
  reason: string
  operationOrder: CtfHumanOperation[]
  acceptedReturnTypes: CtfHumanReturnType[]
  returnContract: {
    onlyReturn: CtfHumanReturnType[]
    format: 'plain_text' | 'json'
    fields: Record<string, string>
  }
  legacySteps?: string[]
  expectedResult?: Record<string, string>
}

export interface CtfToolResultBase {
  status: CtfToolStatus
  observations: string[]
  commands: ToolInvocationRecord[]
  artifacts: Array<Record<string, unknown>>
  limitations: string[]
  nextActions: CtfNextAction[]
  humanRequired: CtfHumanRequest[]
}

export function emptyResult(status: CtfToolStatus = 'ok'): CtfToolResultBase {
  return {
    status,
    observations: [],
    commands: [],
    artifacts: [],
    limitations: [],
    nextActions: [],
    humanRequired: [],
  }
}

export function commandRecord(
  executable: string,
  argv: readonly string[],
  result: CommandResult,
  cwd?: string,
): ToolInvocationRecord {
  return {
    executable,
    argv: [...argv],
    ...(cwd === undefined ? {} : { cwd }),
    ok: result.ok,
    exitCode: result.exitCode,
    stdout: result.stdout,
    stderr: result.stderr,
    error: result.error,
  }
}
