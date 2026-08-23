import type { Context } from '@deepseek-ai/cordis'
import Schema from '@deepseek-ai/schemastery'
import { defineTool, type JsonValue } from '@deepseek-ai/dsh-tools'
import { resolveWorkspaceFile } from '../paths.js'
import { profileCtfArtifact } from './artifact.js'
import { auditCtfTools } from './capabilities.js'
import { routeCtfStart } from './router.js'
import { emptyResult } from './types.js'

export const name = 'ctf-tools'
export const inject = ['tools']

export interface Config {
  workspaceRoot?: string
  maxFileBytes: number
  maxOutputChars: number
  commandTimeoutMs: number
}

export const Config: Schema<Config> = Schema.object({
  workspaceRoot: Schema.string(),
  maxFileBytes: Schema.number().default(128 * 1024 * 1024),
  maxOutputChars: Schema.number().default(60_000),
  commandTimeoutMs: Schema.number().default(20_000),
})

const jsonOutput = {
  schema: { type: 'json' as const },
  render: (_args: unknown, value: JsonValue) => [
    { type: 'text' as const, text: JSON.stringify(value, null, 2) },
  ],
}

export function apply(ctx: Context, config: Config): void {
  validateConfig(config)
  const commandOptions = {
    timeoutMs: config.commandTimeoutMs,
    maxOutputChars: config.maxOutputChars,
  }

  ctx.tools.register(defineTool({
    name: 'ctf_tool_audit',
    description: 'Inventory local CTF capabilities for RE, pwn, crypto, misc, and web. Call this before writing solver scripts so the agent uses installed tools first.',
    parameters: {},
    output: jsonOutput,
    timeoutMs: config.commandTimeoutMs * 2,
    isConcurrencySafe: () => true,
    async execute(_args, exec) {
      return auditCtfTools({ ...commandOptions, signal: exec.signal }) as unknown as Promise<JsonValue>
    },
  }))

  ctx.tools.register(defineTool({
    name: 'ctf_artifact_profile',
    description: 'Profile one local CTF artifact: hash, size, magic, file type, entropy, and text sample. Use this as the first file-based CTF step.',
    parameters: {
      path: { type: 'string', required: true, description: 'Artifact path relative to the active workspace' },
    },
    output: jsonOutput,
    timeoutMs: config.commandTimeoutMs,
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const workspace = executionWorkspace(config, exec)
      const file = await resolveWorkspaceFile(workspace, args.path, config.maxFileBytes)
      const profile = await profileCtfArtifact(file, { ...commandOptions, signal: exec.signal })
      return {
        ...emptyResult('ok'),
        observations: profile.observations,
        commands: profile.commands,
        artifacts: [profile.artifact],
        limitations: profile.limitations,
        artifact: profile.artifact,
        nextActions: [
          { tool: 'ctf_start', args: { path: profile.artifact.path }, reason: 'Route the profiled artifact to the category-specific tool.' },
        ],
      } as unknown as JsonValue
    },
  }))

  ctx.tools.register(defineTool({
    name: 'ctf_start',
    description: 'CTF first-step router. Given a file, URL, category, or prompt, audit local capabilities, profile the artifact, choose the next CTF tool, and list any human action needed.',
    parameters: {
      objective: { type: 'string', description: 'Challenge objective or user question' },
      path: { type: 'string', description: 'Optional challenge artifact path relative to the active workspace' },
      url: { type: 'string', description: 'Optional local or remote challenge URL' },
      category: { type: 'string', description: 'Optional category: auto, re, pwn, crypto, misc, or web' },
      context: { type: 'string', description: 'Optional challenge text, constraints, service info, or notes' },
    },
    output: jsonOutput,
    timeoutMs: config.commandTimeoutMs * 2,
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const workspace = executionWorkspace(config, exec)
      const audit = await auditCtfTools({ ...commandOptions, signal: exec.signal })
      const profile = args.path
        ? await profileCtfArtifact(
          await resolveWorkspaceFile(workspace, args.path, config.maxFileBytes),
          { ...commandOptions, signal: exec.signal },
        )
        : null
      const decision = routeCtfStart({
        objective: args.objective,
        path: args.path,
        url: args.url,
        category: parseCategory(args.category),
        context: args.context,
      }, profile?.artifact ?? null, audit)
      return {
        schemaVersion: '1.0',
        status: decision.humanRequired.length > 0 ? 'human_required' : 'ok',
        objective: args.objective ?? '',
        category: decision.category,
        reasons: decision.reasons,
        artifact: profile?.artifact ?? null,
        availableCapabilities: audit.capabilities.filter(item => item.available).map(item => item.id),
        availablePythonModules: audit.python.modules.filter(item => item.available).map(item => item.id),
        recommendedTool: decision.recommendedTool,
        recommendedArgs: decision.recommendedArgs,
        observations: [
          ...audit.recommendations.map(item => `recommendation: ${item}`),
          ...(profile?.observations ?? []),
        ],
        commands: [
          ...audit.commands,
          ...(profile?.commands ?? []),
        ],
        artifacts: profile ? [profile.artifact] : [],
        limitations: profile?.limitations ?? [],
        nextActions: decision.nextActions,
        humanRequired: decision.humanRequired,
      } as unknown as JsonValue
    },
  }))
}

function executionWorkspace(config: Config, exec: { agent?: { session: { header: { cwd?: string } } } }): string {
  const configured = config.workspaceRoot?.trim()
  if (configured) return configured

  const sessionCwd = exec.agent?.session.header.cwd
  if (sessionCwd) return sessionCwd
  throw new Error('session workspace is unavailable; configure workspaceRoot explicitly')
}

function parseCategory(value: string | undefined): 'auto' | 're' | 'pwn' | 'crypto' | 'misc' | 'web' | undefined {
  if (value === undefined || value === '') return undefined
  if (value === 'auto' || value === 're' || value === 'pwn' || value === 'crypto' || value === 'misc' || value === 'web') return value
  throw new Error('category must be auto, re, pwn, crypto, misc, or web')
}

function validateConfig(config: Config): void {
  for (const [key, value] of Object.entries({
    maxFileBytes: config.maxFileBytes,
    maxOutputChars: config.maxOutputChars,
    commandTimeoutMs: config.commandTimeoutMs,
  })) {
    if (!Number.isInteger(value) || value <= 0) throw new Error(`${key} must be a positive integer`)
  }
}
