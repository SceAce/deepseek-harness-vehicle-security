import type { Context } from '@deepseek-ai/cordis'
import Schema from '@deepseek-ai/schemastery'
import { defineTool, type JsonValue } from '@deepseek-ai/dsh-tools'
import { resolveWorkspaceFile } from '../paths.js'
import { profileCtfArtifact } from './artifact.js'
import { debugPwnArtifact, profilePwnArtifact, profileReArtifact, searchRopGadgets } from './binary.js'
import { auditCtfTools } from './capabilities.js'
import { probeCryptoInput } from './crypto.js'
import { createHumanRequest } from './human.js'
import { profilePcapArtifact, triageMiscArtifact } from './misc.js'
import { routeCtfStart } from './router.js'
import { httpDiff, httpRequest } from './web.js'
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

  ctx.tools.register(defineTool({
    name: 'ctf_re_profile',
    description: 'Reverse-engineering profile for one binary or source-like artifact using installed tools such as file, readelf, strings, and binutils before any custom solver script.',
    parameters: {
      path: { type: 'string', required: true, description: 'Artifact path relative to the active workspace' },
    },
    output: jsonOutput,
    timeoutMs: config.commandTimeoutMs * 2,
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const file = await workspaceFile(config, exec, args.path)
      return profileReArtifact(file, { ...commandOptions, signal: exec.signal }) as unknown as Promise<JsonValue>
    },
  }))

  ctx.tools.register(defineTool({
    name: 'ctf_pwn_profile',
    description: 'Pwn binary profile using installed tools such as checksec, readelf, strings, and binutils; returns mitigations, imports, strings, and next debug/gadget actions.',
    parameters: {
      path: { type: 'string', required: true, description: 'Binary path relative to the active workspace' },
    },
    output: jsonOutput,
    timeoutMs: config.commandTimeoutMs * 2,
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const file = await workspaceFile(config, exec, args.path)
      return profilePwnArtifact(file, { ...commandOptions, signal: exec.signal }) as unknown as Promise<JsonValue>
    },
  }))

  ctx.tools.register(defineTool({
    name: 'ctf_pwn_debug_probe',
    description: 'Run a bounded gdb batch probe on a local pwn binary and return registers, entrypoint disassembly, stack sample, backtrace, and raw debugger output.',
    parameters: {
      path: { type: 'string', required: true, description: 'Binary path relative to the active workspace' },
      argv: { type: 'array', items: { type: 'string' }, description: 'Optional process argv values' },
      breakAt: { type: 'string', description: 'Optional breakpoint symbol or address, for example main or *0x401000' },
      extraGdbCommands: { type: 'array', items: { type: 'string' }, description: 'Optional extra bounded gdb commands' },
    },
    output: jsonOutput,
    timeoutMs: config.commandTimeoutMs * 2,
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const file = await workspaceFile(config, exec, args.path)
      return debugPwnArtifact(file, {
        argv: args.argv,
        breakAt: args.breakAt,
        extraGdbCommands: args.extraGdbCommands,
      }, { ...commandOptions, signal: exec.signal }) as unknown as Promise<JsonValue>
    },
  }))

  ctx.tools.register(defineTool({
    name: 'ctf_rop_search',
    description: 'Search ROP gadgets in a local binary using ROPgadget or ropper when available.',
    parameters: {
      path: { type: 'string', required: true, description: 'Binary path relative to the active workspace' },
      query: { type: 'string', description: 'Optional gadget query, for example pop|ret' },
      maxResults: { type: 'integer', description: 'Maximum gadget lines to return, from 1 to 500' },
    },
    output: jsonOutput,
    timeoutMs: config.commandTimeoutMs * 2,
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const file = await workspaceFile(config, exec, args.path)
      return searchRopGadgets(file, {
        query: args.query,
        maxResults: args.maxResults,
      }, { ...commandOptions, signal: exec.signal }) as unknown as Promise<JsonValue>
    },
  }))

  ctx.tools.register(defineTool({
    name: 'ctf_crypto_probe',
    description: 'Probe text or a small local file for common CTF crypto encodings, entropy, hashes, and single-byte XOR candidates before writing a custom solver.',
    parameters: {
      path: { type: 'string', description: 'Optional artifact path relative to the active workspace' },
      text: { type: 'string', description: 'Optional ciphertext, encoded value, or challenge text' },
    },
    output: jsonOutput,
    timeoutMs: config.commandTimeoutMs,
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const file = args.path ? await workspaceFile(config, exec, args.path) : undefined
      return probeCryptoInput({ file, text: args.text }) as unknown as Promise<JsonValue>
    },
  }))

  ctx.tools.register(defineTool({
    name: 'ctf_misc_triage',
    description: 'Misc/forensics triage for archives, images, captures, and unknown files using local tools such as binwalk, exiftool, 7z, strings, and zsteg.',
    parameters: {
      path: { type: 'string', required: true, description: 'Artifact path relative to the active workspace' },
    },
    output: jsonOutput,
    timeoutMs: config.commandTimeoutMs * 2,
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const file = await workspaceFile(config, exec, args.path)
      return triageMiscArtifact(file, { ...commandOptions, signal: exec.signal }) as unknown as Promise<JsonValue>
    },
  }))

  ctx.tools.register(defineTool({
    name: 'ctf_pcap_profile',
    description: 'PCAP profile using tshark to summarize protocol hierarchy and TCP/UDP conversations.',
    parameters: {
      path: { type: 'string', required: true, description: 'PCAP path relative to the active workspace' },
    },
    output: jsonOutput,
    timeoutMs: config.commandTimeoutMs * 2,
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const file = await workspaceFile(config, exec, args.path)
      return profilePcapArtifact(file, { ...commandOptions, signal: exec.signal }) as unknown as Promise<JsonValue>
    },
  }))

  ctx.tools.register(defineTool({
    name: 'ctf_http_request',
    description: 'Run one structured HTTP request through local curl and return status, body length, hash, preview, exact argv, and next diff action.',
    parameters: {
      url: { type: 'string', required: true, description: 'Challenge URL' },
      method: { type: 'string', description: 'HTTP method; defaults to GET' },
      headers: { type: 'array', items: { type: 'string' }, description: 'Optional headers in Name: value form' },
      body: { type: 'string', description: 'Optional request body' },
      followRedirects: { type: 'boolean', description: 'Follow redirects with curl -L' },
      maxTimeSeconds: { type: 'number', description: 'curl max-time in seconds, from 1 to 120' },
    },
    output: jsonOutput,
    timeoutMs: config.commandTimeoutMs * 2,
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      return httpRequest({
        url: args.url,
        method: args.method,
        headers: args.headers,
        body: args.body,
        followRedirects: args.followRedirects,
        maxTimeSeconds: args.maxTimeSeconds,
      }, { ...commandOptions, signal: exec.signal }) as unknown as Promise<JsonValue>
    },
  }))

  ctx.tools.register(defineTool({
    name: 'ctf_http_diff',
    description: 'Run two structured HTTP requests through curl and compare status, body length, and body hash.',
    parameters: {
      urlA: { type: 'string', required: true, description: 'Baseline URL' },
      urlB: { type: 'string', required: true, description: 'Variant URL' },
      method: { type: 'string', description: 'HTTP method for both requests' },
      headers: { type: 'array', items: { type: 'string' }, description: 'Optional headers in Name: value form' },
      bodyA: { type: 'string', description: 'Optional baseline request body' },
      bodyB: { type: 'string', description: 'Optional variant request body' },
    },
    output: jsonOutput,
    timeoutMs: config.commandTimeoutMs * 3,
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      return httpDiff({
        urlA: args.urlA,
        urlB: args.urlB,
        method: args.method,
        headers: args.headers,
        bodyA: args.bodyA,
        bodyB: args.bodyB,
      }, { ...commandOptions, signal: exec.signal }) as unknown as Promise<JsonValue>
    },
  }))

  ctx.tools.register(defineTool({
    name: 'ctf_human_request',
    description: 'Create a structured human-action request when a CTF step needs a person to start a service, operate a GUI, attach a device, provide data, observe state, or confirm a workspace-changing action.',
    parameters: {
      type: { type: 'string', required: true, description: 'attach_device, start_service, perform_gui_action, provide_data, observe_state, or confirm' },
      title: { type: 'string', required: true, description: 'Short action title' },
      reason: { type: 'string', required: true, description: 'Why the human action is needed' },
      steps: { type: 'array', required: true, items: { type: 'string' }, description: 'Concrete steps for the human' },
      expectedResult: { type: 'object', required: true, additionalProperties: true, description: 'Expected structured fields the user should return' },
    },
    output: jsonOutput,
    isConcurrencySafe: () => true,
    async execute(args) {
      return createHumanRequest({
        type: parseHumanRequestType(args.type),
        title: args.title,
        reason: args.reason,
        steps: args.steps,
        expectedResult: Object.fromEntries(Object.entries(args.expectedResult).map(([key, value]) => [key, String(value)])),
      }) as unknown as JsonValue
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

async function workspaceFile(
  config: Config,
  exec: { agent?: { session: { header: { cwd?: string } } } },
  inputPath: string,
) {
  return resolveWorkspaceFile(executionWorkspace(config, exec), inputPath, config.maxFileBytes)
}

function parseCategory(value: string | undefined): 'auto' | 're' | 'pwn' | 'crypto' | 'misc' | 'web' | undefined {
  if (value === undefined || value === '') return undefined
  if (value === 'auto' || value === 're' || value === 'pwn' || value === 'crypto' || value === 'misc' || value === 'web') return value
  throw new Error('category must be auto, re, pwn, crypto, misc, or web')
}

function parseHumanRequestType(value: string) {
  if (
    value === 'attach_device'
    || value === 'start_service'
    || value === 'perform_gui_action'
    || value === 'provide_data'
    || value === 'observe_state'
    || value === 'confirm'
  ) return value
  throw new Error('type must be attach_device, start_service, perform_gui_action, provide_data, observe_state, or confirm')
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
