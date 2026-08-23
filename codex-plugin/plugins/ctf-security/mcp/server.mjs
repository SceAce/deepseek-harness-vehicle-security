#!/usr/bin/env node
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const pluginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const runtimeRoot = path.join(pluginRoot, 'skills', 'investigate-ctf', 'runtime')
const runtime = name => import(path.join(runtimeRoot, `${name}.js`))
const maxFileBytes = 128 * 1024 * 1024
const commandOptions = { timeoutMs: 20_000, maxOutputChars: 60_000 }

const workspaceProperties = {
  workspaceRoot: {
    type: 'string',
    description: 'Absolute analysis workspace root. Always pass this for file-based calls.',
  },
}

const tools = [
  {
    name: 'ctf_tool_audit',
    description: 'Inventory local CTF capabilities for RE, pwn, crypto, misc, and web.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'ctf_artifact_profile',
    description: 'Profile one local CTF artifact: hash, size, magic, file type, entropy, and text sample.',
    inputSchema: {
      type: 'object',
      properties: {
        ...workspaceProperties,
        path: { type: 'string', description: 'Artifact path relative to workspaceRoot' },
      },
      required: ['workspaceRoot', 'path'],
      additionalProperties: false,
    },
  },
  {
    name: 'ctf_start',
    description: 'CTF first-step router that audits local capabilities, profiles an optional artifact, chooses the next CTF tool, and lists human actions.',
    inputSchema: {
      type: 'object',
      properties: {
        ...workspaceProperties,
        objective: { type: 'string' },
        path: { type: 'string', description: 'Optional challenge artifact path relative to workspaceRoot' },
        url: { type: 'string' },
        category: { type: 'string', enum: ['auto', 're', 'pwn', 'crypto', 'misc', 'web'] },
        context: { type: 'string' },
      },
      additionalProperties: false,
    },
  },
]

async function callTool(name, args) {
  switch (name) {
    case 'ctf_tool_audit': {
      const { auditCtfTools } = await runtime('capabilities')
      return auditCtfTools(commandOptions)
    }
    case 'ctf_artifact_profile': {
      const { profileCtfArtifact } = await runtime('artifact')
      const file = await workspaceFile(args)
      const profile = await profileCtfArtifact(file, commandOptions)
      return {
        status: 'ok',
        observations: profile.observations,
        commands: profile.commands,
        artifacts: [profile.artifact],
        limitations: profile.limitations,
        nextActions: [
          { tool: 'ctf_start', args: { path: profile.artifact.path }, reason: 'Route the profiled artifact to the category-specific tool.' },
        ],
        humanRequired: [],
        artifact: profile.artifact,
      }
    }
    case 'ctf_start': {
      const { auditCtfTools } = await runtime('capabilities')
      const { profileCtfArtifact } = await runtime('artifact')
      const { routeCtfStart } = await runtime('router')
      const audit = await auditCtfTools(commandOptions)
      const profile = args.path ? await profileCtfArtifact(await workspaceFile(args), commandOptions) : null
      const decision = routeCtfStart({
        objective: args.objective,
        path: args.path,
        url: args.url,
        category: args.category,
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
      }
    }
    default:
      throw new Error(`unknown tool: ${name}`)
  }
}

async function workspaceFile(args) {
  const { resolveWorkspaceFile } = await runtime('paths')
  const root = path.resolve(requireString(args.workspaceRoot, 'workspaceRoot'))
  return resolveWorkspaceFile(root, requireString(args.path, 'path'), maxFileBytes)
}

function requireString(value, name) {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`${name} must be a non-empty string`)
  return value
}

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`)
}

async function handle(message) {
  if (!message || message.jsonrpc !== '2.0' || typeof message.method !== 'string') return
  if (message.method.startsWith('notifications/')) return
  const response = { jsonrpc: '2.0', id: message.id }
  try {
    switch (message.method) {
      case 'initialize':
        response.result = {
          protocolVersion: message.params?.protocolVersion ?? '2024-11-05',
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'ctf-security', version: '0.1.0' },
        }
        break
      case 'ping':
        response.result = {}
        break
      case 'tools/list':
        response.result = { tools }
        break
      case 'tools/call': {
        try {
          const result = await callTool(message.params?.name, message.params?.arguments ?? {})
          response.result = {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
            structuredContent: result,
            isError: false,
          }
        } catch (error) {
          response.result = {
            content: [{ type: 'text', text: error instanceof Error ? error.message : String(error) }],
            isError: true,
          }
        }
        break
      }
      default:
        response.error = { code: -32601, message: `method not found: ${message.method}` }
    }
  } catch (error) {
    response.error = { code: -32000, message: error instanceof Error ? error.message : String(error) }
  }
  send(response)
}

let buffer = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', chunk => {
  buffer += chunk
  let newline
  while ((newline = buffer.indexOf('\n')) >= 0) {
    const line = buffer.slice(0, newline).trim()
    buffer = buffer.slice(newline + 1)
    if (!line) continue
    try {
      const message = JSON.parse(line)
      void handle(message)
    } catch (error) {
      send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: error instanceof Error ? error.message : String(error) } })
    }
  }
})
