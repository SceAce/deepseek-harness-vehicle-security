#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const pluginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const skillRoot = path.join(pluginRoot, 'skills', 'analyze-vehicle-security')
const runtime = name => import(path.join(skillRoot, 'runtime', `${name}.js`))
const maxFileBytes = 256 * 1024 * 1024
const commandOptions = { timeoutMs: 20_000, maxOutputChars: 40_000 }

const workspaceProperties = {
  workspaceRoot: {
    type: 'string',
    description: 'Absolute analysis workspace root. Always pass this for file-based calls.',
  },
}

const tools = [
  {
    name: 'vehicle_investigation_plan',
    description: 'Route an attachment, prompt, or lab objective into ranked vehicle-security lanes and evidence-driven validation actions.',
    inputSchema: {
      type: 'object',
      properties: {
        ...workspaceProperties,
        objective: { type: 'string', description: 'Concrete question or desired outcome' },
        inputKind: { type: 'string', enum: ['artifact', 'prompt', 'lab'] },
        context: { type: 'string', description: 'Constraints, observed behavior, target description, or available data' },
        path: { type: 'string', description: 'Optional attachment path relative to workspaceRoot' },
      },
      required: ['objective'],
      additionalProperties: false,
    },
  },
  {
    name: 'vehicle_tool_audit',
    description: 'Audit locally available vehicle-security, reverse-engineering, protocol, firmware, Android, RF, and debugging tools.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'vehicle_can_log_summary',
    description: 'Parse a saved candump or Vector ASC log and summarize IDs, counts, channels, timestamps, and sample frames.',
    inputSchema: {
      type: 'object',
      properties: {
        ...workspaceProperties,
        path: { type: 'string', description: 'Log path relative to workspaceRoot' },
        idFilter: { type: 'string', description: 'Optional comma-separated IDs such as 0x7E0,0x7E8' },
        maxFrames: { type: 'integer', minimum: 1, maximum: 1000000 },
      },
      required: ['workspaceRoot', 'path'],
      additionalProperties: false,
    },
  },
  {
    name: 'vehicle_uds_decode',
    description: 'Decode one UDS request or response with optional ISO-TP single/first-frame unwrapping.',
    inputSchema: {
      type: 'object',
      properties: {
        payload: { type: 'string', description: 'Hex bytes, for example 03 22 F1 90' },
        stripIsoTp: { type: 'boolean', default: true },
      },
      required: ['payload'],
      additionalProperties: false,
    },
  },
  {
    name: 'vehicle_program_analyze',
    description: 'Collect program identity, ELF protections, imports, strings, bounded conclusions, hypotheses, and validation steps.',
    inputSchema: {
      type: 'object',
      properties: {
        ...workspaceProperties,
        path: { type: 'string', description: 'Program path relative to workspaceRoot' },
        focus: { type: 'string', description: 'Concrete analysis objective' },
        maxStrings: { type: 'integer', minimum: 1, maximum: 500 },
        minStringLength: { type: 'integer', minimum: 4, maximum: 64 },
      },
      required: ['workspaceRoot', 'path'],
      additionalProperties: false,
    },
  },
  {
    name: 'vehicle_artifact_triage',
    description: 'Collect immutable artifact identity, size, sampled entropy, file type, and optional Binwalk signatures.',
    inputSchema: {
      type: 'object',
      properties: {
        ...workspaceProperties,
        path: { type: 'string', description: 'Artifact path relative to workspaceRoot' },
        runBinwalk: { type: 'boolean', default: true },
      },
      required: ['workspaceRoot', 'path'],
      additionalProperties: false,
    },
  },
]

async function callTool(name, args) {
  switch (name) {
    case 'vehicle_investigation_plan': {
      const { planInvestigation } = await runtime('investigation')
      const file = args.path ? await workspaceFile(args) : null
      return planInvestigation({
        objective: requireString(args.objective, 'objective'),
        inputKind: args.inputKind,
        context: args.context,
      }, file, { ...commandOptions, enableBinwalk: false })
    }
    case 'vehicle_tool_audit': {
      const { auditTools } = await runtime('audit')
      return auditTools(commandOptions)
    }
    case 'vehicle_can_log_summary': {
      const { parseCanLog } = await runtime('can')
      const file = await workspaceFile(args)
      const text = await readFile(file.path, 'utf8')
      return { path: file.relativePath, ...parseCanLog(text, { idFilter: args.idFilter, maxFrames: args.maxFrames }) }
    }
    case 'vehicle_uds_decode': {
      const { decodeUds } = await runtime('uds')
      return decodeUds(requireString(args.payload, 'payload'), args.stripIsoTp ?? true)
    }
    case 'vehicle_program_analyze': {
      const { analyzeProgram } = await runtime('program')
      const file = await workspaceFile(args)
      return analyzeProgram(file, {
        ...commandOptions,
        focus: args.focus,
        maxStrings: args.maxStrings,
        minStringLength: args.minStringLength,
      })
    }
    case 'vehicle_artifact_triage': {
      const { triageArtifact } = await runtime('artifact')
      const file = await workspaceFile(args)
      return triageArtifact(file, { ...commandOptions, enableBinwalk: args.runBinwalk ?? true })
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
          serverInfo: { name: 'vehicle-security', version: '0.2.0' },
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
