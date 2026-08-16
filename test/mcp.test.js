import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)))
const pluginRoot = path.join(root, 'codex-plugin', 'plugins', 'vehicle-security')

test('Codex MCP initializes, lists tools, and decodes UDS', async t => {
  const child = spawn(process.execPath, ['mcp/server.mjs'], {
    cwd: pluginRoot,
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  t.after(() => child.kill())

  let nextId = 1
  let buffer = ''
  let stderr = ''
  const pending = new Map()
  child.stderr.setEncoding('utf8')
  child.stderr.on('data', chunk => { stderr += chunk })
  child.stdout.setEncoding('utf8')
  child.stdout.on('data', chunk => {
    buffer += chunk
    let newline
    while ((newline = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, newline).trim()
      buffer = buffer.slice(newline + 1)
      if (!line) continue
      const message = JSON.parse(line)
      const waiter = pending.get(message.id)
      if (waiter) {
        pending.delete(message.id)
        waiter.resolve(message)
      }
    }
  })

  const request = (method, params = {}) => new Promise((resolve, reject) => {
    const id = nextId++
    const timeout = setTimeout(() => {
      pending.delete(id)
      reject(new Error(`MCP timeout for ${method}: ${stderr}`))
    }, 5000)
    pending.set(id, {
      resolve: message => {
        clearTimeout(timeout)
        resolve(message)
      },
    })
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
  })

  const initialized = await request('initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'test-client', version: '1.0.0' },
  })
  assert.equal(initialized.result.serverInfo.name, 'vehicle-security')

  const listed = await request('tools/list')
  assert.deepEqual(listed.result.tools.map(tool => tool.name), [
    'vehicle_investigation_plan',
    'vehicle_tool_audit',
    'vehicle_can_log_summary',
    'vehicle_uds_decode',
    'vehicle_program_analyze',
    'vehicle_artifact_triage',
  ])

  const decoded = await request('tools/call', {
    name: 'vehicle_uds_decode',
    arguments: { payload: '03 22 F1 90' },
  })
  assert.equal(decoded.result.structuredContent.dataIdentifier, '0xF190')
  assert.equal(decoded.result.isError, false)

  const planned = await request('tools/call', {
    name: 'vehicle_investigation_plan',
    arguments: {
      workspaceRoot: root,
      objective: 'Analyze this vehicle capture',
      inputKind: 'artifact',
      path: 'fixtures/sample.asc',
    },
  })
  assert.equal(planned.result.structuredContent.selectedLane, 'can-uds')
  assert.equal(planned.result.structuredContent.artifact.path, 'fixtures/sample.asc')

  const failed = await request('tools/call', {
    name: 'vehicle_program_analyze',
    arguments: { path: 'missing.bin' },
  })
  assert.equal(failed.result.isError, true)
  assert.match(failed.result.content[0].text, /workspaceRoot/)
})
