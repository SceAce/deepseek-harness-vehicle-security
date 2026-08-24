import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { once } from 'node:events'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)))
const pluginRoot = path.join(root, 'codex-plugin', 'plugins', 'vehicle-security')
const ctfPluginRoot = path.join(root, 'codex-plugin', 'plugins', 'ctf-security')

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

  const request = (method, params = {}, timeoutMs = 5000) => new Promise((resolve, reject) => {
    const id = nextId++
    const timeout = setTimeout(() => {
      pending.delete(id)
      reject(new Error(`MCP timeout for ${method}: ${stderr}`))
    }, timeoutMs)
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

test('Codex CTF MCP initializes, lists tools, and probes crypto text', async t => {
  const child = spawn(process.execPath, ['mcp/server.mjs'], {
    cwd: ctfPluginRoot,
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

  const request = (method, params = {}, timeoutMs = 5000) => new Promise((resolve, reject) => {
    const id = nextId++
    const timeout = setTimeout(() => {
      pending.delete(id)
      reject(new Error(`MCP timeout for ${method}: ${stderr}`))
    }, timeoutMs)
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
  assert.equal(initialized.result.serverInfo.name, 'ctf-security')

  const listed = await request('tools/list')
  assert.deepEqual(listed.result.tools.map(tool => tool.name), [
    'ctf_tool_audit',
    'ctf_python_exec',
    'ctf_mcp_configure',
    'ctf_artifact_profile',
    'ctf_start',
    'ctf_re_profile',
    'ctf_re_r2_query',
    'ctf_re_ida_script',
    'ctf_pwn_profile',
    'ctf_pwninit',
    'ctf_pwn_debug_probe',
    'ctf_pwn_gdb_probe',
    'ctf_rop_search',
    'ctf_one_gadget',
    'ctf_seccomp_profile',
    'ctf_crypto_probe',
    'ctf_misc_triage',
    'ctf_pcap_profile',
    'ctf_http_request',
    'ctf_http_diff',
    'ctf_web_browser_probe',
    'ctf_web_capture_probe',
    'ctf_tool_setup',
    'ctf_human_request',
  ])

  const probed = await request('tools/call', {
    name: 'ctf_crypto_probe',
    arguments: { text: '414243' },
  })
  assert.equal(probed.result.structuredContent.encodings[0].type, 'hex')
  assert.equal(probed.result.structuredContent.encodings[0].decodedPreview, 'ABC')

  const audit = await request('tools/call', {
    name: 'ctf_tool_audit',
    arguments: {},
  }, 20000)
  assert.equal(audit.result.isError, false)
  assert.ok(audit.result.structuredContent.toolBindings.some(binding => binding.tool === 'ctf_pwn_gdb_probe'))
  assert.ok(audit.result.structuredContent.toolBindings.some(binding => binding.tool === 'ctf_re_r2_query'))

  const python = await request('tools/call', {
    name: 'ctf_python_exec',
    arguments: { code: 'import sys; print(sys.executable)' },
  })
  assert.equal(python.result.isError, false)
  assert.equal(python.result.structuredContent.python.executable, '/home/source/tools/PyVenv/CTF/bin/python')

  const configured = await request('tools/call', {
    name: 'ctf_mcp_configure',
    arguments: {
      configPath: '/tmp/dsh-ctf-mcp-test.json',
      includeChrome: true,
      includeTavily: false,
    },
  })
  assert.equal(configured.result.structuredContent.status, 'ok')
  assert.deepEqual(configured.result.structuredContent.configured, ['mcp.chrome'])

  const reProfile = await request('tools/call', {
    name: 'ctf_re_profile',
    arguments: { workspaceRoot: root, path: 'fixtures/sample.asc' },
  })
  assert.equal(reProfile.result.structuredContent.status, 'ok')
  assert.equal(reProfile.result.structuredContent.artifact.path, 'fixtures/sample.asc')

  const r2 = await request('tools/call', {
    name: 'ctf_re_r2_query',
    arguments: { workspaceRoot: root, path: 'fixtures/sample.asc', commands: ['ij'] },
  })
  assert.equal(r2.result.structuredContent.status, 'ok')
  assert.equal(r2.result.structuredContent.query.commands[0], 'ij')

  const oneGadget = await request('tools/call', {
    name: 'ctf_one_gadget',
    arguments: { workspaceRoot: root, path: 'fixtures/sample.asc' },
  })
  assert.equal(oneGadget.result.isError, false)
  assert.equal(oneGadget.result.structuredContent.status, 'missing_capability')
  assert.equal(oneGadget.result.structuredContent.target.source, 'none')

  const start = await request('tools/call', {
    name: 'ctf_start',
    arguments: {
      workspaceRoot: root,
      objective: 'inspect this pwn binary',
      category: 'pwn',
      path: 'fixtures/sample.asc',
    },
  }, 20000)
  assert.equal(start.result.isError, false)
  assert.ok(Array.isArray(start.result.structuredContent.toolChoices))
  assert.ok(start.result.structuredContent.toolBindings.some(binding => binding.tool === 'ctf_pwn_gdb_probe'))


  const ida = await request('tools/call', {
    name: 'ctf_re_ida_script',
    arguments: { workspaceRoot: root, path: 'fixtures/sample.asc', focus: 'flag' },
  })
  assert.match(ida.result.structuredContent.script, /ida_funcs/)
  assert.equal(ida.result.structuredContent.executed, false)

  const gdb = await request('tools/call', {
    name: 'ctf_pwn_gdb_probe',
    arguments: { workspaceRoot: root, path: 'fixtures/sample.asc' },
  })
  assert.equal(gdb.result.isError, false)
  assert.equal(gdb.result.structuredContent.debugger.frontend, 'pwndbg')

  const setup = await request('tools/call', {
    name: 'ctf_tool_setup',
    arguments: { target: 'ida_pro' },
  })
  assert.equal(setup.result.structuredContent.status, 'human_required')
  assert.ok(setup.result.structuredContent.request.operationOrder.every(operation => operation.command || operation.instruction))

  const seccompSetup = await request('tools/call', {
    name: 'ctf_tool_setup',
    arguments: { target: 'seccomp_tools' },
  })
  assert.equal(seccompSetup.result.structuredContent.target, 'seccomp_tools')
  assert.ok(seccompSetup.result.structuredContent.request.operationOrder.every(operation => operation.command || operation.instruction))

  const oneGadgetSetup = await request('tools/call', {
    name: 'ctf_tool_setup',
    arguments: { target: 'one_gadget' },
  })
  assert.equal(oneGadgetSetup.result.structuredContent.target, 'one_gadget')
  assert.ok(oneGadgetSetup.result.structuredContent.request.operationOrder.every(operation => operation.command || operation.instruction))

  const humanRequest = await request('tools/call', {
    name: 'ctf_human_request',
    arguments: {
      type: 'start_service',
      title: 'Start local service',
      reason: 'Need a URL.',
      operationOrder: [
        {
          order: 1,
          kind: 'instruction',
          title: 'Start service',
          instruction: 'Run the challenge service and return the startup log.',
          expectedSignal: 'Return log, screenshot text, or OCR text with host and port.',
        },
      ],
      acceptedReturnTypes: ['log', 'ocr_text'],
      returnFields: { log: 'startup log', ocr_text: 'OCR text with host and port' },
    },
  })
  assert.equal(humanRequest.result.structuredContent.request.operationOrder[0].kind, 'instruction')
  assert.deepEqual(humanRequest.result.structuredContent.request.acceptedReturnTypes, ['log', 'ocr_text'])

  const human = await request('tools/call', {
    name: 'ctf_start',
    arguments: { category: 'web', objective: 'need service endpoint' },
  })
  assert.equal(human.result.structuredContent.status, 'human_required')
  assert.equal(human.result.structuredContent.humanRequired[0].type, 'start_service')
  assert.equal(human.result.structuredContent.humanRequired[0].operationOrder[0].kind, 'instruction')
  assert.equal(human.result.structuredContent.toolGraph.entry, 'ctf_http_request')

  const server = createServer((req, res) => {
    const body = req.url === '/right' ? 'right-body' : 'left-body'
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(body)
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  const port = typeof address === 'object' && address ? address.port : null
  assert.ok(port)

  const http = await request('tools/call', {
    name: 'ctf_http_request',
    arguments: { url: `http://127.0.0.1:${port}/left`, method: 'GET' },
  })
  assert.equal(http.result.structuredContent.status, 'ok')
  assert.equal(http.result.structuredContent.response.statusCode, 200)

  const diff = await request('tools/call', {
    name: 'ctf_http_diff',
    arguments: {
      urlA: `http://127.0.0.1:${port}/left`,
      urlB: `http://127.0.0.1:${port}/right`,
      method: 'GET',
    },
  })
  assert.equal(diff.result.structuredContent.diff.bodyHashChanged, true)

  server.close()
})
