import assert from 'node:assert/strict'
import { chmod, copyFile, mkdtemp, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { once } from 'node:events'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { Context } from '@deepseek-ai/cordis'
import SkillRegistry from '@deepseek-ai/dsh-skill'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import * as ctfPlugin from '../lib/ctf/index.js'
import * as ctfSkillPlugin from '../lib/ctf/skills.js'
import { DEFAULT_CTF_PYTHON, discoverCtfPython, findCtfIdaExecutable } from '../lib/ctf/environment.js'

const config = {
  workspaceRoot: '.',
  maxFileBytes: 1024 * 1024,
  maxOutputChars: 4000,
  commandTimeoutMs: 1500,
}

const CTF_TOOL_NAMES = [
  'ctf_tool_audit',
  'ctf_mcp_configure',
  'ctf_artifact_profile',
  'ctf_start',
  'ctf_re_profile',
  'ctf_pwn_profile',
  'ctf_pwninit',
  'ctf_pwn_debug_probe',
  'ctf_pwn_gdb_probe',
  'ctf_re_r2_query',
  'ctf_re_ida_script',
  'ctf_rop_search',
  'ctf_crypto_probe',
  'ctf_misc_triage',
  'ctf_pcap_profile',
  'ctf_http_request',
  'ctf_http_diff',
  'ctf_web_browser_probe',
  'ctf_web_capture_probe',
  'ctf_tool_setup',
  'ctf_human_request',
]

const CTF_SKILL_NAMES = [
  'investigate-ctf',
  'solve-ctf-pwn',
  'solve-ctf-re',
  'solve-ctf-web',
]

test('exports an independent CTF namespace and registers core tools', () => {
  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, config)
  assert.equal(ctfPlugin.name, 'ctf-tools')
  assert.deepEqual(ctfPlugin.inject, ['tools'])
  assert.deepEqual(registered.map(tool => tool.name), CTF_TOOL_NAMES)
})

test('CTF tools resolve paths from the active session workspace', async t => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'dsh-ctf-session-'))
  t.after(() => import('node:fs/promises').then(fs => fs.rm(workspace, { recursive: true, force: true })))
  await writeFile(path.join(workspace, 'cipher.txt'), 'cipher = 414243\nflag format test\n')

  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, {
    ...config,
    workspaceRoot: undefined,
  })
  const profile = registered.find(item => item.name === 'ctf_artifact_profile')
  const result = await profile.execute(
    { path: 'cipher.txt' },
    {
      signal: new AbortController().signal,
      agent: { session: { header: { cwd: workspace } } },
    },
  )

  assert.equal(result.artifact.path, 'cipher.txt')
  assert.equal(result.status, 'ok')
  assert.match(result.artifact.sha256, /^[0-9a-f]{64}$/)
})

test('ctf_start routes an ELF artifact to pwninit first', async t => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'dsh-ctf-elf-'))
  t.after(() => import('node:fs/promises').then(fs => fs.rm(workspace, { recursive: true, force: true })))
  await copyFile('/bin/true', path.join(workspace, 'chall'))

  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, {
    ...config,
    workspaceRoot: undefined,
  })
  const start = registered.find(item => item.name === 'ctf_start')
  const result = await start.execute(
    { objective: 'solve this pwn challenge', path: 'chall' },
    {
      signal: new AbortController().signal,
      agent: { session: { header: { cwd: workspace } } },
    },
  )

  assert.equal(result.category, 'pwn')
  assert.equal(result.recommendedTool, 'ctf_pwninit')
  assert.deepEqual(result.recommendedArgs, { path: 'chall', mode: 'prepare' })
  assert.ok(Array.isArray(result.toolChoices))
  assert.equal(result.toolChoices[0].tool, 'ctf_pwninit')
  assert.ok(result.toolChoices.some(choice => choice.tool === 'ctf_pwn_gdb_probe'))
  assert.ok(result.toolChoices.some(choice => choice.tool === 'ctf_re_r2_query'))
  assert.equal(result.toolGraph.entry, 'ctf_pwninit')
  assert.ok(result.toolGraph.edges.some(edge => edge.to === 'ctf_pwn_debug_probe'))
})

test('uses the fixed CTF Python interpreter without environment fallbacks', async () => {
  const previous = {
    python: process.env.DSH_CTF_PYTHON,
    virtualEnv: process.env.VIRTUAL_ENV,
  }
  process.env.DSH_CTF_PYTHON = '/usr/bin/python3'
  process.env.VIRTUAL_ENV = '/tmp/not-the-ctf-venv'
  try {
    const environment = await discoverCtfPython()
    assert.equal(environment.policy, 'fixed')
    assert.equal(environment.requiredExecutable, DEFAULT_CTF_PYTHON)
    assert.equal(environment.executable, DEFAULT_CTF_PYTHON)
    assert.equal(environment.source, 'fixed-default')
  } finally {
    if (previous.python === undefined) delete process.env.DSH_CTF_PYTHON
    else process.env.DSH_CTF_PYTHON = previous.python
    if (previous.virtualEnv === undefined) delete process.env.VIRTUAL_ENV
    else process.env.VIRTUAL_ENV = previous.virtualEnv
  }
})

test('detects an IDA CLI absolute path supplied through DSH_CTF_IDA', async t => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'dsh-ctf-ida-'))
  t.after(() => import('node:fs/promises').then(fs => fs.rm(workspace, { recursive: true, force: true })))
  const ida = path.join(workspace, 'ida')
  await writeFile(ida, '#!/bin/sh\nexit 0\n')
  await chmod(ida, 0o755)
  const previous = process.env.DSH_CTF_IDA
  process.env.DSH_CTF_IDA = ida
  try {
    assert.equal(await findCtfIdaExecutable(), ida)
  } finally {
    if (previous === undefined) delete process.env.DSH_CTF_IDA
    else process.env.DSH_CTF_IDA = previous
  }
})

test('ctf_re_profile returns structured facts for an ELF artifact', async t => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'dsh-ctf-re-'))
  t.after(() => import('node:fs/promises').then(fs => fs.rm(workspace, { recursive: true, force: true })))
  await copyFile('/bin/true', path.join(workspace, 'chall'))

  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, {
    ...config,
    workspaceRoot: undefined,
  })
  const profile = registered.find(item => item.name === 'ctf_re_profile')
  const result = await profile.execute(
    { path: 'chall' },
    {
      signal: new AbortController().signal,
      agent: { session: { header: { cwd: workspace } } },
    },
  )

  assert.equal(result.artifact.path, 'chall')
  assert.equal(result.binary.format, 'elf')
  assert.ok(result.nextActions.some(action => action.tool === 'ctf_re_r2_query'))
  assert.ok(result.nextActions.some(action => action.tool === 'ctf_re_ida_script'))
  assert.ok(result.nextActions.some(action => action.tool === 'ctf_crypto_probe'))
})

test('ctf_pwn_profile returns structured binary facts for an ELF artifact', async t => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'dsh-ctf-pwn-'))
  t.after(() => import('node:fs/promises').then(fs => fs.rm(workspace, { recursive: true, force: true })))
  await copyFile('/bin/true', path.join(workspace, 'chall'))

  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, {
    ...config,
    workspaceRoot: undefined,
  })
  const profile = registered.find(item => item.name === 'ctf_pwn_profile')
  const result = await profile.execute(
    { path: 'chall' },
    {
      signal: new AbortController().signal,
      agent: { session: { header: { cwd: workspace } } },
    },
  )

  assert.equal(result.artifact.path, 'chall')
  assert.equal(result.binary.format, 'elf')
  assert.ok(result.nextActions.some(action => action.tool === 'ctf_pwninit'))
  assert.ok(!result.nextActions.some(action => action.tool === 'ctf_pwn_toolchain'))
  assert.ok(result.nextActions.some(action => action.tool === 'ctf_pwn_gdb_probe'))
  assert.ok(result.nextActions.some(action => action.tool === 'ctf_pwn_debug_probe'))
})

test('ctf_pwninit exposes deterministic runtime and backup operations', async t => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'dsh-ctf-pwninit-'))
  t.after(() => import('node:fs/promises').then(fs => fs.rm(workspace, { recursive: true, force: true })))
  await copyFile('/bin/true', path.join(workspace, 'chall'))

  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, {
    ...config,
    workspaceRoot: undefined,
    commandTimeoutMs: 5000,
  })
  const pwninit = registered.find(item => item.name === 'ctf_pwninit')
  const result = await pwninit.execute(
    { path: 'chall', mode: 'list_backups' },
    {
      signal: new AbortController().signal,
      agent: { session: { header: { cwd: workspace } } },
    },
  )

  if (result.status === 'missing_capability') {
    t.skip('pwninit is not installed in this test environment')
    return
  }
  assert.equal(result.pwninit.mode, 'list_backups')
  assert.equal(result.pwninit.binary, 'chall')
  assert.ok(result.commands.some(command => command.argv.includes('--list-backups')))
})

test('ctf_pwninit runs the initialization-only path when no libc source exists', async t => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'dsh-ctf-pwninit-init-'))
  t.after(() => import('node:fs/promises').then(fs => fs.rm(workspace, { recursive: true, force: true })))
  await copyFile('/bin/true', path.join(workspace, 'chall'))

  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, {
    ...config,
    workspaceRoot: undefined,
    commandTimeoutMs: 5000,
  })
  const pwninit = registered.find(item => item.name === 'ctf_pwninit')
  const result = await pwninit.execute(
    { path: 'chall', mode: 'prepare' },
    {
      signal: new AbortController().signal,
      agent: { session: { header: { cwd: workspace } } },
    },
  )

  if (result.status === 'missing_capability') {
    t.skip('pwninit is not installed in this test environment')
    return
  }
  assert.equal(result.status, 'ok')
  assert.equal(result.pwninit.initializationOnly, true)
  assert.ok(result.pwninit.command.includes('--only-init'))
  assert.equal(result.nextActions[0].tool, 'ctf_pwn_profile')
})

test('ctf_pwninit stays lossless through the real DSH tool runtime', async t => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'dsh-ctf-pwninit-runtime-'))
  t.after(() => import('node:fs/promises').then(fs => fs.rm(workspace, { recursive: true, force: true })))
  await copyFile('/bin/true', path.join(workspace, 'chall'))

  const ctx = new Context()
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime, { mode: 'native' })
  await ctx.plugin(ctfPlugin, {
    ...config,
    workspaceRoot: workspace,
    commandTimeoutMs: 5000,
  })

  const result = await ctx.tools.execute({
    callId: 'ctf-runtime-pwninit',
    name: 'ctf_pwninit',
    arguments: { path: 'chall', mode: 'list_backups' },
    signal: new AbortController().signal,
  })

  assert.equal(result.isError, false)
  assert.ok(result.content.some(block => block.type === 'text'))
})

test('ctf_pwn_gdb_probe calls local GDB with Pwndbg commands', async t => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'dsh-ctf-pwndbg-'))
  t.after(() => import('node:fs/promises').then(fs => fs.rm(workspace, { recursive: true, force: true })))
  await copyFile('/bin/true', path.join(workspace, 'chall'))

  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, {
    ...config,
    workspaceRoot: undefined,
    commandTimeoutMs: 5000,
  })
  const probe = registered.find(item => item.name === 'ctf_pwn_gdb_probe')
  const result = await probe.execute(
    { path: 'chall' },
    {
      signal: new AbortController().signal,
      agent: { session: { header: { cwd: workspace } } },
    },
  )

  assert.equal(result.status, 'ok')
  assert.equal(result.debugger.frontend, 'pwndbg')
  assert.match(result.debugger.output, /pwndbg/i)
  assert.ok(result.commands.some(command => command.executable.endsWith('/gdb')))
})

test('ctf_re_r2_query executes local radare2 and ctf_re_ida_script remains useful without IDA', async t => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'dsh-ctf-retools-'))
  t.after(() => import('node:fs/promises').then(fs => fs.rm(workspace, { recursive: true, force: true })))
  await copyFile('/bin/true', path.join(workspace, 'chall'))

  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, {
    ...config,
    workspaceRoot: undefined,
    commandTimeoutMs: 5000,
  })
  const r2Tool = registered.find(item => item.name === 'ctf_re_r2_query')
  const idaTool = registered.find(item => item.name === 'ctf_re_ida_script')
  const execution = {
    signal: new AbortController().signal,
    agent: { session: { header: { cwd: workspace } } },
  }
  const r2 = await r2Tool.execute({ path: 'chall', commands: ['ij'] }, execution)
  const ida = await idaTool.execute({ path: 'chall', focus: 'flag strcmp' }, execution)

  assert.equal(r2.status, 'ok')
  assert.equal(r2.query.commands[0], 'ij')
  assert.ok(r2.rawOutput)
  assert.match(ida.script, /ida_funcs/)
  assert.match(ida.script, /collect_xrefs/)
  assert.equal(ida.executed, false)
  assert.ok(['ok', 'missing_capability'].includes(ida.status))
})

test('ctf_tool_audit exposes local capability and external MCP state', async () => {
  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, {
    ...config,
    commandTimeoutMs: 5000,
  })
  const auditTool = registered.find(item => item.name === 'ctf_tool_audit')
  const result = await auditTool.execute({}, { signal: new AbortController().signal })

  assert.ok(Array.isArray(result.capabilities))
  assert.ok(Array.isArray(result.mcp))
  assert.ok(result.mcp.some(item => item.id === 'mcp.ida_pro'))
  assert.ok(result.mcp.some(item => item.id === 'mcp.chrome'))
  assert.ok(result.mcp.some(item => item.id === 'mcp.tavily'))
  assert.ok(Array.isArray(result.toolBindings))
  const gdbBinding = result.toolBindings.find(item => item.tool === 'ctf_pwn_gdb_probe')
  assert.equal(gdbBinding.callable, true)
  assert.ok(gdbBinding.backendCapabilities.includes('pwn.gdb'))
  const r2Binding = result.toolBindings.find(item => item.tool === 'ctf_re_r2_query')
  assert.equal(r2Binding.callable, true)
  assert.ok(r2Binding.exampleArgs.commands.includes('aaa'))
  assert.ok(result.capabilities.some(item => item.id === 're.r2'))
  assert.ok(result.capabilities.some(item => item.id === 'pwn.pwndbg'))
  assert.ok(result.capabilities.some(item => item.id === 'web.mcp_chrome_bridge'))
  assert.match(result.python.executable ?? '', /python/)
  assert.ok('source' in result.python)
  assert.ok('venv' in result.python)
})

test('CTF audit and start results are lossless through the real DSH tool runtime', async t => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'dsh-ctf-runtime-'))
  t.after(() => import('node:fs/promises').then(fs => fs.rm(workspace, { recursive: true, force: true })))
  await copyFile('/bin/true', path.join(workspace, 'pwn'))

  const ctx = new Context()
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime, { mode: 'native' })
  await ctx.plugin(ctfPlugin, {
    ...config,
    workspaceRoot: workspace,
    commandTimeoutMs: 5000,
  })

  const signal = new AbortController().signal
  const audit = await ctx.tools.execute({
    callId: 'ctf-runtime-audit',
    name: 'ctf_tool_audit',
    arguments: {},
    signal,
  })
  assert.equal(audit.isError, false)
  assert.ok(audit.content.some(block => block.type === 'text'))

  const start = await ctx.tools.execute({
    callId: 'ctf-runtime-start',
    name: 'ctf_start',
    arguments: { objective: 'pwn runtime regression', path: 'pwn' },
    signal,
  })
  assert.equal(start.isError, false)
  assert.ok(start.content.some(block => block.type === 'text'))
})

test('ctf_mcp_configure writes key-only external MCP configuration without returning secrets', async t => {
  const configPath = path.join(await mkdtemp(path.join(os.tmpdir(), 'dsh-ctf-mcp-')), 'ctf-mcp.json')
  t.after(() => import('node:fs/promises').then(fs => fs.rm(path.dirname(configPath), { recursive: true, force: true })))
  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, config)
  const configure = registered.find(item => item.name === 'ctf_mcp_configure')
  const result = await configure.execute({
    configPath,
    includeChrome: true,
    includeTavily: true,
    tavilyApiKey: 'test-tavily-secret',
  }, { signal: new AbortController().signal })

  assert.equal(result.status, 'ok')
  assert.deepEqual(result.configured, ['mcp.chrome', 'mcp.tavily'])
  assert.deepEqual(result.requiredSecrets, [])
  assert.doesNotMatch(JSON.stringify(result), /test-tavily-secret/)
  const document = JSON.parse(await import('node:fs/promises').then(fs => fs.readFile(configPath, 'utf8')))
  assert.ok(document.mcpServers['mcp-chrome'].command || document.mcpServers['mcp-chrome'].url)
  assert.equal(document.mcpServers['tavily-mcp'].env.TAVILY_API_KEY, 'test-tavily-secret')
})

test('ctf_mcp_configure asks only for the Tavily key when it is missing', async t => {
  const configPath = path.join(await mkdtemp(path.join(os.tmpdir(), 'dsh-ctf-mcp-missing-')), 'ctf-mcp.json')
  t.after(() => import('node:fs/promises').then(fs => fs.rm(path.dirname(configPath), { recursive: true, force: true })))
  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, config)
  const configure = registered.find(item => item.name === 'ctf_mcp_configure')
  const result = await configure.execute({
    configPath,
    includeChrome: false,
    includeTavily: true,
  }, { signal: new AbortController().signal })

  assert.equal(result.status, 'missing_capability')
  assert.deepEqual(result.configured, [])
  assert.deepEqual(result.requiredSecrets, ['TAVILY_API_KEY'])
  assert.match(result.limitations[0], /TAVILY_API_KEY/)
})

test('ctf_crypto_probe detects simple hex text before script generation', async () => {
  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, config)
  const probe = registered.find(item => item.name === 'ctf_crypto_probe')
  const result = await probe.execute(
    { text: '414243' },
    { signal: new AbortController().signal },
  )

  assert.equal(result.status, 'ok')
  assert.equal(result.encodings[0].type, 'hex')
  assert.equal(result.encodings[0].decodedPreview, 'ABC')
})

test('ctf_http_request and ctf_http_diff work against a local HTTP service', async () => {
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

  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, config)
  const request = registered.find(item => item.name === 'ctf_http_request')
  const diff = registered.find(item => item.name === 'ctf_http_diff')
  const left = await request.execute(
    { url: `http://127.0.0.1:${port}/left`, method: 'GET' },
    { signal: new AbortController().signal },
  )
  const compared = await diff.execute(
    {
      urlA: `http://127.0.0.1:${port}/left`,
      urlB: `http://127.0.0.1:${port}/right`,
      method: 'GET',
    },
    { signal: new AbortController().signal },
  )

  assert.equal(left.status, 'ok')
  assert.equal(left.response.statusCode, 200)
  assert.ok(left.nextActions.some(action => action.tool === 'ctf_web_browser_probe'))
  assert.ok(left.nextActions.some(action => action.tool === 'ctf_web_capture_probe'))
  assert.equal(compared.diff.bodyHashChanged, true)

  server.close()
})

test('ctf_web_browser_probe makes a real local browser invocation', async t => {
  const server = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end('<title>DSH CTF</title><main>browser probe</main>')
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => server.close())
  const address = server.address()
  const port = typeof address === 'object' && address ? address.port : null
  assert.ok(port)

  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, {
    ...config,
    commandTimeoutMs: 10000,
  })
  const browser = registered.find(item => item.name === 'ctf_web_browser_probe')
  const result = await browser.execute(
    { url: `http://127.0.0.1:${port}/`, captureScreenshot: false },
    { signal: new AbortController().signal },
  )

  assert.ok(result.browser)
  assert.equal(result.url, `http://127.0.0.1:${port}/`)
  assert.ok(result.commands.length >= 1)
  assert.ok(['ok', 'failed'].includes(result.status))
})

test('ctf_web_capture_probe reports proxy capability or setup handoff', async () => {
  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, {
    ...config,
    commandTimeoutMs: 5000,
  })
  const capture = registered.find(item => item.name === 'ctf_web_capture_probe')
  const result = await capture.execute({}, { signal: new AbortController().signal })

  assert.ok(['ok', 'human_required', 'missing_capability', 'failed'].includes(result.status))
  if (result.proxy) {
    assert.match(result.launchCommand, /mitm/)
    assert.ok(result.humanRequired.length > 0)
  } else {
    assert.ok(result.nextActions.some(action => action.tool === 'ctf_tool_setup'))
  }
})

test('ctf_tool_setup enforces ordered human operations and return types', async () => {
  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, config)
  const setup = registered.find(item => item.name === 'ctf_tool_setup')
  const result = await setup.execute({ target: 'chrome_mcp' }, { signal: new AbortController().signal })

  assert.equal(result.status, 'human_required')
  assert.ok(result.request.operationOrder.length >= 2)
  assert.ok(result.request.operationOrder.every(operation => operation.command || operation.instruction))
  assert.deepEqual(result.request.acceptedReturnTypes, ['log', 'screenshot', 'ocr_text'])
  assert.deepEqual(result.request.returnContract.onlyReturn, ['log', 'screenshot', 'ocr_text'])
})

test('ctf_start returns structured human request for web service gaps', async () => {
  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, config)
  const start = registered.find(item => item.name === 'ctf_start')
  const result = await start.execute(
    { category: 'web', objective: 'web challenge service is not started yet' },
    { signal: new AbortController().signal },
  )

  assert.equal(result.status, 'human_required')
  assert.equal(result.recommendedTool, 'ctf_human_request')
  assert.equal(result.humanRequired[0].type, 'start_service')
  assert.equal(result.humanRequired[0].operationOrder[0].kind, 'instruction')
  assert.equal(result.toolGraph.entry, 'ctf_http_request')
})

test('ctf_human_request creates deterministic structured request IDs', async () => {
  const registered = []
  ctfPlugin.apply({ tools: { register: tool => registered.push(tool) } }, config)
  const human = registered.find(item => item.name === 'ctf_human_request')
  const result = await human.execute(
    {
      type: 'start_service',
      title: 'Start challenge',
      reason: 'Need a local URL.',
      operationOrder: [
        {
          order: 2,
          kind: 'command',
          title: 'Confirm the endpoint',
          command: 'curl -i -sS --max-time 5 http://HOST:PORT/',
          expectedSignal: 'Return the response headers and body preview as log text.',
        },
        {
          order: 1,
          kind: 'instruction',
          title: 'Start the service',
          instruction: 'Run the provided service.',
          expectedSignal: 'Return a log line with the listening host and port.',
        },
      ],
      acceptedReturnTypes: ['log', 'ocr_text'],
      returnFields: { log: 'startup log', ocr_text: 'OCR text with host and port' },
    },
    { signal: new AbortController().signal },
  )

  assert.equal(result.status, 'human_required')
  assert.match(result.requestId, /^human-[0-9a-f]{12}$/)
  assert.equal(result.request.type, 'start_service')
  assert.equal(result.request.operationOrder[0].title, 'Start the service')
  assert.equal(result.request.operationOrder[1].kind, 'command')
  assert.deepEqual(result.request.acceptedReturnTypes, ['log', 'ocr_text'])
})

test('registers packaged CTF skill through a separate provider', async () => {
  const ctx = new Context()
  await ctx.plugin(SkillRegistry)
  const fiber = await ctx.plugin(ctfSkillPlugin)

  const skills = await ctx.skills.list({ cwd: process.cwd() })
  assert.deepEqual(skills.map(skill => skill.name).sort(), CTF_SKILL_NAMES)
  assert.ok(skills.every(skill => skill.provider === 'ctf-security'))

  const investigation = await ctx.skills.get('investigate-ctf', { cwd: process.cwd() })
  assert.match(investigation.content, /ctf_start/)
  assert.match((await ctx.skills.get('solve-ctf-re', { cwd: process.cwd() })).content, /ctf_re_profile/)
  assert.match((await ctx.skills.get('solve-ctf-pwn', { cwd: process.cwd() })).content, /ctf_pwn_profile/)
  assert.match((await ctx.skills.get('solve-ctf-web', { cwd: process.cwd() })).content, /ctf_http_request/)

  await fiber.dispose()
  assert.deepEqual(await ctx.skills.list({ cwd: process.cwd() }), [])
})

test('mounts CTF tools on real Cordis services without vehicle namespace overlap', async () => {
  const ctx = new Context()
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  const fiber = await ctx.plugin(ctfPlugin, config)

  const names = ctx.tools.schemas().map(tool => tool.name)
  assert.deepEqual(names.filter(toolName => toolName.startsWith('ctf_')), CTF_TOOL_NAMES)
  assert.equal(names.some(toolName => toolName.startsWith('vehicle_')), false)

  await fiber.dispose()
  assert.equal(ctx.tools.schemas().some(toolName => toolName.startsWith('ctf_')), false)
})
