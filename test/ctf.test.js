import assert from 'node:assert/strict'
import { copyFile, mkdtemp, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { Context } from '@deepseek-ai/cordis'
import SkillRegistry from '@deepseek-ai/dsh-skill'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import * as ctfPlugin from '../lib/ctf/index.js'
import * as ctfSkillPlugin from '../lib/ctf/skills.js'

const config = {
  workspaceRoot: '.',
  maxFileBytes: 1024 * 1024,
  maxOutputChars: 4000,
  commandTimeoutMs: 1500,
}

const CTF_TOOL_NAMES = [
  'ctf_tool_audit',
  'ctf_artifact_profile',
  'ctf_start',
  'ctf_re_profile',
  'ctf_pwn_profile',
  'ctf_pwn_debug_probe',
  'ctf_rop_search',
  'ctf_crypto_probe',
  'ctf_misc_triage',
  'ctf_pcap_profile',
  'ctf_http_request',
  'ctf_http_diff',
  'ctf_human_request',
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

test('ctf_start routes an ELF artifact to pwn profile first', async t => {
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
  assert.equal(result.recommendedTool, 'ctf_pwn_profile')
  assert.deepEqual(result.recommendedArgs, { path: 'chall' })
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
  assert.ok(result.nextActions.some(action => action.tool === 'ctf_pwn_debug_probe'))
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
      steps: ['Run the provided service.', 'Return host and port.'],
      expectedResult: { host: 'string', port: 'number' },
    },
    { signal: new AbortController().signal },
  )

  assert.equal(result.status, 'human_required')
  assert.match(result.requestId, /^human-[0-9a-f]{12}$/)
  assert.equal(result.request.type, 'start_service')
})

test('registers packaged CTF skill through a separate provider', async () => {
  const ctx = new Context()
  await ctx.plugin(SkillRegistry)
  const fiber = await ctx.plugin(ctfSkillPlugin)

  const skills = await ctx.skills.list({ cwd: process.cwd() })
  assert.deepEqual(skills.map(skill => skill.name), ['investigate-ctf'])
  assert.ok(skills.every(skill => skill.provider === 'ctf-security'))

  const investigation = await ctx.skills.get('investigate-ctf', { cwd: process.cwd() })
  assert.match(investigation.content, /ctf_start/)

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
