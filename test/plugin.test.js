import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { Context } from '@deepseek-ai/cordis'
import SkillRegistry from '@deepseek-ai/dsh-skill'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import * as plugin from '../lib/index.js'
import * as skillPlugin from '../lib/skills.js'

const { apply, inject, name } = plugin

const config = {
  workspaceRoot: '.',
  maxFileBytes: 1024 * 1024,
  maxOutputChars: 4000,
  commandTimeoutMs: 5000,
  enableBinwalk: false,
}

test('exports a namespace plugin and registers six tools', () => {
  const registered = []
  apply({ tools: { register: tool => registered.push(tool) } }, config)
  assert.equal(name, 'vehicle-security-tools')
  assert.deepEqual(inject, ['tools'])
  assert.deepEqual(registered.map(tool => tool.name), [
    'vehicle_investigation_plan',
    'vehicle_tool_audit',
    'vehicle_can_log_summary',
    'vehicle_uds_decode',
    'vehicle_program_analyze',
    'vehicle_artifact_triage',
  ])
})

test('file tools resolve paths from the active session workspace', async t => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'dsh-vehicle-session-'))
  t.after(() => import('node:fs/promises').then(fs => fs.rm(workspace, { recursive: true, force: true })))
  await writeFile(path.join(workspace, 'capture.log'), '(1.000000) can0 123#0102\n')

  const registered = []
  apply({ tools: { register: tool => registered.push(tool) } }, {
    ...config,
    workspaceRoot: undefined,
  })
  const tool = registered.find(item => item.name === 'vehicle_can_log_summary')
  const result = await tool.execute(
    { path: 'capture.log' },
    {
      signal: new AbortController().signal,
      agent: { session: { header: { cwd: workspace } } },
    },
  )

  assert.equal(result.path, 'capture.log')
  assert.equal(result.parsedFrames, 1)
})

test('registers packaged vehicle skills through an independent provider', async () => {
  const ctx = new Context()
  await ctx.plugin(SkillRegistry)
  const fiber = await ctx.plugin(skillPlugin)

  const skills = await ctx.skills.list({ cwd: process.cwd() })
  assert.deepEqual(skills.map(skill => skill.name), [
    'analyze-vehicle-security',
    'investigate-vehicle-security',
  ])
  assert.ok(skills.every(skill => skill.provider === 'vehicle-security'))
  assert.ok(skills.every(skill => skill.source === 'bundled'))

  const investigation = await ctx.skills.get('investigate-vehicle-security', { cwd: process.cwd() })
  assert.match(investigation.content, /vehicle_investigation_plan/)
  assert.equal(investigation.resourceBase.kind, 'directory')

  await fiber.dispose()
  assert.deepEqual(await ctx.skills.list({ cwd: process.cwd() }), [])
})

test('registered UDS tool validates and executes through defineTool', async () => {
  const registered = []
  apply({ tools: { register: tool => registered.push(tool) } }, config)
  const tool = registered.find(item => item.name === 'vehicle_uds_decode')
  const result = await tool.execute(
    { payload: '03 22 F1 90' },
    { signal: new AbortController().signal },
  )
  assert.equal(result.dataIdentifier, '0xF190')
})

test('registered investigation tool routes a prompt through defineTool', async () => {
  const registered = []
  apply({ tools: { register: tool => registered.push(tool) } }, config)
  const tool = registered.find(item => item.name === 'vehicle_investigation_plan')
  const result = await tool.execute(
    { objective: 'Decode UDS diagnostic frames', inputKind: 'prompt' },
    { signal: new AbortController().signal },
  )
  assert.equal(result.selectedLane, 'can-uds')
  assert.equal(result.inputKind, 'prompt')
})

test('mounts on real Cordis services and cleans up registrations', async () => {
  const ctx = new Context()
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  const fiber = await ctx.plugin(plugin, config)
  const names = ctx.tools.schemas().map(tool => tool.name)
  assert.deepEqual(names.filter(toolName => toolName.startsWith('vehicle_')), [
    'vehicle_investigation_plan',
    'vehicle_tool_audit',
    'vehicle_can_log_summary',
    'vehicle_uds_decode',
    'vehicle_program_analyze',
    'vehicle_artifact_triage',
  ])
  await fiber.dispose()
  assert.equal(ctx.tools.schemas().some(tool => tool.name.startsWith('vehicle_')), false)
})
