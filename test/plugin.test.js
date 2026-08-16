import assert from 'node:assert/strict'
import test from 'node:test'
import { Context } from '@deepseek-ai/cordis'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import * as plugin from '../lib/index.js'

const { apply, inject, name } = plugin

const config = {
  workspaceRoot: '.',
  maxFileBytes: 1024 * 1024,
  maxOutputChars: 4000,
  commandTimeoutMs: 5000,
  enableBinwalk: false,
}

test('exports a namespace plugin and registers four tools', () => {
  const registered = []
  apply({ tools: { register: tool => registered.push(tool) } }, config)
  assert.equal(name, 'vehicle-security')
  assert.deepEqual(inject, ['tools'])
  assert.deepEqual(registered.map(tool => tool.name), [
    'vehicle_tool_audit',
    'vehicle_can_log_summary',
    'vehicle_uds_decode',
    'vehicle_artifact_triage',
  ])
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

test('mounts on real Cordis services and cleans up registrations', async () => {
  const ctx = new Context()
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  const fiber = await ctx.plugin(plugin, config)
  const names = ctx.tools.schemas().map(tool => tool.name)
  assert.deepEqual(names.filter(toolName => toolName.startsWith('vehicle_')), [
    'vehicle_tool_audit',
    'vehicle_can_log_summary',
    'vehicle_uds_decode',
    'vehicle_artifact_triage',
  ])
  await fiber.dispose()
  assert.equal(ctx.tools.schemas().some(tool => tool.name.startsWith('vehicle_')), false)
})
