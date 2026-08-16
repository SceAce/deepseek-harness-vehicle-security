import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { parseCanLog } from '../lib/can.js'

test('summarizes candump logs and normalizes IDs', async () => {
  const text = await readFile(new URL('../fixtures/candump.log', import.meta.url), 'utf8')
  const result = parseCanLog(text)
  assert.equal(result.format, 'candump')
  assert.equal(result.parsedFrames, 4)
  assert.equal(result.uniqueIds, 3)
  assert.deepEqual(result.topIds[0], { id: '0x123', count: 2, channels: ['can0', 'can1'] })
})

test('parses ASC logs and applies an ID filter', async () => {
  const text = await readFile(new URL('../fixtures/sample.asc', import.meta.url), 'utf8')
  const result = parseCanLog(text, { idFilter: '0x7e0, 7E8' })
  assert.equal(result.format, 'asc')
  assert.equal(result.parsedFrames, 2)
  assert.deepEqual(result.topIds.map(item => item.id), ['0x7E0', '0x7E8'])
})

test('validates maxFrames', () => {
  assert.throws(() => parseCanLog('', { maxFrames: 0 }), /between 1 and 1000000/)
})
