import assert from 'node:assert/strict'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { planInvestigation } from '../lib/investigation.js'
import { resolveWorkspaceFile } from '../lib/paths.js'

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)))

test('routes an ASC attachment into the CAN and UDS lane', async () => {
  const file = await resolveWorkspaceFile(root, 'fixtures/sample.asc', 1024 * 1024)
  const result = await planInvestigation(
    { objective: 'Find and validate diagnostic traffic', inputKind: 'artifact' },
    file,
    { enableBinwalk: false },
  )

  assert.equal(result.selectedLane, 'can-uds')
  assert.equal(result.artifact.path, 'fixtures/sample.asc')
  assert.match(result.caseId, /^vehicle-[0-9a-f]{12}$/)
  assert.equal(result.firstActions[0].tool, 'vehicle_can_log_summary')
  assert.equal(result.phases.at(-1).name, 'conclusion')
})

test('routes a sentence-only UDS implementation clue into firmware analysis', async () => {
  const result = await planInvestigation({
    objective: 'Locate the UDS 0x27 SecurityAccess implementation in ECU firmware',
    inputKind: 'prompt',
  })

  assert.equal(result.selectedLane, 'firmware')
  assert.ok(result.laneCandidates.some(item => item.lane === 'can-uds'))
  assert.match(result.evidenceModel.promotionRule, /success criteria/)
  assert.ok(result.languagePlan.some(item => item.language === 'TypeScript'))
})

test('keeps an uninformative prompt in the unknown lane', async () => {
  const result = await planInvestigation({ objective: 'Please inspect this issue' })
  assert.equal(result.selectedLane, 'unknown')
  assert.equal(result.firstActions[0].tool, 'vehicle_tool_audit and focused intake')
})
