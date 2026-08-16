import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { triageArtifact } from '../src/artifact.js'
import { resolveWorkspaceFile } from '../src/paths.js'

test('computes deterministic artifact metadata without extraction', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'dsh-vehicle-artifact-'))
  t.after(() => import('node:fs/promises').then(fs => fs.rm(root, { recursive: true, force: true })))
  await writeFile(path.join(root, 'sample.bin'), Buffer.from('vehicle-security'))
  const file = await resolveWorkspaceFile(root, 'sample.bin', 1024)
  const result = await triageArtifact(file, { enableBinwalk: false })
  assert.equal(result.path, 'sample.bin')
  assert.equal(result.sizeBytes, 16)
  assert.match(result.sha256, /^[0-9a-f]{64}$/)
  assert.equal(result.binwalk, null)
})
