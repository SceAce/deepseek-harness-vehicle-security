import assert from 'node:assert/strict'
import { mkdtemp, symlink, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { resolveWorkspaceFile } from '../lib/paths.js'

test('resolves a regular file inside workspaceRoot', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'dsh-vehicle-path-'))
  t.after(() => import('node:fs/promises').then(fs => fs.rm(root, { recursive: true, force: true })))
  await writeFile(path.join(root, 'firmware.bin'), 'fixture')
  const result = await resolveWorkspaceFile(root, 'firmware.bin', 1024)
  assert.equal(result.relativePath, 'firmware.bin')
})

test('rejects direct and symlink workspace escapes', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'dsh-vehicle-root-'))
  const outside = await mkdtemp(path.join(os.tmpdir(), 'dsh-vehicle-outside-'))
  t.after(async () => {
    const fs = await import('node:fs/promises')
    await fs.rm(root, { recursive: true, force: true })
    await fs.rm(outside, { recursive: true, force: true })
  })
  await writeFile(path.join(outside, 'secret.bin'), 'fixture')
  await symlink(path.join(outside, 'secret.bin'), path.join(root, 'link.bin'))
  await assert.rejects(resolveWorkspaceFile(root, '../secret.bin', 1024))
  await assert.rejects(resolveWorkspaceFile(root, 'link.bin', 1024), /escapes configured workspaceRoot/)
})
