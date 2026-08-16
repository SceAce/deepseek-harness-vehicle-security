import { cp, mkdir, rm } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const runtime = path.join(
  root,
  'codex-plugin/plugins/vehicle-security/skills/analyze-vehicle-security/runtime',
)
const modules = ['artifact', 'audit', 'can', 'paths', 'process', 'program', 'uds']

await rm(runtime, { recursive: true, force: true })
await mkdir(runtime, { recursive: true })
for (const moduleName of modules) {
  await cp(path.join(root, 'lib', `${moduleName}.js`), path.join(runtime, `${moduleName}.js`))
}
