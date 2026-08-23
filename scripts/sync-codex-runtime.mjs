import { cp, mkdir, rm } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const vehicleRuntime = path.join(
  root,
  'codex-plugin/plugins/vehicle-security/skills/analyze-vehicle-security/runtime',
)
const vehicleModules = ['artifact', 'audit', 'can', 'investigation', 'paths', 'process', 'program', 'uds']

await rm(vehicleRuntime, { recursive: true, force: true })
await mkdir(vehicleRuntime, { recursive: true })
for (const moduleName of vehicleModules) {
  await cp(path.join(root, 'lib', `${moduleName}.js`), path.join(vehicleRuntime, `${moduleName}.js`))
}

const ctfRuntime = path.join(
  root,
  'codex-plugin/plugins/ctf-security/skills/investigate-ctf/runtime',
)
const ctfSkillRoot = path.dirname(ctfRuntime)
const ctfModules = ['artifact', 'binary', 'capabilities', 'crypto', 'human', 'misc', 'retools', 'router', 'setup', 'types', 'web']

await rm(ctfRuntime, { recursive: true, force: true })
await mkdir(ctfRuntime, { recursive: true })
for (const moduleName of ctfModules) {
  await cp(path.join(root, 'lib', 'ctf', `${moduleName}.js`), path.join(ctfRuntime, `${moduleName}.js`))
}
await cp(path.join(root, 'lib', 'paths.js'), path.join(ctfRuntime, 'paths.js'))
await cp(path.join(root, 'lib', 'process.js'), path.join(ctfRuntime, 'process.js'))
await cp(path.join(root, 'lib', 'paths.js'), path.join(ctfSkillRoot, 'paths.js'))
await cp(path.join(root, 'lib', 'process.js'), path.join(ctfSkillRoot, 'process.js'))
