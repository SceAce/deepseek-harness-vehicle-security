#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const skillDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const runtime = name => import(path.join(skillDir, 'runtime', `${name}.js`))
const args = process.argv.slice(2)
const command = args.shift()

function option(name) {
  const index = args.indexOf(name)
  return index >= 0 ? args[index + 1] : undefined
}

function has(name) {
  return args.includes(name)
}

function usage() {
  console.error('usage: vehicle_security.mjs audit | uds-decode | can-summary --path PATH | artifact-triage --path PATH | program-analyze --path PATH')
  process.exitCode = 2
}

const workspaceRoot = process.env.VEHICLE_WORKSPACE_ROOT ?? process.cwd()

async function workspaceFile(filePath) {
  const { resolveWorkspaceFile } = await runtime('paths')
  return resolveWorkspaceFile(
    workspaceRoot,
    path.relative(workspaceRoot, path.resolve(filePath)),
    256 * 1024 * 1024,
  )
}

try {
  if (command === 'audit') {
    const { auditTools } = await runtime('audit')
    console.log(JSON.stringify(await auditTools(), null, 2))
  } else if (command === 'uds-decode') {
    const payload = option('--payload')
    if (!payload) throw new Error('--payload is required')
    const { decodeUds } = await runtime('uds')
    console.log(JSON.stringify(decodeUds(payload, !has('--no-isotp')), null, 2))
  } else if (command === 'can-summary') {
    const filePath = option('--path')
    if (!filePath) throw new Error('--path is required')
    const { parseCanLog } = await runtime('can')
    const file = await workspaceFile(filePath)
    const text = await readFile(file.path, 'utf8')
    const maxFrames = option('--max-frames')
    console.log(JSON.stringify({ path: file.relativePath, ...parseCanLog(text, {
      idFilter: option('--id-filter'),
      maxFrames: maxFrames === undefined ? undefined : Number(maxFrames),
    }) }, null, 2))
  } else if (command === 'artifact-triage') {
    const filePath = option('--path')
    if (!filePath) throw new Error('--path is required')
    const { triageArtifact } = await runtime('artifact')
    const file = await workspaceFile(filePath)
    console.log(JSON.stringify(await triageArtifact(file, {
      enableBinwalk: !has('--no-binwalk'),
      timeoutMs: 20_000,
      maxOutputChars: 40_000,
    }), null, 2))
  } else if (command === 'program-analyze') {
    const filePath = option('--path')
    if (!filePath) throw new Error('--path is required')
    const { analyzeProgram } = await runtime('program')
    const file = await workspaceFile(filePath)
    const maxStrings = option('--max-strings')
    const minStringLength = option('--min-string-length')
    console.log(JSON.stringify(await analyzeProgram(file, {
      focus: option('--focus'),
      maxStrings: maxStrings === undefined ? undefined : Number(maxStrings),
      minStringLength: minStringLength === undefined ? undefined : Number(minStringLength),
      timeoutMs: 20_000,
      maxOutputChars: 40_000,
    }), null, 2))
  } else {
    usage()
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error))
  process.exitCode = 1
}
