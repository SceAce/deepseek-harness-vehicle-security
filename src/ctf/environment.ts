import { constants } from 'node:fs'
import { access, readdir } from 'node:fs/promises'
import path from 'node:path'
import { findExecutable } from '../paths.js'

export interface CtfPythonEnvironment {
  policy: 'fixed'
  requiredExecutable: string
  executable: string | null
  source: string | null
  venv: string | null
  bin: string | null
  searchPath: string
}

export const DEFAULT_CTF_PYTHON = '/home/source/tools/PyVenv/CTF/bin/python'
export const DEFAULT_CTF_IDA_CLI_CANDIDATES = [
  '/home/source/CTF_PWN/tools/IDA/IDA-Pro-9.3/IDA-9-3/idat64',
  '/home/source/CTF_PWN/tools/IDA/IDA-Pro-9.3/IDA-9-3/idat',
  '/home/source/CTF_PWN/tools/IDA/IDA-Pro-9.3/IDA-9-3/ida64',
  '/home/source/CTF_PWN/tools/IDA/IDA-Pro-9.3/IDA-9-3/ida',
] as const

export async function discoverCtfPython(cwd = process.cwd()): Promise<CtfPythonEnvironment> {
  const selected = await isExecutable(DEFAULT_CTF_PYTHON)
    ? { executable: DEFAULT_CTF_PYTHON, source: 'fixed-default' }
    : null

  const bin = selected ? path.dirname(selected.executable) : null
  const venv = bin && path.basename(bin) === 'bin' ? path.dirname(bin) : null
  return {
    policy: 'fixed',
    requiredExecutable: DEFAULT_CTF_PYTHON,
    executable: selected?.executable ?? null,
    source: selected?.source ?? 'fixed-default (missing)',
    venv,
    bin,
    searchPath: await ctfSearchPath(cwd, bin),
  }
}

export async function findCtfExecutable(name: string, cwd = process.cwd()): Promise<string | null> {
  const environment = await discoverCtfPython(cwd)
  return findExecutable(name, environment.searchPath)
}

export async function findCtfIdaExecutable(cwd = process.cwd()): Promise<string | null> {
  const configured = expandHome(process.env.DSH_CTF_IDA?.trim() ?? '')
  const searchPath = await ctfSearchPath(cwd)
  const candidates = [
    ...(configured ? [configured] : []),
    ...DEFAULT_CTF_IDA_CLI_CANDIDATES,
    'idat64',
    'idat',
    'ida64',
    'ida',
  ]
  for (const candidate of deduplicateStrings(candidates)) {
    const executable = await findExecutable(candidate, searchPath)
    if (executable) return executable
  }
  return null
}

export async function ctfSearchPath(cwd = process.cwd(), selectedPythonBin?: string | null): Promise<string> {
  const directories = [
    selectedPythonBin,
    DEFAULT_CTF_PYTHON && path.dirname(DEFAULT_CTF_PYTHON),
    ...(await discoverRubyGemBins()),
    ...(process.env.PATH ?? '').split(path.delimiter),
  ]
  return [...new Set(directories.filter((item): item is string => Boolean(item && item.trim())))]
    .join(path.delimiter)
}

async function discoverRubyGemBins(): Promise<string[]> {
  const home = process.env.HOME
  const roots = [
    process.env.GEM_HOME,
    home ? path.join(home, '.local', 'share', 'gem', 'ruby') : null,
    home ? path.join(home, '.gem', 'ruby') : null,
  ].filter((item): item is string => Boolean(item && item.trim()))
  const directories: string[] = []

  for (const root of roots) {
    if (process.env.GEM_HOME === root) {
      directories.push(path.join(root, 'bin'))
      continue
    }
    try {
      const entries = await readdir(root, { withFileTypes: true })
      for (const entry of entries) {
        if (entry.isDirectory()) directories.push(path.join(root, entry.name, 'bin'))
      }
    } catch {
      // A missing Ruby user-gem directory is not a capability failure.
    }
  }
  return directories
}

async function isExecutable(candidate: string): Promise<boolean> {
  try {
    await access(candidate, constants.X_OK)
    return true
  } catch {
    return false
  }
}

function expandHome(value: string): string {
  if (value === '~') return process.env.HOME ?? value
  if (value.startsWith('~/')) return path.join(process.env.HOME ?? '~', value.slice(2))
  if (value.startsWith('$HOME/')) return path.join(process.env.HOME ?? '$HOME', value.slice(6))
  return value
}

function deduplicateStrings(candidates: readonly string[]): string[] {
  const seen = new Set<string>()
  return candidates.filter(candidate => {
    if (seen.has(candidate)) return false
    seen.add(candidate)
    return true
  })
}
