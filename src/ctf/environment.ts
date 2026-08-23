import { constants } from 'node:fs'
import { access } from 'node:fs/promises'
import path from 'node:path'
import { findExecutable } from '../paths.js'

export interface CtfPythonEnvironment {
  executable: string | null
  source: string | null
  venv: string | null
  bin: string | null
  searchPath: string
}

const DEFAULT_CTF_PYTHON = '/home/source/tools/PyVenv/CTF/bin/python'

export async function discoverCtfPython(cwd = process.cwd()): Promise<CtfPythonEnvironment> {
  const candidates: Array<{ executable: string; source: string }> = []
  const configured = process.env.DSH_CTF_PYTHON?.trim()
  if (configured) {
    if (path.isAbsolute(configured) || configured.includes(path.sep)) {
      candidates.push({ executable: configured, source: 'DSH_CTF_PYTHON' })
    } else {
      const resolved = await findExecutable(configured)
      if (resolved) candidates.push({ executable: resolved, source: 'DSH_CTF_PYTHON' })
    }
  }

  candidates.push({ executable: DEFAULT_CTF_PYTHON, source: DEFAULT_CTF_PYTHON })

  const virtualEnv = process.env.VIRTUAL_ENV?.trim()
  if (virtualEnv) {
    candidates.push({ executable: path.join(virtualEnv, 'bin', 'python'), source: '$VIRTUAL_ENV' })
    candidates.push({ executable: path.join(virtualEnv, 'bin', 'python3'), source: '$VIRTUAL_ENV' })
  }

  const workspaceVenv = path.join(cwd, '.venv', 'bin')
  candidates.push({ executable: path.join(workspaceVenv, 'python'), source: 'workspace/.venv' })
  candidates.push({ executable: path.join(workspaceVenv, 'python3'), source: 'workspace/.venv' })

  const pathPython = await findExecutable('python3')
  if (pathPython) candidates.push({ executable: pathPython, source: 'PATH/python3' })
  const pathPythonLegacy = await findExecutable('python')
  if (pathPythonLegacy) candidates.push({ executable: pathPythonLegacy, source: 'PATH/python' })

  let selected: { executable: string; source: string } | null = null
  for (const candidate of deduplicateCandidates(candidates)) {
    if (await isExecutable(candidate.executable)) {
      selected = candidate
      break
    }
  }

  const bin = selected ? path.dirname(selected.executable) : null
  const venv = bin && path.basename(bin) === 'bin' ? path.dirname(bin) : null
  return {
    executable: selected?.executable ?? null,
    source: selected?.source ?? null,
    venv,
    bin,
    searchPath: await ctfSearchPath(cwd, bin),
  }
}

export async function findCtfExecutable(name: string, cwd = process.cwd()): Promise<string | null> {
  const environment = await discoverCtfPython(cwd)
  return findExecutable(name, environment.searchPath)
}

export async function ctfSearchPath(cwd = process.cwd(), selectedPythonBin?: string | null): Promise<string> {
  const directories = [
    selectedPythonBin,
    process.env.DSH_CTF_PYTHON && path.dirname(process.env.DSH_CTF_PYTHON),
    DEFAULT_CTF_PYTHON && path.dirname(DEFAULT_CTF_PYTHON),
    process.env.VIRTUAL_ENV && path.join(process.env.VIRTUAL_ENV, 'bin'),
    path.join(cwd, '.venv', 'bin'),
    ...(process.env.PATH ?? '').split(path.delimiter),
  ]
  return [...new Set(directories.filter((item): item is string => Boolean(item && item.trim())))]
    .join(path.delimiter)
}

async function isExecutable(candidate: string): Promise<boolean> {
  try {
    await access(candidate, constants.X_OK)
    return true
  } catch {
    return false
  }
}

function deduplicateCandidates(
  candidates: Array<{ executable: string; source: string }>,
): Array<{ executable: string; source: string }> {
  const seen = new Set<string>()
  return candidates.filter(candidate => {
    if (seen.has(candidate.executable)) return false
    seen.add(candidate.executable)
    return true
  })
}
