import { constants, type Stats } from 'node:fs'
import { access, realpath, stat } from 'node:fs/promises'
import path from 'node:path'

export interface ResolvedWorkspaceFile {
  root: string
  path: string
  relativePath: string
  info: Stats
}

export async function resolveWorkspaceFile(
  workspaceRoot: string,
  inputPath: string,
  maxFileBytes: number,
): Promise<ResolvedWorkspaceFile> {
  if (inputPath.trim() === '') throw new Error('path must be a non-empty string')

  const root = await realpath(path.resolve(workspaceRoot))
  const candidate = await realpath(path.resolve(root, inputPath))
  assertInside(root, candidate)

  const info = await stat(candidate)
  if (!info.isFile()) throw new Error(`path is not a regular file: ${inputPath}`)
  if (info.size > maxFileBytes) {
    throw new Error(`file is ${info.size} bytes; configured limit is ${maxFileBytes}`)
  }

  return { root, path: candidate, relativePath: path.relative(root, candidate), info }
}

export function assertInside(root: string, candidate: string): void {
  const relative = path.relative(root, candidate)
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error('path escapes configured workspaceRoot')
  }
}

export async function findExecutable(
  name: string,
  envPath = process.env.PATH ?? '',
): Promise<string | null> {
  for (const directory of envPath.split(path.delimiter).filter(Boolean)) {
    const candidate = path.join(directory, name)
    try {
      await access(candidate, constants.X_OK)
      return candidate
    } catch {
      // Continue through PATH.
    }
  }
  return null
}
