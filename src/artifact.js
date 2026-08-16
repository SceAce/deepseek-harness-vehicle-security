import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { open } from 'node:fs/promises'
import { findExecutable } from './paths.js'
import { runCommand } from './process.js'

export async function triageArtifact(file, options = {}) {
  const sha256 = await hashFile(file.path)
  const entropy = await sampleEntropy(file.path, Math.min(file.info.size, 1024 * 1024))
  const result = {
    path: file.relativePath,
    sizeBytes: file.info.size,
    sha256,
    sampleEntropy: entropy,
    fileType: null,
    binwalk: null,
  }

  const fileCommand = await findExecutable('file')
  if (fileCommand) {
    const detected = await runCommand(fileCommand, ['--brief', '--', file.path], options)
    result.fileType = detected.stdout.trim() || detected.stderr.trim() || null
  }

  if (options.enableBinwalk) {
    const binwalk = await findExecutable('binwalk')
    if (binwalk) {
      const scan = await runCommand(binwalk, [file.path], options)
      result.binwalk = {
        ok: scan.ok,
        exitCode: scan.exitCode,
        output: [scan.stdout, scan.stderr].filter(Boolean).join('\n').trim(),
      }
    }
  }
  return result
}

function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256')
    const stream = createReadStream(filePath)
    stream.on('error', reject)
    stream.on('data', chunk => hash.update(chunk))
    stream.on('end', () => resolve(hash.digest('hex')))
  })
}

async function sampleEntropy(filePath, sampleSize) {
  if (sampleSize === 0) return 0
  const handle = await open(filePath, 'r')
  try {
    const buffer = Buffer.alloc(sampleSize)
    const { bytesRead } = await handle.read(buffer, 0, sampleSize, 0)
    const counts = new Uint32Array(256)
    for (let index = 0; index < bytesRead; index += 1) counts[buffer[index]] += 1
    let entropy = 0
    for (const count of counts) {
      if (count === 0) continue
      const probability = count / bytesRead
      entropy -= probability * Math.log2(probability)
    }
    return Number(entropy.toFixed(4))
  } finally {
    await handle.close()
  }
}
