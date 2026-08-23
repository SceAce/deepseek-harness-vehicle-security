import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { open } from 'node:fs/promises';
import path from 'node:path';
import { findCtfExecutable } from './environment.js';
import { runCommand } from '../process.js';
import { commandRecord } from './types.js';
export async function profileCtfArtifact(file, options = {}) {
    const commands = [];
    const sha256 = await hashFile(file.path);
    const entropy = await sampleEntropy(file.path, Math.min(file.info.size, 1024 * 1024));
    const magic = await readMagic(file.path, 16);
    let fileType = null;
    const fileCommand = await findCtfExecutable('file', options.cwd);
    if (fileCommand) {
        const result = await runCommand(fileCommand, ['--brief', '--', file.path], options);
        commands.push(commandRecord(fileCommand, ['--brief', '--', file.path], result, options.cwd));
        fileType = result.stdout.trim() || result.stderr.trim() || null;
    }
    const textSample = await maybeReadTextSample(file.path, file.info.size);
    const artifact = {
        path: file.relativePath,
        extension: path.extname(file.relativePath).toLowerCase(),
        basename: path.basename(file.relativePath),
        sizeBytes: file.info.size,
        sha256,
        sampleEntropy: entropy,
        fileType,
        magic,
        textSample,
    };
    return {
        artifact,
        commands,
        observations: artifactObservations(artifact),
        limitations: fileCommand ? [] : ['file is not installed; fileType is based on extension, magic, and content heuristics only.'],
    };
}
function artifactObservations(artifact) {
    const observations = [
        `artifact ${artifact.path} size=${artifact.sizeBytes} sha256=${artifact.sha256}`,
        `sampleEntropy=${artifact.sampleEntropy}`,
    ];
    if (artifact.fileType)
        observations.push(`fileType=${artifact.fileType}`);
    if (artifact.magic)
        observations.push(`magic=${artifact.magic}`);
    return observations;
}
function hashFile(filePath) {
    return new Promise((resolve, reject) => {
        const hash = createHash('sha256');
        const stream = createReadStream(filePath);
        stream.on('error', reject);
        stream.on('data', (chunk) => hash.update(chunk));
        stream.on('end', () => resolve(hash.digest('hex')));
    });
}
async function sampleEntropy(filePath, sampleSize) {
    if (sampleSize === 0)
        return 0;
    const handle = await open(filePath, 'r');
    try {
        const buffer = Buffer.alloc(sampleSize);
        const { bytesRead } = await handle.read(buffer, 0, sampleSize, 0);
        const counts = new Uint32Array(256);
        for (let index = 0; index < bytesRead; index += 1)
            counts[buffer[index]] += 1;
        let entropy = 0;
        for (const count of counts) {
            if (count === 0)
                continue;
            const probability = count / bytesRead;
            entropy -= probability * Math.log2(probability);
        }
        return Number(entropy.toFixed(4));
    }
    finally {
        await handle.close();
    }
}
async function readMagic(filePath, byteCount) {
    const handle = await open(filePath, 'r');
    try {
        const buffer = Buffer.alloc(byteCount);
        const { bytesRead } = await handle.read(buffer, 0, byteCount, 0);
        return buffer.subarray(0, bytesRead).toString('hex').toUpperCase();
    }
    finally {
        await handle.close();
    }
}
async function maybeReadTextSample(filePath, sizeBytes) {
    if (sizeBytes === 0)
        return '';
    const sampleSize = Math.min(sizeBytes, 4096);
    const handle = await open(filePath, 'r');
    try {
        const buffer = Buffer.alloc(sampleSize);
        const { bytesRead } = await handle.read(buffer, 0, sampleSize, 0);
        const sample = buffer.subarray(0, bytesRead);
        const printable = sample.filter(byte => byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)).length;
        if (printable / Math.max(bytesRead, 1) < 0.85)
            return null;
        return sample.toString('utf8').replace(/\0/g, '').slice(0, 2000);
    }
    finally {
        await handle.close();
    }
}
//# sourceMappingURL=artifact.js.map