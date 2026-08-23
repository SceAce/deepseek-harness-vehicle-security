import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { profileCtfArtifact } from './artifact.js';
import { emptyResult } from './types.js';
export async function probeCryptoInput(input) {
    const base = emptyResult();
    let artifact = null;
    let text = input.text ?? '';
    if (input.file) {
        const profile = await profileCtfArtifact(input.file);
        base.commands.push(...profile.commands);
        base.artifacts.push(profile.artifact);
        base.observations.push(...profile.observations);
        base.limitations.push(...profile.limitations);
        artifact = profile.artifact;
        if (input.file.info.size <= 2 * 1024 * 1024) {
            text = await readFile(input.file.path, 'utf8');
        }
        else {
            base.limitations.push('file is larger than 2 MiB; crypto probe only used metadata.');
        }
    }
    const bytes = Buffer.from(text, 'utf8');
    const encodings = detectEncodings(text);
    const xorCandidates = bytes.length > 0 && bytes.length <= 20000 ? singleByteXorCandidates(bytes, 5) : [];
    base.observations.push(`crypto input length=${bytes.length} entropy=${entropy(bytes)}`);
    if (encodings.length > 0)
        base.observations.push(`detected encoding candidates: ${encodings.map(item => item.type).join(', ')}`);
    if (xorCandidates.length > 0)
        base.observations.push(`ranked ${xorCandidates.length} single-byte XOR candidates.`);
    base.nextActions.push({ tool: 'ctf_tool_audit', args: {}, reason: 'Check whether Sage, z3, SymPy, gmpy2, or pycryptodome are installed before complex solver work.' });
    return {
        ...base,
        artifact,
        input: {
            length: bytes.length,
            entropy: entropy(bytes),
            sha256: createHash('sha256').update(bytes).digest('hex'),
        },
        encodings,
        xorCandidates,
    };
}
function detectEncodings(text) {
    const compact = text.trim().replace(/\s+/g, '');
    const result = [];
    if (/^(?:0x)?[0-9a-f]+$/i.test(compact) && compact.replace(/^0x/i, '').length % 2 === 0) {
        const decoded = Buffer.from(compact.replace(/^0x/i, ''), 'hex');
        result.push({ type: 'hex', confidence: printableRatio(decoded) > 0.75 ? 'high' : 'medium', decodedPreview: preview(decoded) });
    }
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(compact) && compact.length % 4 === 0) {
        try {
            const decoded = Buffer.from(compact, 'base64');
            if (decoded.length > 0)
                result.push({ type: 'base64', confidence: printableRatio(decoded) > 0.75 ? 'high' : 'low', decodedPreview: preview(decoded) });
        }
        catch {
            // Ignore malformed candidates.
        }
    }
    if (/^[01]+$/.test(compact) && compact.length % 8 === 0) {
        const decoded = Buffer.from(compact.match(/.{8}/g)?.map(bits => String.fromCharCode(Number.parseInt(bits, 2))).join('') ?? '', 'binary');
        result.push({ type: 'binary-ascii', confidence: printableRatio(decoded) > 0.75 ? 'high' : 'medium', decodedPreview: preview(decoded) });
    }
    if (/^[A-Za-z0-9+/=._-]{20,}$/.test(compact) && compact.includes('.')) {
        result.push({ type: 'token-or-jwt-like', confidence: 'medium' });
    }
    return result;
}
function singleByteXorCandidates(bytes, limit) {
    const candidates = [];
    for (let key = 0; key < 256; key += 1) {
        const decoded = Buffer.from(bytes.map(byte => byte ^ key));
        const score = englishScore(decoded);
        candidates.push({ key: `0x${key.toString(16).padStart(2, '0')}`, score, preview: preview(decoded) });
    }
    return candidates.sort((left, right) => right.score - left.score).slice(0, limit);
}
function entropy(bytes) {
    if (bytes.length === 0)
        return 0;
    const counts = new Uint32Array(256);
    for (const byte of bytes)
        counts[byte] += 1;
    let value = 0;
    for (const count of counts) {
        if (count === 0)
            continue;
        const probability = count / bytes.length;
        value -= probability * Math.log2(probability);
    }
    return Number(value.toFixed(4));
}
function englishScore(bytes) {
    let score = 0;
    for (const byte of bytes) {
        const ch = String.fromCharCode(byte);
        if (/[etaoin shrdluETAOINSHRDLU]/.test(ch))
            score += 2;
        else if (/[a-zA-Z0-9{}_!?,.'"-]/.test(ch))
            score += 1;
        else if (byte === 9 || byte === 10 || byte === 13)
            score += 0.2;
        else if (byte < 32 || byte > 126)
            score -= 4;
    }
    return Number((score / Math.max(bytes.length, 1)).toFixed(4));
}
function printableRatio(bytes) {
    if (bytes.length === 0)
        return 0;
    let printable = 0;
    for (const byte of bytes) {
        if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126))
            printable += 1;
    }
    return printable / bytes.length;
}
function preview(bytes) {
    return bytes.toString('utf8').replace(/\0/g, '').slice(0, 160);
}
//# sourceMappingURL=crypto.js.map