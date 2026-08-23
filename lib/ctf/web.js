import { createHash } from 'node:crypto';
import { findExecutable } from '../paths.js';
import { runCommand } from '../process.js';
import { commandRecord, emptyResult } from './types.js';
export async function httpRequest(args, options = {}) {
    const base = emptyResult();
    const curl = await findExecutable('curl');
    if (!curl) {
        base.status = 'missing_capability';
        base.limitations.push('curl is not installed.');
        base.nextActions.push({ tool: 'ctf_tool_audit', args: {}, reason: 'Refresh web tooling capabilities.' });
        return { ...base, request: args, response: null };
    }
    const argv = curlArgs(args);
    const capture = await runCommand(curl, argv, { ...options, maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000) });
    base.commands.push(commandRecord(curl, argv, capture, options.cwd));
    const parsed = parseCurlResponse(capture.stdout);
    base.observations.push(parsed
        ? `HTTP status=${parsed.statusCode ?? 'unknown'} bodyBytes=${parsed.bodyBytes} bodySha256=${parsed.bodySha256}`
        : `curl exited with ${capture.exitCode ?? 'no status'} and no parseable HTTP response.`);
    base.nextActions.push({ tool: 'ctf_http_diff', args: { urlA: args.url, urlB: args.url, method: args.method ?? 'GET' }, reason: 'Compare a baseline with one controlled variation before writing a web solver.' });
    return { ...base, status: capture.ok ? 'ok' : 'failed', request: args, response: parsed };
}
export async function httpDiff(args, options = {}) {
    const left = await httpRequest({ url: args.urlA, method: args.method, headers: args.headers, body: args.bodyA }, options);
    const right = await httpRequest({ url: args.urlB, method: args.method, headers: args.headers, body: args.bodyB }, options);
    const base = emptyResult(left.status === 'ok' && right.status === 'ok' ? 'ok' : 'failed');
    base.commands.push(...left.commands, ...right.commands);
    base.limitations.push(...left.limitations, ...right.limitations);
    base.humanRequired.push(...left.humanRequired, ...right.humanRequired);
    const diff = {
        statusChanged: left.response?.statusCode !== right.response?.statusCode,
        bodyLengthDelta: (right.response?.bodyBytes ?? 0) - (left.response?.bodyBytes ?? 0),
        bodyHashChanged: left.response?.bodySha256 !== right.response?.bodySha256,
        leftStatus: left.response?.statusCode ?? null,
        rightStatus: right.response?.statusCode ?? null,
    };
    base.observations.push(`HTTP diff statusChanged=${diff.statusChanged} bodyLengthDelta=${diff.bodyLengthDelta} bodyHashChanged=${diff.bodyHashChanged}`);
    return { ...base, left, right, diff };
}
function curlArgs(args) {
    const method = (args.method ?? 'GET').toUpperCase();
    const argv = ['-i', '-sS', '--max-time', String(normalizeNumber(args.maxTimeSeconds, 10, 1, 120)), '-X', method];
    if (args.followRedirects)
        argv.push('-L');
    for (const header of args.headers ?? [])
        argv.push('-H', header);
    if (args.body !== undefined)
        argv.push('--data-binary', args.body);
    argv.push(args.url);
    return argv;
}
function parseCurlResponse(raw) {
    if (!raw.trim())
        return null;
    const normalized = raw.replace(/\r\n/g, '\n');
    const marker = '\n\n';
    const split = normalized.lastIndexOf(marker);
    const headerText = split >= 0 ? normalized.slice(0, split) : '';
    const body = split >= 0 ? normalized.slice(split + marker.length) : normalized;
    const statusMatches = [...headerText.matchAll(/^HTTP\/\S+\s+(\d{3})/gm)];
    const statusCode = statusMatches.length > 0 ? Number(statusMatches.at(-1)?.[1]) : null;
    return {
        statusCode,
        headerBytes: Buffer.byteLength(headerText),
        bodyBytes: Buffer.byteLength(body),
        bodySha256: createHash('sha256').update(body).digest('hex'),
        preview: body.slice(0, 400),
    };
}
function normalizeNumber(value, fallback, min, max) {
    if (value === undefined)
        return fallback;
    if (!Number.isFinite(value) || value < min || value > max)
        throw new Error(`number must be in range ${min}..${max}`);
    return value;
}
//# sourceMappingURL=web.js.map