import { createHash } from 'node:crypto';
import { mkdtemp } from 'node:fs/promises';
import { findExecutable } from '../paths.js';
import { runCommand } from '../process.js';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { makeHumanRequest } from './human.js';
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
    base.nextActions.push({ tool: 'ctf_web_browser_probe', args: { url: args.url, captureScreenshot: true }, reason: 'Inspect rendered DOM and client-side behavior with the local browser before writing browser automation.' });
    base.nextActions.push({ tool: 'ctf_web_capture_probe', args: {}, reason: 'Check the live proxy path when request/response evidence is insufficient or replay is needed.' });
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
export async function probeWebBrowser(args, options = {}) {
    const base = emptyResult();
    const browser = await findExecutable('chromium') ?? await findExecutable('google-chrome-stable') ?? await findExecutable('google-chrome');
    if (!browser) {
        base.status = 'missing_capability';
        base.limitations.push('No local Chromium or Google Chrome executable was found.');
        base.nextActions.push({ tool: 'ctf_tool_setup', args: { target: 'chrome_devtools_mcp' }, reason: 'Install or expose Chrome/Chromium and configure Chrome DevTools MCP.' });
        return {
            ...base,
            browser: null,
            url: args.url,
            domPreview: null,
            title: null,
            screenshotPath: null,
        };
    }
    const domProfileDir = await mkdtemp(path.join(tmpdir(), 'dsh-chromium-profile-'));
    const domArgs = ['--headless=new', `--user-data-dir=${domProfileDir}`, '--disable-gpu', '--no-sandbox', '--virtual-time-budget=5000', '--dump-dom', args.url];
    const domCapture = await runCommand(browser, domArgs, { ...options, maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000) });
    base.commands.push(commandRecord(browser, domArgs, domCapture, options.cwd));
    const domPreview = domCapture.stdout.trim().slice(0, 4000) || null;
    const title = extractTitle(domCapture.stdout);
    let screenshotPath = null;
    if (args.captureScreenshot ?? true) {
        const shotDir = await mkdtemp(path.join(tmpdir(), 'dsh-web-browser-'));
        const shotProfileDir = await mkdtemp(path.join(tmpdir(), 'dsh-chromium-profile-'));
        screenshotPath = path.join(shotDir, 'page.png');
        const shotArgs = ['--headless=new', `--user-data-dir=${shotProfileDir}`, '--disable-gpu', '--no-sandbox', '--virtual-time-budget=5000', '--window-size=1440,2200', `--screenshot=${screenshotPath}`, args.url];
        const shotCapture = await runCommand(browser, shotArgs, { ...options, maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 20_000) });
        base.commands.push(commandRecord(browser, shotArgs, shotCapture, options.cwd));
        if (!shotCapture.ok)
            base.limitations.push(`Browser screenshot probe exited with ${shotCapture.exitCode ?? 'no status'}: ${shotCapture.error ?? shotCapture.stderr.trim()}`);
    }
    base.observations.push(`browser probe completed with ${browser}.`);
    base.nextActions.push({ tool: 'ctf_http_diff', args: { urlA: args.url, urlB: args.url, method: 'GET' }, reason: 'Compare a controlled browser-visible variation once a baseline page is available.' });
    base.nextActions.push({ tool: 'ctf_tool_setup', args: { target: 'chrome_devtools_mcp' }, reason: 'Use Chrome DevTools MCP when interactive browser automation is needed.' });
    if (!domCapture.ok)
        base.limitations.push(`Browser DOM probe exited with ${domCapture.exitCode ?? 'no status'}: ${domCapture.error ?? domCapture.stderr.trim()}`);
    return {
        ...base,
        status: domCapture.ok ? 'ok' : 'failed',
        browser,
        url: args.url,
        domPreview,
        title,
        screenshotPath,
    };
}
export async function probeWebCapture(args, options = {}) {
    const base = emptyResult();
    const proxy = await findExecutable('mitmweb') ?? await findExecutable('mitmdump') ?? await findExecutable('mitmproxy');
    const listenHost = args.listenHost ?? '127.0.0.1';
    const listenPort = normalizeNumber(args.listenPort, 8080, 1, 65535);
    const webPort = normalizeNumber(args.webPort, 8081, 1, 65535);
    if (!proxy) {
        base.status = 'missing_capability';
        base.limitations.push('mitmweb, mitmdump, and mitmproxy are not installed.');
        base.nextActions.push({ tool: 'ctf_tool_setup', args: { target: 'mitmproxy' }, reason: 'Install mitmproxy before starting live HTTP(S) capture.' });
        return { ...base, proxy: null, version: null, launchCommand: null, verifyCommand: null };
    }
    const versionArgs = ['--version'];
    const versionResult = await runCommand(proxy, versionArgs, options);
    const version = [versionResult.stdout, versionResult.stderr].join('\n').split(/\r?\n/).map(line => line.trim()).find(Boolean) ?? null;
    base.commands.push(commandRecord(proxy, versionArgs, versionResult, options.cwd));
    const launchCommand = proxy.endsWith('mitmweb')
        ? `mitmweb --listen-host ${listenHost} --listen-port ${listenPort} --web-host 127.0.0.1 --web-port ${webPort}`
        : `mitmdump --listen-host ${listenHost} --listen-port ${listenPort}`;
    const verifyCommand = `curl --proxy ${listenHost}:${listenPort} --max-time 10 http://HOST:PORT/`;
    base.observations.push(`live capture capability detected: ${proxy}.`);
    base.humanRequired.push(makeHumanRequest({
        type: 'start_service',
        title: 'Start live web traffic capture',
        reason: 'The proxy is installed, but its long-running process and browser/device traffic must be started by the human.',
        operationOrder: [
            {
                order: 1,
                kind: 'command',
                title: 'Start the proxy',
                command: launchCommand,
                expectedSignal: 'Return the proxy startup log with the listen and, when applicable, web UI ports.',
            },
            {
                order: 2,
                kind: 'instruction',
                title: 'Route the client through the proxy',
                instruction: `Configure the browser or test client to use ${listenHost}:${listenPort}; for HTTPS, install the local mitmproxy CA only in that test client.`,
                expectedSignal: 'Return a screenshot, log, or OCR text showing the client proxy setting or captured flow.',
            },
            {
                order: 3,
                kind: 'command',
                title: 'Verify one request',
                command: verifyCommand,
                expectedSignal: 'Return the request output and the corresponding captured-flow log.',
            },
        ],
        acceptedReturnTypes: ['log', 'screenshot', 'ocr_text'],
        returnFields: {
            log: 'proxy startup, client request, and captured-flow log',
            screenshot: 'mitmweb flow view or client proxy configuration screenshot text',
            ocr_text: 'recognized text containing proxy ports and captured request details',
        },
    }));
    return {
        ...base,
        status: versionResult.ok ? 'human_required' : 'failed',
        proxy,
        version,
        launchCommand,
        verifyCommand,
    };
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
function extractTitle(dom) {
    const match = dom.match(/<title[^>]*>([^<]*)<\/title>/i);
    return match?.[1]?.trim() || null;
}
//# sourceMappingURL=web.js.map