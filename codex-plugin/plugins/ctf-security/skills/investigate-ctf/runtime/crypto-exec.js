import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { resolveWorkspaceFile } from '../paths.js';
import { runCommand } from '../process.js';
import { findCtfExecutable } from './environment.js';
import { commandRecord, emptyResult } from './types.js';
export async function runCtfCryptoEngine(engine, args, options = {}) {
    const base = emptyResult();
    const executable = await findCtfExecutable(engine, options.cwd);
    const script = args.scriptPath
        ? await resolveScript(options.workspaceRoot, args.scriptPath, options.maxFileBytes ?? 128 * 1024 * 1024)
        : null;
    const code = typeof args.code === 'string' ? args.code : '';
    const argv = normalizeArgv(args.argv);
    if (!script && code.trim() === '') {
        throw new Error('Provide either code or scriptPath.');
    }
    if (!executable) {
        base.status = 'missing_capability';
        base.limitations.push(`${engine} is not installed or is not visible in the CTF tool search path.`);
        base.nextActions.push({
            tool: 'ctf_tool_setup',
            args: { target: engine === 'sage' ? 'sage' : 'pari_gp' },
            reason: `Install or expose ${engine} before running a CTF crypto solver.`,
        });
        return {
            ...base,
            engine: {
                name: engine,
                executable: null,
                argv: [],
                scriptPath: script?.relativePath ?? null,
            },
            output: null,
        };
    }
    const temporary = script
        ? engine === 'gp' ? await materializeWorkspaceScript(engine, script.path) : null
        : await materializeInlineScript(engine, code);
    const executionScriptPath = temporary?.path ?? script?.path;
    if (!executionScriptPath)
        throw new Error('Crypto execution script was not created.');
    const commandArgv = script
        ? [quietFlag(engine), script.path, ...argv]
        : [quietFlag(engine), executionScriptPath, ...argv];
    const executionRoot = script?.root ?? options.cwd ?? options.workspaceRoot;
    let capture;
    try {
        capture = await runCommand(executable, commandArgv, {
            ...options,
            cwd: executionRoot,
            maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000),
        });
    }
    finally {
        if (temporary)
            await rm(temporary.root, { recursive: true, force: true });
    }
    const output = [capture.stdout, capture.stderr].filter(Boolean).join('\n').trim() || null;
    base.commands.push(commandRecord(executable, commandArgv, capture, executionRoot));
    base.observations.push(`Executed ${engine} with ${script ? `workspace script ${script.relativePath}` : 'inline code'}.`);
    if (!capture.ok) {
        base.status = 'failed';
        base.limitations.push(`${engine} exited with ${capture.exitCode ?? 'no status'}: ${capture.error ?? capture.stderr.trim()}`);
    }
    return {
        ...base,
        status: capture.ok ? 'ok' : 'failed',
        engine: {
            name: engine,
            executable,
            argv: commandArgv,
            scriptPath: script?.relativePath ?? null,
        },
        output,
    };
}
async function materializeInlineScript(engine, code) {
    const root = await mkdtemp(path.join(os.tmpdir(), `dsh-ctf-${engine}-`));
    const extension = engine === 'sage' ? '.sage' : '.gp';
    const scriptPath = path.join(root, `inline${extension}`);
    await writeFile(scriptPath, `${code.trimEnd()}\n${engine === 'gp' ? 'quit()\n' : ''}`, 'utf8');
    return { root, path: scriptPath };
}
async function materializeWorkspaceScript(engine, sourcePath) {
    const source = await readFile(sourcePath, 'utf8');
    return materializeInlineScript(engine, source);
}
async function resolveScript(workspaceRoot, inputPath, maxFileBytes) {
    if (!workspaceRoot)
        throw new Error('workspaceRoot is required when scriptPath is provided.');
    return resolveWorkspaceFile(workspaceRoot, inputPath, maxFileBytes);
}
function quietFlag(engine) {
    return engine === 'sage' ? '-q' : '-q';
}
function normalizeArgv(argv) {
    return Array.isArray(argv) ? argv.slice(0, 32).map(String) : [];
}
//# sourceMappingURL=crypto-exec.js.map