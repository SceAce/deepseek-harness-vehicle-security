import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readdir, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { assertInside, resolveWorkspaceFile } from '../paths.js';
import { findCtfExecutable } from './environment.js';
import { runCommand } from '../process.js';
import { commandRecord, emptyResult } from './types.js';
export async function runPwninit(file, args = {}, options = {}) {
    const base = emptyResult();
    const mode = args.mode ?? 'prepare';
    const beforeSha256 = await hashFile(file.path);
    const executable = await findCtfExecutable('pwninit', options.cwd);
    const selected = await resolveRuntimeSources(file, args, options.maxFileBytes ?? 128 * 1024 * 1024);
    const pwninit = {
        mode,
        executable,
        binary: file.relativePath,
        command: [],
        selectedLibc: selected.libc ? relativePath(file.root, selected.libc) : null,
        selectedLd: selected.ld ? relativePath(file.root, selected.ld) : null,
        beforeSha256,
        afterSha256: beforeSha256,
        changed: false,
    };
    if (!executable) {
        base.status = 'missing_capability';
        base.limitations.push('pwninit is not installed or is not visible in the CTF tool search path.');
        base.nextActions.push({ tool: 'ctf_tool_audit', args: {}, reason: 'Refresh the local Pwn capability inventory.' });
        return { ...base, pwninit };
    }
    if (mode === 'prepare' && !args.onlyInit && !selected.source) {
        base.status = 'missing_capability';
        base.limitations.push('No libc source was selected. Provide libcPath, ldPath plus libcPath, dependencyDir, or a local libc/ld pair.');
        base.nextActions.push({
            tool: 'ctf_human_request',
            args: {
                type: 'provide_data',
                title: 'Provide the matching glibc files',
                reason: 'pwninit needs a deterministic libc source before patching the challenge binary.',
            },
            reason: 'Return the local libc/ld paths or place them in the challenge workspace.',
        });
        return { ...base, pwninit };
    }
    const argv = buildPwninitArgs(mode, file.path, selected, args);
    pwninit.command = [executable, ...argv];
    const capture = await runCommand(executable, argv, {
        ...options,
        cwd: file.root,
        maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000),
    });
    base.commands.push(commandRecord(executable, argv, capture, file.root));
    base.observations.push(`pwninit mode=${mode} binary=${file.relativePath}`);
    if (selected.libc)
        base.observations.push(`selected libc=${relativePath(file.root, selected.libc)}`);
    if (selected.ld)
        base.observations.push(`selected ld=${relativePath(file.root, selected.ld)}`);
    if (capture.ok) {
        base.observations.push('pwninit completed without a non-zero exit status.');
    }
    else {
        base.status = 'failed';
        base.limitations.push(`pwninit exited with ${capture.exitCode ?? 'no status'}: ${capture.error ?? capture.stderr.trim()}`);
    }
    const afterSha256 = await hashFile(file.path);
    pwninit.afterSha256 = afterSha256;
    pwninit.changed = beforeSha256 !== afterSha256;
    if (pwninit.changed) {
        base.observations.push(`binary hash changed from ${beforeSha256} to ${afterSha256}.`);
    }
    else {
        base.observations.push('binary hash did not change.');
    }
    base.artifacts.push({
        kind: 'pwninit',
        mode,
        binary: file.relativePath,
        libc: pwninit.selectedLibc,
        ld: pwninit.selectedLd,
    });
    if (mode === 'prepare' && capture.ok) {
        base.nextActions.push({
            tool: 'ctf_pwn_gdb_probe',
            args: { path: file.relativePath },
            reason: 'Probe the challenge again after pwninit selected the intended loader and libc.',
        });
        base.nextActions.push({
            tool: 'ctf_pwn_debug_probe',
            args: { path: file.relativePath, breakAt: 'main' },
            reason: 'Inspect main and input handling under the patched runtime.',
        });
    }
    else if (mode === 'restore' && capture.ok) {
        base.nextActions.push({
            tool: 'ctf_pwn_profile',
            args: { path: file.relativePath },
            reason: 'Re-profile the restored original binary before further runtime work.',
        });
    }
    return { ...base, status: capture.ok ? 'ok' : 'failed', pwninit };
}
async function resolveRuntimeSources(file, args, maxFileBytes) {
    const sourceKinds = [
        Boolean(args.dependencyDir),
        Boolean(args.libcPath),
        Boolean(args.ldPath),
        Boolean(args.libcVersion),
    ].filter(Boolean).length;
    if (sourceKinds > 2 || args.dependencyDir && (args.libcPath || args.ldPath || args.libcVersion)) {
        throw new Error('Choose one libc source: dependencyDir, libcPath/ldPath, or libcVersion.');
    }
    if (args.libcIndex !== undefined && (!Number.isInteger(args.libcIndex) || args.libcIndex < 1)) {
        throw new Error('libcIndex must be a positive integer.');
    }
    let libc = args.libcPath
        ? (await resolveWorkspaceFile(file.root, args.libcPath, maxFileBytes)).path
        : null;
    let ld = args.ldPath
        ? (await resolveWorkspaceFile(file.root, args.ldPath, maxFileBytes)).path
        : null;
    const dependencyDir = args.dependencyDir ? await resolveWorkspaceDirectory(file.root, args.dependencyDir) : null;
    if (!dependencyDir && (!args.libcVersion || libc || ld)) {
        const discovered = await discoverSiblingRuntimeFiles(file.path);
        libc ??= discovered.libc;
        ld ??= discovered.ld;
    }
    const source = Boolean(dependencyDir || args.libcVersion || libc || ld);
    return {
        source,
        libc,
        ld,
        dependencyDir,
        libcVersion: args.libcVersion ?? null,
        libcIndex: args.libcIndex ?? null,
    };
}
function buildPwninitArgs(mode, binary, sources, args) {
    if (mode === 'doctor')
        return ['--doctor', binary];
    if (mode === 'restore')
        return ['--restore', binary];
    if (mode === 'list_backups')
        return ['--list-backups', binary];
    const argv = ['--skip-venv-check', '--skip-checksec'];
    if (args.debug)
        argv.push('--debug');
    if (args.onlyInit) {
        argv.push('--only-init');
    }
    else if (args.onlyLibc ?? true) {
        argv.push('--only-libc');
    }
    if (args.generateExp) {
        if (args.forceExp)
            argv.push('--force-exp');
    }
    else {
        argv.push('--skip-exp');
    }
    argv.push(binary);
    if (sources.dependencyDir) {
        argv.push('-M', sources.dependencyDir);
    }
    else if (sources.ld && sources.libc) {
        argv.push('-W', sources.ld, sources.libc);
    }
    else if (sources.libc) {
        argv.push('--libc', sources.libc);
        if (sources.libcIndex !== null)
            argv.push('--libc-index', String(sources.libcIndex));
        if (sources.libcVersion)
            argv.push('--libc-version', sources.libcVersion);
    }
    else if (sources.libcVersion) {
        argv.push(sources.libcVersion);
    }
    return argv;
}
async function discoverSiblingRuntimeFiles(binary) {
    const directory = path.dirname(binary);
    const entries = await readdir(directory);
    const libcCandidates = await existingFiles(directory, entries.filter(name => /^libc(?:\.so(?:\..*)?|-[^/]+\.so(?:\..*)?)$/.test(name)));
    const ldCandidates = await existingFiles(directory, entries.filter(name => /^ld(?:-linux[^/]*|-[^/]+)?\.so(?:\..*)?$/.test(name)));
    return {
        libc: libcCandidates[0] ?? null,
        ld: ldCandidates[0] ?? null,
    };
}
async function existingFiles(directory, names) {
    const result = [];
    for (const name of names.sort()) {
        const candidate = path.join(directory, name);
        try {
            if ((await stat(candidate)).isFile())
                result.push(candidate);
        }
        catch {
            // Ignore broken symlinks and files removed during discovery.
        }
    }
    return result;
}
async function resolveWorkspaceDirectory(workspaceRoot, inputPath) {
    if (inputPath.trim() === '')
        throw new Error('dependencyDir must be a non-empty string');
    const root = await realpath(path.resolve(workspaceRoot));
    const candidate = await realpath(path.resolve(root, inputPath));
    assertInside(root, candidate);
    if (!(await stat(candidate)).isDirectory())
        throw new Error(`dependencyDir is not a directory: ${inputPath}`);
    return candidate;
}
function relativePath(root, candidate) {
    return path.relative(root, candidate);
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
//# sourceMappingURL=pwninit.js.map