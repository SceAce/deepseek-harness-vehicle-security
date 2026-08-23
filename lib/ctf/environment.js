import { constants } from 'node:fs';
import { access } from 'node:fs/promises';
import path from 'node:path';
import { findExecutable } from '../paths.js';
export const DEFAULT_CTF_PYTHON = '/home/source/tools/PyVenv/CTF/bin/python';
export const DEFAULT_CTF_IDA_CLI_CANDIDATES = [
    '/home/source/CTF_PWN/tools/IDA/IDA-Pro-9.3/IDA-9-3/idat64',
    '/home/source/CTF_PWN/tools/IDA/IDA-Pro-9.3/IDA-9-3/idat',
    '/home/source/CTF_PWN/tools/IDA/IDA-Pro-9.3/IDA-9-3/ida64',
    '/home/source/CTF_PWN/tools/IDA/IDA-Pro-9.3/IDA-9-3/ida',
];
export async function discoverCtfPython(cwd = process.cwd()) {
    const selected = await isExecutable(DEFAULT_CTF_PYTHON)
        ? { executable: DEFAULT_CTF_PYTHON, source: 'fixed-default' }
        : null;
    const bin = selected ? path.dirname(selected.executable) : null;
    const venv = bin && path.basename(bin) === 'bin' ? path.dirname(bin) : null;
    return {
        policy: 'fixed',
        requiredExecutable: DEFAULT_CTF_PYTHON,
        executable: selected?.executable ?? null,
        source: selected?.source ?? 'fixed-default (missing)',
        venv,
        bin,
        searchPath: await ctfSearchPath(cwd, bin),
    };
}
export async function findCtfExecutable(name, cwd = process.cwd()) {
    const environment = await discoverCtfPython(cwd);
    return findExecutable(name, environment.searchPath);
}
export async function findCtfIdaExecutable(_cwd = process.cwd()) {
    const configured = expandHome(process.env.DSH_CTF_IDA?.trim() ?? '');
    const candidates = [
        ...(configured ? [configured] : []),
        ...DEFAULT_CTF_IDA_CLI_CANDIDATES,
        'idat64',
        'idat',
        'ida64',
        'ida',
    ];
    for (const candidate of deduplicateStrings(candidates)) {
        const executable = await findExecutable(candidate);
        if (executable)
            return executable;
    }
    return null;
}
export async function ctfSearchPath(cwd = process.cwd(), selectedPythonBin) {
    const directories = [
        selectedPythonBin,
        DEFAULT_CTF_PYTHON && path.dirname(DEFAULT_CTF_PYTHON),
        ...(process.env.PATH ?? '').split(path.delimiter),
    ];
    return [...new Set(directories.filter((item) => Boolean(item && item.trim())))]
        .join(path.delimiter);
}
async function isExecutable(candidate) {
    try {
        await access(candidate, constants.X_OK);
        return true;
    }
    catch {
        return false;
    }
}
function expandHome(value) {
    if (value === '~')
        return process.env.HOME ?? value;
    if (value.startsWith('~/'))
        return path.join(process.env.HOME ?? '~', value.slice(2));
    if (value.startsWith('$HOME/'))
        return path.join(process.env.HOME ?? '$HOME', value.slice(6));
    return value;
}
function deduplicateStrings(candidates) {
    const seen = new Set();
    return candidates.filter(candidate => {
        if (seen.has(candidate))
            return false;
        seen.add(candidate);
        return true;
    });
}
//# sourceMappingURL=environment.js.map