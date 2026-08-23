import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { findCtfExecutable } from './environment.js';
import { runCommand } from '../process.js';
import { commandRecord, emptyResult } from './types.js';
export async function queryRadare2(file, commands, options = {}) {
    const base = emptyResult();
    const r2 = await findCtfExecutable('r2', options.cwd);
    if (!r2) {
        base.status = 'missing_capability';
        base.limitations.push('radare2 is not installed.');
        base.nextActions.push({ tool: 'ctf_tool_setup', args: { target: 'r2' }, reason: 'Install or refresh radare2 before running r2 queries.' });
        return { ...base, executable: null, query: { commands }, rawOutput: null, json: null };
    }
    const query = commands.length > 0 ? commands : ['aaa', 'ij'];
    const argv = ['-q', '-e', 'bin.cache=true', '-c', query.join('; '), '--', file.path];
    const capture = await runCommand(r2, argv, { ...options, maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000) });
    const rawOutput = [capture.stdout, capture.stderr].filter(Boolean).join('\n').trim() || null;
    const json = tryParseJson(capture.stdout);
    base.commands.push({
        executable: r2,
        argv,
        cwd: options.cwd,
        ok: capture.ok,
        exitCode: capture.exitCode,
        stdout: capture.stdout,
        stderr: capture.stderr,
        error: capture.error,
    });
    base.observations.push(`radare2 executed ${query.length} commands against ${file.relativePath}.`);
    if (!capture.ok)
        base.limitations.push(`r2 exited with ${capture.exitCode ?? 'no status'}: ${capture.error ?? capture.stderr.trim()}`);
    return {
        ...base,
        status: capture.ok ? 'ok' : 'failed',
        executable: r2,
        query: { commands: query },
        rawOutput,
        json,
    };
}
export function buildIdaScriptPlan(file, focus, execute = false, options = {}) {
    return buildIdaScriptPlanImpl(file, focus, execute, options);
}
async function buildIdaScriptPlanImpl(file, focus, execute, options) {
    const base = emptyResult();
    const idaExecutable = await findCtfExecutable('idat64', options.cwd)
        ?? await findCtfExecutable('idat', options.cwd)
        ?? await findCtfExecutable('ida64', options.cwd)
        ?? await findCtfExecutable('ida', options.cwd);
    const script = buildIdaScript(file.relativePath, focus);
    const launcher = { executable: idaExecutable ?? 'idat64', argv: ['-A', '-Sanalysis.py', file.path] };
    let analysisOutput = null;
    let scriptPath = null;
    if (!idaExecutable) {
        base.status = 'missing_capability';
        base.limitations.push('IDA CLI is not detected; the generated IDAPython script remains usable through the configured IDA MCP or the IDA UI. CLI is optional and only needed for batch execution.');
        base.nextActions.push({ tool: 'mcp.ida_pro', args: { path: file.relativePath, focus }, reason: 'Use the configured IDA MCP to run the generated IDAPython analysis in the existing IDA database.' });
        base.nextActions.push({ tool: 'ctf_tool_setup', args: { target: 'ida_pro' }, reason: 'Use this only when an IDA CLI batch fallback is specifically required.' });
    }
    else {
        base.status = 'ok';
        base.observations.push(`IDA CLI candidate detected: ${idaExecutable}.`);
        if (execute) {
            const scriptDir = await mkdtemp(path.join(tmpdir(), 'dsh-ida-script-'));
            scriptPath = path.join(scriptDir, 'analysis.py');
            await writeFile(scriptPath, script, 'utf8');
            const executionArgv = ['-A', `-S${scriptPath}`, file.path];
            const capture = await runCommand(idaExecutable, executionArgv, {
                ...options,
                maxOutputChars: Math.max(options.maxOutputChars ?? 60_000, 120_000),
            });
            launcher.argv = executionArgv;
            base.commands.push(commandRecord(idaExecutable, executionArgv, capture, options.cwd));
            analysisOutput = [capture.stdout, capture.stderr].filter(Boolean).join('\n').trim() || null;
            base.observations.push(capture.ok
                ? 'IDA batch analysis completed with the generated IDAPython script.'
                : `IDA batch analysis exited with ${capture.exitCode ?? 'no status'}.`);
            if (!capture.ok)
                base.limitations.push(capture.error ?? capture.stderr.trim());
            base.status = capture.ok ? 'ok' : 'failed';
        }
        else {
            base.nextActions.push({ tool: 'ctf_re_ida_script', args: { path: file.relativePath, focus, execute: true }, reason: 'Execute the generated IDAPython script after reviewing its focus terms.' });
        }
    }
    return {
        ...base,
        executable: idaExecutable ?? null,
        launcher,
        script,
        executed: execute && Boolean(idaExecutable),
        analysisOutput,
        scriptPath,
    };
}
function buildIdaScript(relativePath, focus) {
    const focusLiteral = JSON.stringify(focus);
    const pathLiteral = JSON.stringify(relativePath);
    return `# IDAPython autogenerated by dsh-vehicle-security
import json
import ida_nalt
import idaapi
import idautils
import ida_funcs
import ida_name
import ida_auto

FOCUS = ${focusLiteral}
INPUT_FILE = ${pathLiteral}
FOCUS_TERMS = [term for term in (FOCUS or "").lower().replace(",", " ").split() if term]

def emit(kind, payload):
    print(json.dumps({"kind": kind, "payload": payload}, ensure_ascii=False))

def collect_strings():
    items = []
    for s in idautils.Strings():
        value = str(s)
        if FOCUS_TERMS and not any(term in value.lower() for term in FOCUS_TERMS):
            continue
        items.append({"ea": hex(int(s.ea)), "value": value})
        if len(items) >= 100:
            break
    return items

def collect_functions():
    items = []
    for ea in idautils.Functions():
        name = ida_name.get_name(ea) or f"sub_{int(ea):x}"
        items.append({"ea": hex(int(ea)), "name": name})
        if len(items) >= 200:
            break
    return items

def collect_xrefs(strings):
    items = []
    for string_item in strings[:50]:
        ea = int(string_item["ea"], 16)
        for xref in idautils.XrefsTo(ea):
            items.append({"from": hex(int(xref.frm)), "to": hex(int(xref.to)), "type": str(xref.type)})
            if len(items) >= 200:
                return items
    return items

def main():
    ida_auto.auto_wait()
    emit("input_file", ida_nalt.get_input_file_path() or INPUT_FILE)
    emit("focus", FOCUS)
    functions = collect_functions()
    strings = collect_strings()
    xrefs = collect_xrefs(strings)
    emit("functions", functions)
    emit("strings", strings)
    emit("xrefs", xrefs)

if __name__ == "__main__":
    main()
`;
}
function tryParseJson(text) {
    const lines = text.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    for (let index = lines.length - 1; index >= 0; index -= 1) {
        const line = lines[index];
        if (!(line.startsWith('{') || line.startsWith('[')))
            continue;
        try {
            return JSON.parse(line);
        }
        catch {
            continue;
        }
    }
    return null;
}
//# sourceMappingURL=retools.js.map