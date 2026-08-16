import { readFile } from 'node:fs/promises';
import Schema from '@deepseek-ai/schemastery';
import { defineTool } from '@deepseek-ai/dsh-tools';
import { auditTools } from './audit.js';
import { triageArtifact } from './artifact.js';
import { parseCanLog } from './can.js';
import { planInvestigation } from './investigation.js';
import { resolveWorkspaceFile } from './paths.js';
import { analyzeProgram } from './program.js';
import { decodeUds } from './uds.js';
export const name = 'vehicle-security-tools';
export const inject = ['tools'];
export const Config = Schema.object({
    workspaceRoot: Schema.string(),
    maxFileBytes: Schema.number().default(256 * 1024 * 1024),
    maxOutputChars: Schema.number().default(40_000),
    commandTimeoutMs: Schema.number().default(20_000),
    enableBinwalk: Schema.boolean().default(true),
});
const jsonOutput = {
    schema: { type: 'json' },
    render: (_args, value) => [
        { type: 'text', text: JSON.stringify(value, null, 2) },
    ],
};
export function apply(ctx, config) {
    validateConfig(config);
    const commandOptions = {
        timeoutMs: config.commandTimeoutMs,
        maxOutputChars: config.maxOutputChars,
    };
    ctx.tools.register(defineTool({
        name: 'vehicle_investigation_plan',
        description: 'Route an attachment, prompt, or lab objective into a formal vehicle-security investigation with ranked lanes, first validation actions, language choices, evidence rules, and stop conditions.',
        parameters: {
            objective: { type: 'string', required: true, description: 'Concrete question or desired outcome' },
            inputKind: { type: 'string', description: 'Optional intake kind: artifact, prompt, or lab' },
            context: { type: 'string', description: 'Optional constraints, target description, observed behavior, or available data' },
            path: { type: 'string', description: 'Optional attachment path relative to workspaceRoot' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const inputKind = parseInputKind(args.inputKind);
            const file = args.path
                ? await resolveWorkspaceFile(executionWorkspace(config, exec), args.path, config.maxFileBytes)
                : null;
            return planInvestigation({ objective: args.objective, inputKind, context: args.context }, file, {
                ...commandOptions,
                signal: exec.signal,
                enableBinwalk: false,
            });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'vehicle_tool_audit',
        description: 'Audit the local vehicle-security toolchain and report executable paths and versions.',
        parameters: {},
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(_args, exec) {
            return auditTools({ ...commandOptions, signal: exec.signal });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'vehicle_can_log_summary',
        description: 'Parse a local candump or Vector ASC log and summarize CAN IDs, counts, channels, timestamps, and sample frames.',
        parameters: {
            path: { type: 'string', required: true, description: 'Log path relative to workspaceRoot' },
            idFilter: { type: 'string', description: 'Optional comma-separated CAN IDs, for example 0x7E0,0x7E8' },
            maxFrames: { type: 'integer', description: 'Maximum parsed frames, from 1 to 1000000' },
        },
        output: jsonOutput,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const file = await resolveWorkspaceFile(executionWorkspace(config, exec), args.path, config.maxFileBytes);
            const text = await readFile(file.path, 'utf8');
            return { path: file.relativePath, ...parseCanLog(text, args) };
        },
    }));
    ctx.tools.register(defineTool({
        name: 'vehicle_uds_decode',
        description: 'Decode one UDS request or response payload, with optional ISO-TP single/first-frame unwrapping.',
        parameters: {
            payload: { type: 'string', required: true, description: 'Hex bytes, for example 03 22 F1 90' },
            stripIsoTp: { type: 'boolean', description: 'Decode an ISO-TP prefix when present; defaults to true' },
        },
        output: jsonOutput,
        isConcurrencySafe: () => true,
        async execute(args) {
            return decodeUds(args.payload, args.stripIsoTp ?? true);
        },
    }));
    ctx.tools.register(defineTool({
        name: 'vehicle_program_analyze',
        description: 'Build an evidence-backed program analysis: identity, ELF hardening, imports, relevant strings, bounded conclusions, hypotheses, and tool validation steps.',
        parameters: {
            path: { type: 'string', required: true, description: 'Program path relative to workspaceRoot' },
            focus: { type: 'string', description: 'Optional analysis objective, for example diagnostic authentication or CAN message parsing' },
            maxStrings: { type: 'integer', description: 'Maximum tagged strings to return, from 1 to 500' },
            minStringLength: { type: 'integer', description: 'Minimum printable string length, from 4 to 64' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const file = await resolveWorkspaceFile(executionWorkspace(config, exec), args.path, config.maxFileBytes);
            return analyzeProgram(file, {
                ...commandOptions,
                signal: exec.signal,
                focus: args.focus,
                maxStrings: args.maxStrings,
                minStringLength: args.minStringLength,
            });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'vehicle_artifact_triage',
        description: 'Perform read-only firmware or binary triage: size, SHA-256, sampled entropy, file type, and optional Binwalk signature scan.',
        parameters: {
            path: { type: 'string', required: true, description: 'Artifact path relative to workspaceRoot' },
            runBinwalk: { type: 'boolean', description: 'Run Binwalk when enabled in plugin config; defaults to true' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const file = await resolveWorkspaceFile(executionWorkspace(config, exec), args.path, config.maxFileBytes);
            return triageArtifact(file, {
                ...commandOptions,
                signal: exec.signal,
                enableBinwalk: config.enableBinwalk && (args.runBinwalk ?? true),
            });
        },
    }));
}
function executionWorkspace(config, exec) {
    const configured = config.workspaceRoot?.trim();
    if (configured)
        return configured;
    const sessionCwd = exec.agent?.session.header.cwd;
    if (sessionCwd)
        return sessionCwd;
    throw new Error('session workspace is unavailable; configure workspaceRoot explicitly');
}
function parseInputKind(value) {
    if (value === undefined || value === '')
        return undefined;
    if (value === 'artifact' || value === 'prompt' || value === 'lab')
        return value;
    throw new Error('inputKind must be artifact, prompt, or lab');
}
function validateConfig(config) {
    for (const [key, value] of Object.entries({
        maxFileBytes: config.maxFileBytes,
        maxOutputChars: config.maxOutputChars,
        commandTimeoutMs: config.commandTimeoutMs,
    })) {
        if (!Number.isInteger(value) || value <= 0)
            throw new Error(`${key} must be a positive integer`);
    }
}
//# sourceMappingURL=index.js.map