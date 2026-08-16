import { readFile } from 'node:fs/promises';
import Schema from '@deepseek-ai/schemastery';
import { defineTool } from '@deepseek-ai/dsh-tools';
import { auditTools } from './audit.js';
import { triageArtifact } from './artifact.js';
import { parseCanLog } from './can.js';
import { resolveWorkspaceFile } from './paths.js';
import { decodeUds } from './uds.js';
export const name = 'vehicle-security';
export const inject = ['tools'];
export const Config = Schema.object({
    workspaceRoot: Schema.string().default('.'),
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
        async execute(args) {
            const file = await resolveWorkspaceFile(config.workspaceRoot, args.path, config.maxFileBytes);
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
            const file = await resolveWorkspaceFile(config.workspaceRoot, args.path, config.maxFileBytes);
            return triageArtifact(file, {
                ...commandOptions,
                signal: exec.signal,
                enableBinwalk: config.enableBinwalk && (args.runBinwalk ?? true),
            });
        },
    }));
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