import Schema from '@deepseek-ai/schemastery';
import { defineTool } from '@deepseek-ai/dsh-tools';
import { resolveWorkspaceFile } from '../paths.js';
import { profileCtfArtifact } from './artifact.js';
import { debugPwnArtifact, debugPwndbgArtifact, profilePwnArtifact, profileReArtifact, searchRopGadgets } from './binary.js';
import { auditCtfTools } from './capabilities.js';
import { probeCryptoInput } from './crypto.js';
import { runCtfCryptoEngine } from './crypto-exec.js';
import { createHumanRequest, operationsFromLegacySteps } from './human.js';
import { configureCtfMcp } from './mcp.js';
import { profilePcapArtifact, triageMiscArtifact } from './misc.js';
import { runCtfPython } from './python.js';
import { routeCtfStart } from './router.js';
import { searchOneGadgets } from './one-gadget.js';
import { buildIdaScriptPlan, queryRadare2 } from './retools.js';
import { profileSeccomp } from './seccomp.js';
import { createToolSetupRequest } from './setup.js';
import { httpDiff, httpRequest, probeWebBrowser, probeWebCapture } from './web.js';
import { runPwninit } from './pwninit.js';
import { emptyResult } from './types.js';
export const name = 'ctf-tools';
export const inject = ['tools'];
export const Config = Schema.object({
    workspaceRoot: Schema.string(),
    maxFileBytes: Schema.number().default(128 * 1024 * 1024),
    maxOutputChars: Schema.number().default(60_000),
    commandTimeoutMs: Schema.number().default(20_000),
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
        name: 'ctf_tool_audit',
        description: 'Refresh local CTF capabilities. Returns executable paths, the selected Python environment, MCP configuration, and directly callable local tool bindings with example arguments. Intake is recommended, not mandatory.',
        parameters: {},
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(_args, exec) {
            return auditCtfTools({ ...commandOptions, signal: exec.signal });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_mcp_configure',
        description: 'Write the CTF MCP configuration for mcp-chrome and Tavily. The model supplies only TAVILY_API_KEY when needed; paths, server JSON, and secret redaction are handled automatically.',
        parameters: {
            configPath: { type: 'string', description: 'Optional MCP JSON path; defaults to the DSH CTF config path' },
            chromeUrl: { type: 'string', description: 'Optional mcp-chrome HTTP endpoint; defaults to http://127.0.0.1:12306/mcp' },
            includeChrome: { type: 'boolean', description: 'Configure mcp-chrome; defaults to true' },
            includeTavily: { type: 'boolean', description: 'Configure Tavily MCP; defaults to true' },
            tavilyApiKey: { type: 'string', description: 'Tavily API key. Never include it in a human log or screenshot return.' },
        },
        output: jsonOutput,
        isConcurrencySafe: () => false,
        async execute(args) {
            return configureCtfMcp({
                configPath: args.configPath,
                chromeUrl: args.chromeUrl,
                includeChrome: args.includeChrome,
                includeTavily: args.includeTavily,
                tavilyApiKey: args.tavilyApiKey,
            });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_python_exec',
        description: 'Execute inline Python or a workspace script with the fixed CTF interpreter /home/source/tools/PyVenv/CTF/bin/python. Never falls back to python3, PATH Python, or another virtual environment.',
        parameters: {
            code: { type: 'string', description: 'Inline Python source; provide this or scriptPath' },
            scriptPath: { type: 'string', description: 'Python script path relative to the active workspace; provide this or code' },
            argv: { type: 'array', items: { type: 'string' }, description: 'Optional script arguments' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            return runCtfPython({
                code: args.code,
                scriptPath: args.scriptPath,
                argv: args.argv,
            }, {
                ...commandOptions,
                workspaceRoot: executionWorkspace(config, exec),
                maxFileBytes: config.maxFileBytes,
                signal: exec.signal,
            });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_artifact_profile',
        description: 'Profile one local CTF artifact: hash, size, magic, file type, entropy, and text sample. Use this as the first file-based CTF step.',
        parameters: {
            path: { type: 'string', required: true, description: 'Artifact path relative to the active workspace' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const workspace = executionWorkspace(config, exec);
            const file = await resolveWorkspaceFile(workspace, args.path, config.maxFileBytes);
            const profile = await profileCtfArtifact(file, { ...commandOptions, signal: exec.signal });
            return {
                ...emptyResult('ok'),
                observations: profile.observations,
                commands: profile.commands,
                artifacts: [profile.artifact],
                limitations: profile.limitations,
                artifact: profile.artifact,
                nextActions: [
                    { tool: 'ctf_start', args: { path: profile.artifact.path }, reason: 'Route the profiled artifact to the category-specific tool.' },
                ],
            };
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_start',
        description: 'CTF router and capability snapshot. It audits local capabilities, profiles an optional artifact, selects a category, and returns ranked tool choices. Use it for intake when useful; direct category tools remain callable when the target and context are already known.',
        parameters: {
            objective: { type: 'string', description: 'Challenge objective or user question' },
            path: { type: 'string', description: 'Optional challenge artifact path relative to the active workspace' },
            url: { type: 'string', description: 'Optional local or remote challenge URL' },
            category: { type: 'string', description: 'Optional category: auto, re, pwn, crypto, misc, or web' },
            context: { type: 'string', description: 'Optional challenge text, constraints, service info, or notes' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const workspace = executionWorkspace(config, exec);
            const audit = await auditCtfTools({ ...commandOptions, signal: exec.signal });
            const profile = args.path
                ? await profileCtfArtifact(await resolveWorkspaceFile(workspace, args.path, config.maxFileBytes), { ...commandOptions, signal: exec.signal })
                : null;
            const decision = routeCtfStart({
                objective: args.objective,
                path: args.path,
                url: args.url,
                category: parseCategory(args.category),
                context: args.context,
            }, profile?.artifact ?? null, audit);
            return {
                schemaVersion: '1.0',
                status: decision.humanRequired.length > 0 ? 'human_required' : 'ok',
                objective: args.objective ?? '',
                category: decision.category,
                reasons: decision.reasons,
                artifact: profile?.artifact ?? null,
                availableCapabilities: audit.capabilities.filter(item => item.available).map(item => item.id),
                availablePythonModules: audit.python.modules.filter(item => item.available).map(item => item.id),
                mcp: audit.mcp,
                toolBindings: audit.toolBindings,
                recommendedTool: decision.recommendedTool,
                recommendedArgs: decision.recommendedArgs,
                toolChoices: decision.toolChoices,
                toolGraph: decision.toolGraph,
                observations: [
                    ...audit.recommendations.map(item => `recommendation: ${item}`),
                    ...(profile?.observations ?? []),
                ],
                commands: [
                    ...audit.commands,
                    ...(profile?.commands ?? []),
                ],
                artifacts: profile ? [profile.artifact] : [],
                limitations: profile?.limitations ?? [],
                nextActions: decision.nextActions,
                humanRequired: decision.humanRequired,
            };
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_re_profile',
        description: 'Reverse-engineering profile for one binary or source-like artifact using installed tools such as file, readelf, strings, and binutils before any custom solver script.',
        parameters: {
            path: { type: 'string', required: true, description: 'Artifact path relative to the active workspace' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const file = await workspaceFile(config, exec, args.path);
            return profileReArtifact(file, { ...commandOptions, signal: exec.signal });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_pwn_profile',
        description: 'Static Pwn profile after the mandatory ctf_pwninit first step. Returns mitigation, import, string, and next-action evidence; choose deeper tools according to the evidence question.',
        parameters: {
            path: { type: 'string', required: true, description: 'Binary path relative to the active workspace' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const file = await workspaceFile(config, exec, args.path);
            return profilePwnArtifact(file, { ...commandOptions, signal: exec.signal });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_pwninit',
        description: 'Patch or diagnose a Pwn binary with matching ld/libc files. Use when a local runtime source exists; prepare is deterministic and creates a backup, while doctor/restore/list_backups are non-exploit maintenance operations.',
        parameters: {
            path: { type: 'string', required: true, description: 'Pwn binary path relative to the active workspace' },
            mode: { type: 'string', enum: ['prepare', 'doctor', 'restore', 'list_backups'], description: 'prepare patches the runtime; doctor diagnoses it; restore reverts the latest backup; list_backups lists available backups' },
            libcPath: { type: 'string', description: 'Optional libc path relative to the active workspace; sibling libc files are auto-detected when omitted' },
            ldPath: { type: 'string', description: 'Optional loader path relative to the active workspace; sibling ld files are auto-detected when omitted' },
            dependencyDir: { type: 'string', description: 'Optional dependency directory relative to the active workspace; uses pwninit -M' },
            libcVersion: { type: 'string', description: 'Optional glibc-all-in-one version or directory fragment' },
            libcIndex: { type: 'integer', description: 'Optional 1-based glibc-all-in-one candidate index' },
            onlyLibc: { type: 'boolean', description: 'Patch only the loader/libc; defaults to true' },
            onlyInit: { type: 'boolean', description: 'Only run pwninit initialization and skip libc patching' },
            generateExp: { type: 'boolean', description: 'Allow pwninit to generate exp.py; defaults to false' },
            forceExp: { type: 'boolean', description: 'Overwrite exp.py when generateExp is true' },
            debug: { type: 'boolean', description: 'Enable pwninit debug logging' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 3,
        isConcurrencySafe: () => false,
        async execute(args, exec) {
            const file = await workspaceFile(config, exec, args.path);
            return runPwninit(file, {
                mode: args.mode,
                libcPath: args.libcPath,
                ldPath: args.ldPath,
                dependencyDir: args.dependencyDir,
                libcVersion: args.libcVersion,
                libcIndex: args.libcIndex,
                onlyLibc: args.onlyLibc,
                onlyInit: args.onlyInit,
                generateExp: args.generateExp,
                forceExp: args.forceExp,
                debug: args.debug,
            }, {
                ...commandOptions,
                maxFileBytes: config.maxFileBytes,
                signal: exec.signal,
            });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_pwn_debug_probe',
        description: 'Run bounded generic GDB on a local Pwn binary. Use for registers, stack, entrypoint, a named/address breakpoint, or custom GDB commands when Pwndbg is not needed or unavailable.',
        parameters: {
            path: { type: 'string', required: true, description: 'Binary path relative to the active workspace' },
            argv: { type: 'array', items: { type: 'string' }, description: 'Optional process argv values' },
            breakAt: { type: 'string', description: 'Optional breakpoint symbol or address, for example main or *0x401000' },
            extraGdbCommands: { type: 'array', items: { type: 'string' }, description: 'Optional extra bounded gdb commands' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const file = await workspaceFile(config, exec, args.path);
            return debugPwnArtifact(file, {
                argv: args.argv,
                breakAt: args.breakAt,
                extraGdbCommands: args.extraGdbCommands,
            }, { ...commandOptions, signal: exec.signal });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_pwn_gdb_probe',
        description: 'Run bounded GDB with the Pwndbg frontend when available. Use for heap/runtime state, context, vmmap, registers, backtrace, or a named/address breakpoint; returns raw debugger output and exact argv.',
        parameters: {
            path: { type: 'string', required: true, description: 'Binary path relative to the active workspace' },
            argv: { type: 'array', items: { type: 'string' }, description: 'Optional process argv values' },
            breakAt: { type: 'string', description: 'Optional breakpoint symbol or address' },
            extraCommands: { type: 'array', items: { type: 'string' }, description: 'Optional extra bounded GDB/Pwndbg commands' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const file = await workspaceFile(config, exec, args.path);
            return debugPwndbgArtifact(file, {
                argv: args.argv,
                breakAt: args.breakAt,
                extraCommands: args.extraCommands,
            }, { ...commandOptions, signal: exec.signal });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_re_r2_query',
        description: 'Run bounded radare2 commands against a local artifact. Use for fast headless functions, xrefs, sections, metadata, and focused disassembly; returns exact commands, raw output, and the last parseable JSON result.',
        parameters: {
            path: { type: 'string', required: true, description: 'Artifact path relative to the active workspace' },
            commands: { type: 'array', items: { type: 'string' }, description: 'Ordered r2 commands; defaults to aaa and ij' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const file = await workspaceFile(config, exec, args.path);
            return queryRadare2(file, args.commands ?? [], { ...commandOptions, signal: exec.signal });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_re_ida_script',
        description: 'Generate focused IDAPython for functions, strings, and xrefs. Use the configured IDA MCP/UI or the detected local IDA CLI path; optional batch execution is disabled by default.',
        parameters: {
            path: { type: 'string', required: true, description: 'Artifact path relative to the active workspace' },
            focus: { type: 'string', description: 'Optional terms used to filter strings and guide the generated script' },
            execute: { type: 'boolean', description: 'Execute the generated script when IDA CLI is available; defaults to false' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 3,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const file = await workspaceFile(config, exec, args.path);
            return buildIdaScriptPlan(file, args.focus ?? '', args.execute ?? false, { ...commandOptions, signal: exec.signal });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_rop_search',
        description: 'Search gadgets in a local binary using ROPgadget or ropper. Use when NX is enabled, a ROP chain is plausible, or available control-flow gadgets need confirmation.',
        parameters: {
            path: { type: 'string', required: true, description: 'Binary path relative to the active workspace' },
            query: { type: 'string', description: 'Optional gadget query, for example pop|ret' },
            maxResults: { type: 'integer', description: 'Maximum gadget lines to return, from 1 to 500' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const file = await workspaceFile(config, exec, args.path);
            return searchRopGadgets(file, {
                query: args.query,
                maxResults: args.maxResults,
            }, { ...commandOptions, signal: exec.signal });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_one_gadget',
        description: 'Search one_gadget candidates in a local libc. Pass libcPath explicitly or keep libc-*.so beside the challenge binary; use after pwninit when ret2libc or libc-base control flow is relevant.',
        parameters: {
            path: { type: 'string', required: true, description: 'Challenge binary or libc path relative to the active workspace' },
            libcPath: { type: 'string', description: 'Optional libc path relative to the active workspace; sibling libc files are auto-detected when omitted' },
            level: { type: 'integer', description: 'one_gadget constraint level from 0 to 5; defaults to 0' },
            near: { type: 'string', description: 'Optional symbol or address filter passed to one_gadget' },
            raw: { type: 'boolean', description: 'Return raw offsets when supported by one_gadget' },
            maxResults: { type: 'integer', description: 'Maximum parsed gadget entries, from 1 to 500; defaults to 80' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const file = await workspaceFile(config, exec, args.path);
            return searchOneGadgets(file, {
                libcPath: args.libcPath,
                level: args.level,
                near: args.near,
                raw: args.raw,
                maxResults: args.maxResults,
            }, {
                ...commandOptions,
                maxFileBytes: config.maxFileBytes,
                signal: exec.signal,
            });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_seccomp_profile',
        description: 'Inspect seccomp filters installed by a local Pwn binary with seccomp-tools. Use when imports, strings, or runtime evidence suggest prctl, seccomp, sandboxing, or syscall restrictions.',
        parameters: {
            path: { type: 'string', required: true, description: 'Binary path relative to the active workspace' },
            argv: { type: 'array', items: { type: 'string' }, description: 'Optional target arguments; the target is launched through seccomp-tools --sh-exec' },
            format: { type: 'string', enum: ['disasm', 'raw', 'inspect'], description: 'seccomp-tools output format; defaults to disasm' },
            limit: { type: 'integer', description: 'Maximum number of seccomp filters to capture, from 1 to 32; defaults to 1' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const file = await workspaceFile(config, exec, args.path);
            return profileSeccomp(file, {
                argv: args.argv,
                format: args.format,
                limit: args.limit,
            }, { ...commandOptions, signal: exec.signal });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_crypto_probe',
        description: 'Probe text or a small local file for common CTF crypto encodings, entropy, hashes, and single-byte XOR candidates before writing a custom solver.',
        parameters: {
            path: { type: 'string', description: 'Optional artifact path relative to the active workspace' },
            text: { type: 'string', description: 'Optional ciphertext, encoded value, or challenge text' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const file = args.path ? await workspaceFile(config, exec, args.path) : undefined;
            return probeCryptoInput({ file, text: args.text });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_sage_exec',
        description: 'Execute SageMath code or a workspace .sage/.py script for CTF number theory, algebra, finite fields, elliptic curves, and symbolic calculations. Use only after crypto evidence shows Sage is useful.',
        parameters: {
            code: { type: 'string', description: 'Inline SageMath source; provide this or scriptPath' },
            scriptPath: { type: 'string', description: 'SageMath script path relative to the active workspace; provide this or code' },
            argv: { type: 'array', items: { type: 'string' }, description: 'Optional script arguments' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            return runCtfCryptoEngine('sage', {
                code: args.code,
                scriptPath: args.scriptPath,
                argv: args.argv,
            }, {
                ...commandOptions,
                workspaceRoot: executionWorkspace(config, exec),
                maxFileBytes: config.maxFileBytes,
                signal: exec.signal,
            });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_gp_exec',
        description: 'Execute PARI/GP code or a workspace .gp script for CTF integer arithmetic, factorization, discrete logarithms, and algebraic number theory. Use only when GP is the best local backend.',
        parameters: {
            code: { type: 'string', description: 'Inline PARI/GP source; provide this or scriptPath' },
            scriptPath: { type: 'string', description: 'PARI/GP script path relative to the active workspace; provide this or code' },
            argv: { type: 'array', items: { type: 'string' }, description: 'Optional script arguments' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            return runCtfCryptoEngine('gp', {
                code: args.code,
                scriptPath: args.scriptPath,
                argv: args.argv,
            }, {
                ...commandOptions,
                workspaceRoot: executionWorkspace(config, exec),
                maxFileBytes: config.maxFileBytes,
                signal: exec.signal,
            });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_misc_triage',
        description: 'Misc/forensics triage for archives, images, captures, and unknown files using local tools such as binwalk, exiftool, 7z, strings, and zsteg.',
        parameters: {
            path: { type: 'string', required: true, description: 'Artifact path relative to the active workspace' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const file = await workspaceFile(config, exec, args.path);
            return triageMiscArtifact(file, { ...commandOptions, signal: exec.signal });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_pcap_profile',
        description: 'PCAP profile using tshark to summarize protocol hierarchy and TCP/UDP conversations.',
        parameters: {
            path: { type: 'string', required: true, description: 'PCAP path relative to the active workspace' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            const file = await workspaceFile(config, exec, args.path);
            return profilePcapArtifact(file, { ...commandOptions, signal: exec.signal });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_http_request',
        description: 'Run one structured HTTP request through local curl and return status, body length, hash, preview, exact argv, and next diff action.',
        parameters: {
            url: { type: 'string', required: true, description: 'Challenge URL' },
            method: { type: 'string', description: 'HTTP method; defaults to GET' },
            headers: { type: 'array', items: { type: 'string' }, description: 'Optional headers in Name: value form' },
            body: { type: 'string', description: 'Optional request body' },
            followRedirects: { type: 'boolean', description: 'Follow redirects with curl -L' },
            maxTimeSeconds: { type: 'number', description: 'curl max-time in seconds, from 1 to 120' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            return httpRequest({
                url: args.url,
                method: args.method,
                headers: args.headers,
                body: args.body,
                followRedirects: args.followRedirects,
                maxTimeSeconds: args.maxTimeSeconds,
            }, { ...commandOptions, signal: exec.signal });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_http_diff',
        description: 'Run two structured HTTP requests through curl and compare status, body length, and body hash.',
        parameters: {
            urlA: { type: 'string', required: true, description: 'Baseline URL' },
            urlB: { type: 'string', required: true, description: 'Variant URL' },
            method: { type: 'string', description: 'HTTP method for both requests' },
            headers: { type: 'array', items: { type: 'string' }, description: 'Optional headers in Name: value form' },
            bodyA: { type: 'string', description: 'Optional baseline request body' },
            bodyB: { type: 'string', description: 'Optional variant request body' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 3,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            return httpDiff({
                urlA: args.urlA,
                urlB: args.urlB,
                method: args.method,
                headers: args.headers,
                bodyA: args.bodyA,
                bodyB: args.bodyB,
            }, { ...commandOptions, signal: exec.signal });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_web_browser_probe',
        description: 'Use local Chromium or Chrome headless mode to capture a DOM preview, title, and optional screenshot before requesting interactive browser MCP operations.',
        parameters: {
            url: { type: 'string', required: true, description: 'HTTP(S) URL to open' },
            captureScreenshot: { type: 'boolean', description: 'Capture a PNG screenshot; defaults to true' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 3,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            return probeWebBrowser({
                url: args.url,
                captureScreenshot: args.captureScreenshot,
            }, { ...commandOptions, signal: exec.signal });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_web_capture_probe',
        description: 'Check local mitmproxy/mitmweb capability and create an ordered human handoff for starting a live HTTP(S) capture.',
        parameters: {
            listenHost: { type: 'string', description: 'Proxy listen host; defaults to 127.0.0.1' },
            listenPort: { type: 'integer', description: 'Proxy listen port; defaults to 8080' },
            webPort: { type: 'integer', description: 'mitmweb UI port; defaults to 8081' },
        },
        output: jsonOutput,
        timeoutMs: config.commandTimeoutMs * 2,
        isConcurrencySafe: () => true,
        async execute(args, exec) {
            return probeWebCapture({
                listenHost: args.listenHost,
                listenPort: args.listenPort,
                webPort: args.webPort,
            }, { ...commandOptions, signal: exec.signal });
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_tool_setup',
        description: 'Create an ordered human setup request for GDB/Pwndbg, IDA Pro, radare2, Sage, PARI/GP, mcp-chrome, mitmproxy, Python CTF packages, or BlackArch packages. The human returns only logs, screenshots, or OCR text.',
        parameters: {
            target: {
                type: 'string',
                required: true,
                enum: ['gdb_pwndbg', 'ida_pro', 'r2', 'one_gadget', 'seccomp_tools', 'sage', 'pari_gp', 'chrome_mcp', 'chrome_devtools_mcp', 'mitmproxy', 'python_ctf_env', 'blackarch_repo'],
                description: 'Tool or package setup target',
            },
            context: { type: 'string', description: 'Optional local setup context' },
        },
        output: jsonOutput,
        isConcurrencySafe: () => true,
        async execute(args) {
            return createToolSetupRequest(parseSetupTarget(args.target), args.context);
        },
    }));
    ctx.tools.register(defineTool({
        name: 'ctf_human_request',
        description: 'Create a structured human-action request. The model must provide ordered operations with command or instruction text; the human only returns logs, screenshots, or OCR text.',
        parameters: {
            type: { type: 'string', required: true, description: 'attach_device, start_service, perform_gui_action, provide_data, observe_state, or confirm' },
            title: { type: 'string', required: true, description: 'Short action title' },
            reason: { type: 'string', required: true, description: 'Why the human action is needed' },
            operationOrder: {
                required: true,
                type: 'array',
                items: {
                    type: 'object',
                    additionalProperties: true,
                    properties: {
                        order: { type: 'integer', required: true },
                        kind: { type: 'string', enum: ['command', 'instruction'], required: true },
                        title: { type: 'string', required: true },
                        command: { type: 'string' },
                        instruction: { type: 'string' },
                        expectedSignal: { type: 'string', required: true },
                    },
                },
                description: 'Ordered operations. Each item must include kind=command with command text or kind=instruction with instruction text.',
            },
            steps: { type: 'array', items: { type: 'string' }, description: 'Deprecated compatibility field; operationOrder is required for model-facing calls' },
            acceptedReturnTypes: { type: 'array', items: { type: 'string', enum: ['log', 'screenshot', 'ocr_text'] }, description: 'Allowed human return types: log, screenshot, ocr_text' },
            returnFields: { type: 'object', additionalProperties: true, description: 'Plain-text fields the human should include in logs, screenshots, or OCR text' },
        },
        output: jsonOutput,
        isConcurrencySafe: () => true,
        async execute(args) {
            const operations = Array.isArray(args.operationOrder) && args.operationOrder.length > 0
                ? args.operationOrder.map((operation, index) => parseHumanOperation(operation, index))
                : operationsFromLegacySteps(args.steps ?? []);
            const acceptedReturnTypes = (args.acceptedReturnTypes ?? ['log', 'screenshot', 'ocr_text']).map(parseHumanReturnType);
            const returnFields = Object.fromEntries(Object.entries(args.returnFields ?? {
                log: 'terminal output or service log text',
                screenshot: 'screenshot path or image content rendered as text',
                ocr_text: 'text recognized from the screenshot or GUI',
            }).map(([key, value]) => [key, String(value)]));
            return createHumanRequest({
                type: parseHumanRequestType(args.type),
                title: args.title,
                reason: args.reason,
                operationOrder: operations,
                acceptedReturnTypes,
                returnContract: {
                    onlyReturn: acceptedReturnTypes,
                    format: 'plain_text',
                    fields: returnFields,
                },
                legacySteps: args.steps,
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
async function workspaceFile(config, exec, inputPath) {
    return resolveWorkspaceFile(executionWorkspace(config, exec), inputPath, config.maxFileBytes);
}
function parseCategory(value) {
    if (value === undefined || value === '')
        return undefined;
    if (value === 'auto' || value === 're' || value === 'pwn' || value === 'crypto' || value === 'misc' || value === 'web')
        return value;
    throw new Error('category must be auto, re, pwn, crypto, misc, or web');
}
function parseSetupTarget(value) {
    if (value === 'gdb_pwndbg'
        || value === 'ida_pro'
        || value === 'r2'
        || value === 'one_gadget'
        || value === 'seccomp_tools'
        || value === 'sage'
        || value === 'pari_gp'
        || value === 'chrome_mcp'
        || value === 'chrome_devtools_mcp'
        || value === 'mitmproxy'
        || value === 'python_ctf_env'
        || value === 'blackarch_repo')
        return value;
    throw new Error('target must be gdb_pwndbg, ida_pro, r2, one_gadget, seccomp_tools, sage, pari_gp, chrome_mcp, chrome_devtools_mcp, mitmproxy, python_ctf_env, or blackarch_repo');
}
function parseHumanRequestType(value) {
    if (value === 'attach_device'
        || value === 'start_service'
        || value === 'perform_gui_action'
        || value === 'provide_data'
        || value === 'observe_state'
        || value === 'confirm')
        return value;
    throw new Error('type must be attach_device, start_service, perform_gui_action, provide_data, observe_state, or confirm');
}
function parseHumanOperation(value, index) {
    const kind = value.kind === 'command' ? 'command' : 'instruction';
    const command = typeof value.command === 'string' ? value.command : undefined;
    const instruction = typeof value.instruction === 'string' ? value.instruction : undefined;
    if (kind === 'command' && !command)
        throw new Error('command operation requires command text');
    if (kind === 'instruction' && !instruction)
        throw new Error('instruction operation requires instruction text');
    return {
        order: typeof value.order === 'number' && Number.isInteger(value.order) && value.order > 0 ? value.order : index + 1,
        kind,
        title: typeof value.title === 'string' && value.title.trim() ? value.title : `Step ${index + 1}`,
        ...(kind === 'command' ? { command } : { instruction }),
        expectedSignal: typeof value.expectedSignal === 'string' && value.expectedSignal.trim()
            ? value.expectedSignal
            : 'Return log, screenshot text, or OCR text showing the result.',
    };
}
function parseHumanReturnType(value) {
    if (value === 'log' || value === 'screenshot' || value === 'ocr_text')
        return value;
    throw new Error('acceptedReturnTypes must contain only log, screenshot, or ocr_text');
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