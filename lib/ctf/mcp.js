import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { emptyResult } from './types.js';
export async function discoverCtfMcpConfiguration(cwd = process.cwd()) {
    const explicitPaths = [
        process.env.DSH_CTF_MCP_CONFIG?.trim(),
        process.env.CTF_MCP_CONFIG?.trim(),
    ].filter((item) => Boolean(item));
    const home = os.homedir();
    const xdgConfig = process.env.XDG_CONFIG_HOME?.trim() || path.join(home, '.config');
    const candidatePaths = [
        ...explicitPaths,
        path.join(xdgConfig, 'dsh', 'ctf-mcp.json'),
        path.join(cwd, '.dsh', 'ctf-mcp.json'),
        path.join(home, '.codex', 'mcp.json'),
        path.join(home, '.codex', 'config.json'),
    ];
    const configuredServers = {};
    const serverSources = {};
    const configPaths = [];
    for (const candidate of [...new Set(candidatePaths)]) {
        try {
            const parsed = JSON.parse(await readFile(candidate, 'utf8'));
            const servers = parsed.mcpServers ?? parsed.servers ?? {};
            if (!servers || typeof servers !== 'object')
                continue;
            configPaths.push(candidate);
            for (const [name, value] of Object.entries(servers)) {
                configuredServers[name] = value;
                serverSources[name] = candidate;
            }
        }
        catch {
            // Missing and non-JSON host configuration files are ignored.
        }
    }
    const chromeUrl = process.env.DSH_CTF_CHROME_MCP_URL?.trim();
    if (chromeUrl) {
        configuredServers['mcp-chrome'] = { url: chromeUrl };
        serverSources['mcp-chrome'] = 'DSH_CTF_CHROME_MCP_URL';
    }
    if (process.env.TAVILY_API_KEY?.trim()) {
        configuredServers['tavily-mcp'] = {
            command: 'npx',
            args: ['-y', 'tavily-mcp@latest'],
            env: { TAVILY_API_KEY: '[provided by environment]' },
        };
        serverSources['tavily-mcp'] = 'TAVILY_API_KEY';
    }
    return { configuredServers, serverSources, configPaths };
}
export async function configureCtfMcp(args = {}) {
    const base = emptyResult();
    const configPath = resolveConfigPath(args.configPath);
    const includeChrome = args.includeChrome ?? true;
    const includeTavily = args.includeTavily ?? true;
    const requiredSecrets = [];
    const configured = [];
    let document = { mcpServers: {} };
    try {
        const parsed = JSON.parse(await readFile(configPath, 'utf8'));
        document = {
            mcpServers: parsed?.mcpServers && typeof parsed.mcpServers === 'object' ? parsed.mcpServers : {},
        };
    }
    catch (error) {
        if (isMissingFile(error)) {
            document = { mcpServers: {} };
        }
        else {
            base.status = 'failed';
            base.limitations.push(`MCP config is not valid JSON: ${configPath}`);
            return { ...base, configPath, configured, requiredSecrets };
        }
    }
    if (includeChrome) {
        const chromeUrl = args.chromeUrl?.trim()
            || process.env.DSH_CTF_CHROME_MCP_URL?.trim()
            || 'http://127.0.0.1:12306/mcp';
        document.mcpServers['mcp-chrome'] = { url: chromeUrl };
        configured.push('mcp.chrome');
    }
    if (includeTavily) {
        const current = asServer(document.mcpServers['tavily-mcp']);
        const key = args.tavilyApiKey?.trim() || process.env.TAVILY_API_KEY?.trim() || current?.env?.TAVILY_API_KEY;
        if (key && !isPlaceholder(key)) {
            document.mcpServers['tavily-mcp'] = {
                command: 'npx',
                args: ['-y', 'tavily-mcp@latest'],
                env: { TAVILY_API_KEY: key },
            };
            configured.push('mcp.tavily');
        }
        else {
            requiredSecrets.push('TAVILY_API_KEY');
            base.limitations.push('Tavily MCP needs TAVILY_API_KEY; provide only that key to ctf_mcp_configure.');
        }
    }
    await mkdir(path.dirname(configPath), { recursive: true });
    await writeFile(configPath, `${JSON.stringify(document, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    await chmod(configPath, 0o600);
    base.observations.push(`CTF MCP configuration written to ${configPath}.`);
    base.observations.push(`configured servers: ${configured.length > 0 ? configured.join(', ') : 'none'}.`);
    base.status = requiredSecrets.length > 0 ? 'missing_capability' : 'ok';
    return { ...base, configPath, configured, requiredSecrets };
}
export function resolveConfigPath(configPath) {
    return configPath?.trim()
        || process.env.DSH_CTF_MCP_CONFIG?.trim()
        || process.env.CTF_MCP_CONFIG?.trim()
        || path.join(process.env.XDG_CONFIG_HOME?.trim() || path.join(os.homedir(), '.config'), 'dsh', 'ctf-mcp.json');
}
function asServer(value) {
    if (!value || typeof value !== 'object')
        return null;
    const env = value.env;
    if (!env || typeof env !== 'object')
        return {};
    return {
        env: Object.fromEntries(Object.entries(env).filter((entry) => typeof entry[1] === 'string')),
    };
}
function isPlaceholder(value) {
    return value.startsWith('REPLACE_WITH_') || value === 'TAVILY_API_KEY';
}
function isMissingFile(error) {
    return Boolean(error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT');
}
//# sourceMappingURL=mcp.js.map