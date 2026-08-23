import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { emptyResult, type CtfToolResultBase } from './types.js'

export interface CtfMcpDiscovery {
  configuredServers: Record<string, unknown>
  serverSources: Record<string, string>
  configPaths: string[]
}

export interface CtfMcpConfigureResult extends CtfToolResultBase {
  configPath: string
  configured: string[]
  requiredSecrets: string[]
}

export interface CtfMcpConfigureArgs {
  configPath?: string
  chromeUrl?: string
  includeChrome?: boolean
  includeTavily?: boolean
  tavilyApiKey?: string
}

export async function discoverCtfMcpConfiguration(cwd = process.cwd()): Promise<CtfMcpDiscovery> {
  const explicitPaths = [
    process.env.DSH_CTF_MCP_CONFIG?.trim(),
    process.env.CTF_MCP_CONFIG?.trim(),
  ].filter((item): item is string => Boolean(item))
  const home = os.homedir()
  const xdgConfig = process.env.XDG_CONFIG_HOME?.trim() || path.join(home, '.config')
  const candidatePaths = [
    ...explicitPaths,
    path.join(xdgConfig, 'dsh', 'ctf-mcp.json'),
    path.join(cwd, '.dsh', 'ctf-mcp.json'),
    path.join(home, '.codex', 'mcp.json'),
    path.join(home, '.codex', 'config.json'),
  ]

  const configuredServers: Record<string, unknown> = {}
  const serverSources: Record<string, string> = {}
  const configPaths: string[] = []
  for (const candidate of [...new Set(candidatePaths)]) {
    try {
      const parsed = JSON.parse(await readFile(candidate, 'utf8')) as {
        mcpServers?: Record<string, unknown>
        servers?: Record<string, unknown>
      }
      const servers = parsed.mcpServers ?? parsed.servers ?? {}
      if (!servers || typeof servers !== 'object') continue
      configPaths.push(candidate)
      for (const [name, value] of Object.entries(servers)) {
        configuredServers[name] = value
        serverSources[name] = candidate
      }
    } catch {
      // Missing and non-JSON host configuration files are ignored.
    }
  }

  const chromeUrl = process.env.DSH_CTF_CHROME_MCP_URL?.trim()
  if (chromeUrl) {
    configuredServers['mcp-chrome'] = { url: chromeUrl }
    serverSources['mcp-chrome'] = 'DSH_CTF_CHROME_MCP_URL'
  }

  if (process.env.TAVILY_API_KEY?.trim()) {
    configuredServers['tavily-mcp'] = {
      command: 'npx',
      args: ['-y', 'tavily-mcp@latest'],
      env: { TAVILY_API_KEY: '[provided by environment]' },
    }
    serverSources['tavily-mcp'] = 'TAVILY_API_KEY'
  }

  return { configuredServers, serverSources, configPaths }
}

export async function configureCtfMcp(args: CtfMcpConfigureArgs = {}): Promise<CtfMcpConfigureResult> {
  const base = emptyResult()
  const configPath = resolveConfigPath(args.configPath)
  const includeChrome = args.includeChrome ?? true
  const includeTavily = args.includeTavily ?? true
  const requiredSecrets: string[] = []
  const configured: string[] = []

  let document: { mcpServers: Record<string, unknown> } = { mcpServers: {} }
  try {
    const parsed = JSON.parse(await readFile(configPath, 'utf8')) as { mcpServers?: Record<string, unknown> } | null
    document = {
      mcpServers: parsed?.mcpServers && typeof parsed.mcpServers === 'object' ? parsed.mcpServers : {},
    }
  } catch (error) {
    if (isMissingFile(error)) {
      document = { mcpServers: {} }
    } else {
      base.status = 'failed'
      base.limitations.push(`MCP config is not valid JSON: ${configPath}`)
      return { ...base, configPath, configured, requiredSecrets }
    }
  }

  if (includeChrome) {
    const chromeUrl = args.chromeUrl?.trim()
      || process.env.DSH_CTF_CHROME_MCP_URL?.trim()
      || 'http://127.0.0.1:12306/mcp'
    document.mcpServers['mcp-chrome'] = { url: chromeUrl }
    configured.push('mcp.chrome')
  }

  if (includeTavily) {
    const current = asServer(document.mcpServers['tavily-mcp'])
    const key = args.tavilyApiKey?.trim() || process.env.TAVILY_API_KEY?.trim() || current?.env?.TAVILY_API_KEY
    if (key && !isPlaceholder(key)) {
      document.mcpServers['tavily-mcp'] = {
        command: 'npx',
        args: ['-y', 'tavily-mcp@latest'],
        env: { TAVILY_API_KEY: key },
      }
      configured.push('mcp.tavily')
    } else {
      requiredSecrets.push('TAVILY_API_KEY')
      base.limitations.push('Tavily MCP needs TAVILY_API_KEY; provide only that key to ctf_mcp_configure.')
    }
  }

  await mkdir(path.dirname(configPath), { recursive: true })
  await writeFile(configPath, `${JSON.stringify(document, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
  await chmod(configPath, 0o600)
  base.observations.push(`CTF MCP configuration written to ${configPath}.`)
  base.observations.push(`configured servers: ${configured.length > 0 ? configured.join(', ') : 'none'}.`)
  base.status = requiredSecrets.length > 0 ? 'missing_capability' : 'ok'
  return { ...base, configPath, configured, requiredSecrets }
}

export function resolveConfigPath(configPath?: string): string {
  return configPath?.trim()
    || process.env.DSH_CTF_MCP_CONFIG?.trim()
    || process.env.CTF_MCP_CONFIG?.trim()
    || path.join(process.env.XDG_CONFIG_HOME?.trim() || path.join(os.homedir(), '.config'), 'dsh', 'ctf-mcp.json')
}

function asServer(value: unknown): { env?: Record<string, string> } | null {
  if (!value || typeof value !== 'object') return null
  const env = (value as { env?: unknown }).env
  if (!env || typeof env !== 'object') return {}
  return {
    env: Object.fromEntries(
      Object.entries(env).filter((entry): entry is [string, string] => typeof entry[1] === 'string'),
    ),
  }
}

function isPlaceholder(value: string): boolean {
  return value.startsWith('REPLACE_WITH_') || value === 'TAVILY_API_KEY'
}

function isMissingFile(error: unknown): boolean {
  return Boolean(error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT')
}
