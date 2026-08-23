import { type CtfToolResultBase } from './types.js';
export interface CtfMcpDiscovery {
    configuredServers: Record<string, unknown>;
    serverSources: Record<string, string>;
    configPaths: string[];
}
export interface CtfMcpConfigureResult extends CtfToolResultBase {
    configPath: string;
    configured: string[];
    requiredSecrets: string[];
}
export interface CtfMcpConfigureArgs {
    configPath?: string;
    chromeUrl?: string;
    includeChrome?: boolean;
    includeTavily?: boolean;
    tavilyApiKey?: string;
}
export declare function discoverCtfMcpConfiguration(cwd?: string): Promise<CtfMcpDiscovery>;
export declare function configureCtfMcp(args?: CtfMcpConfigureArgs): Promise<CtfMcpConfigureResult>;
export declare function resolveConfigPath(configPath?: string): string;
//# sourceMappingURL=mcp.d.ts.map