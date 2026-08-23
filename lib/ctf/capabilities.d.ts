import { type CommandOptions } from '../process.js';
import { type CtfToolBinding, type ToolInvocationRecord } from './types.js';
export type CtfCapabilityCategory = 'core' | 're' | 'pwn' | 'crypto' | 'misc' | 'web';
export interface CapabilityProbe {
    id: string;
    category: CtfCapabilityCategory;
    executable: string;
    args: readonly string[];
    operations: string[];
    features?: string[];
}
export interface CtfCapability {
    id: string;
    category: CtfCapabilityCategory;
    executable: string;
    available: boolean;
    path: string | null;
    version: string | null;
    operations: string[];
    features: string[];
}
export interface PythonModuleProbe {
    module: string;
    importName: string;
    category: CtfCapabilityCategory;
    operations: string[];
}
export interface CtfToolAuditResult {
    schemaVersion: '1.0';
    available: number;
    missing: number;
    capabilities: CtfCapability[];
    python: {
        policy: 'fixed';
        requiredExecutable: string;
        executable: string | null;
        source: string | null;
        venv: string | null;
        bin: string | null;
        version: string | null;
        modules: CtfCapability[];
    };
    mcp: CtfMcpCapability[];
    toolBindings: CtfToolBinding[];
    commands: ToolInvocationRecord[];
    recommendations: string[];
}
export interface CtfMcpCapability {
    id: string;
    category: CtfCapabilityCategory;
    configured: boolean;
    configSource: string | null;
    command: string | null;
    operations: string[];
    limitation: string | null;
}
export declare function auditCtfTools(options?: CommandOptions): Promise<CtfToolAuditResult>;
export declare function hasCapability(audit: CtfToolAuditResult, id: string): boolean;
//# sourceMappingURL=capabilities.d.ts.map