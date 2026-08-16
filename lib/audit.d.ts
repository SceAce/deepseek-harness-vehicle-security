import { type CommandOptions } from './process.js';
export interface ToolAuditRow {
    name: string;
    available: boolean;
    path: string | null;
    version: string | null;
}
export interface ToolAuditResult {
    available: number;
    missing: number;
    tools: ToolAuditRow[];
}
export declare function auditTools(options?: CommandOptions): Promise<ToolAuditResult>;
//# sourceMappingURL=audit.d.ts.map