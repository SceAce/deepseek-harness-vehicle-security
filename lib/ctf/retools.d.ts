import { type ResolvedWorkspaceFile } from '../paths.js';
import { type CommandOptions } from '../process.js';
import { type CtfToolResultBase } from './types.js';
export interface R2QueryResult extends CtfToolResultBase {
    executable: string | null;
    query: {
        commands: string[];
    };
    rawOutput: string | null;
    json: unknown | null;
}
export interface IdaScriptPlanResult extends CtfToolResultBase {
    executable: string | null;
    launcher: {
        executable: string;
        argv: string[];
    };
    script: string;
    executed: boolean;
    analysisOutput: string | null;
    scriptPath: string | null;
}
export declare function queryRadare2(file: ResolvedWorkspaceFile, commands: string[], options?: CommandOptions): Promise<R2QueryResult>;
export declare function buildIdaScriptPlan(file: ResolvedWorkspaceFile, focus: string, execute?: boolean, options?: CommandOptions): Promise<IdaScriptPlanResult>;
//# sourceMappingURL=retools.d.ts.map