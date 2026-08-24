import { type ResolvedWorkspaceFile } from '../paths.js';
import { type CommandOptions } from '../process.js';
import { type CtfToolResultBase } from './types.js';
export interface OneGadgetArgs {
    libcPath?: string;
    level?: number;
    near?: string;
    raw?: boolean;
    maxResults?: number;
}
export interface OneGadgetResult extends CtfToolResultBase {
    executable: string | null;
    anchor: string;
    target: {
        path: string | null;
        source: 'explicit' | 'anchor' | 'sibling' | 'none';
    };
    options: {
        level: number;
        near: string | null;
        raw: boolean;
        maxResults: number;
    };
    rawOutput: string | null;
    gadgets: Array<{
        offset: string;
        invocation: string | null;
        constraints: string[];
    }>;
}
export interface OneGadgetOptions extends CommandOptions {
    maxFileBytes?: number;
}
export declare function searchOneGadgets(file: ResolvedWorkspaceFile, args?: OneGadgetArgs, options?: OneGadgetOptions): Promise<OneGadgetResult>;
//# sourceMappingURL=one-gadget.d.ts.map