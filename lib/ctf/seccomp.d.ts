import type { ResolvedWorkspaceFile } from '../paths.js';
import { type CommandOptions } from '../process.js';
import { type CtfToolResultBase } from './types.js';
export type SeccompDumpFormat = 'disasm' | 'raw' | 'inspect';
export interface SeccompProfileArgs {
    argv?: string[];
    format?: SeccompDumpFormat;
    limit?: number;
}
export interface SeccompProfileResult extends CtfToolResultBase {
    executable: string | null;
    target: {
        path: string;
        argv: string[];
    };
    dump: {
        format: SeccompDumpFormat;
        limit: number;
        rawOutput: string | null;
        rules: string[];
        syscalls: string[];
    };
}
export declare function profileSeccomp(file: ResolvedWorkspaceFile, args?: SeccompProfileArgs, options?: CommandOptions): Promise<SeccompProfileResult>;
//# sourceMappingURL=seccomp.d.ts.map