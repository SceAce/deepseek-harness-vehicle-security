import { type ResolvedWorkspaceFile } from '../paths.js';
import { type CommandOptions } from '../process.js';
import { type CtfToolResultBase } from './types.js';
export type PwninitMode = 'prepare' | 'doctor' | 'restore' | 'list_backups';
export interface PwninitArgs {
    mode?: PwninitMode;
    libcPath?: string;
    ldPath?: string;
    dependencyDir?: string;
    libcVersion?: string;
    libcIndex?: number;
    onlyLibc?: boolean;
    onlyInit?: boolean;
    generateExp?: boolean;
    forceExp?: boolean;
    debug?: boolean;
}
export interface PwninitOptions extends CommandOptions {
    maxFileBytes?: number;
}
export interface CtfPwninitResult extends CtfToolResultBase {
    pwninit: {
        mode: PwninitMode;
        executable: string | null;
        binary: string;
        command: string[];
        selectedLibc: string | null;
        selectedLd: string | null;
        initializationOnly: boolean;
        beforeSha256: string | null;
        afterSha256: string | null;
        changed: boolean;
    };
}
export declare function runPwninit(file: ResolvedWorkspaceFile, args?: PwninitArgs, options?: PwninitOptions): Promise<CtfPwninitResult>;
//# sourceMappingURL=pwninit.d.ts.map