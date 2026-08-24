import { type CtfArtifactProfile } from './artifact.js';
import type { ResolvedWorkspaceFile } from '../paths.js';
import { type CommandOptions } from '../process.js';
import { type CtfToolResultBase } from './types.js';
export interface BinaryFactSummary {
    format: 'elf' | 'pe' | 'macho' | 'script' | 'unknown';
    arch: string | null;
    entryPoint: string | null;
    protections: {
        pie: string;
        nx: string;
        relro: string;
        canary: string;
        stripped: string;
    };
    imports: string[];
    libcCandidates: string[];
    interestingStrings: Array<{
        offset: string;
        value: string;
        tags: string[];
    }>;
    checksec: string | null;
}
export interface CtfBinaryProfileResult extends CtfToolResultBase {
    artifact: CtfArtifactProfile;
    binary: BinaryFactSummary;
}
export declare function profileReArtifact(file: ResolvedWorkspaceFile, options?: CommandOptions): Promise<CtfBinaryProfileResult>;
export declare function profilePwnArtifact(file: ResolvedWorkspaceFile, options?: CommandOptions): Promise<CtfBinaryProfileResult>;
export declare function debugPwnArtifact(file: ResolvedWorkspaceFile, args: {
    argv?: string[];
    breakAt?: string;
    extraGdbCommands?: string[];
}, options?: CommandOptions): Promise<CtfToolResultBase & {
    debugger: {
        output: string | null;
    };
}>;
export declare function debugPwndbgArtifact(file: ResolvedWorkspaceFile, args: {
    argv?: string[];
    breakAt?: string;
    extraCommands?: string[];
}, options?: CommandOptions): Promise<CtfToolResultBase & {
    debugger: {
        output: string | null;
        frontend: 'pwndbg';
    };
}>;
export declare function searchRopGadgets(file: ResolvedWorkspaceFile, args: {
    query?: string;
    maxResults?: number;
}, options?: CommandOptions): Promise<CtfToolResultBase & {
    gadgets: string[];
}>;
//# sourceMappingURL=binary.d.ts.map