import { type CtfArtifactProfile } from './artifact.js';
import type { ResolvedWorkspaceFile } from '../paths.js';
import { type CommandOptions } from '../process.js';
import { type CtfToolResultBase } from './types.js';
export interface CtfPlatformProfileResult extends CtfToolResultBase {
    platform: 'windows' | 'android' | 'multiarch';
    artifact: CtfArtifactProfile;
    tools: Array<{
        name: string;
        executable: string | null;
        available: boolean;
        output: string | null;
    }>;
    architecture: string | null;
}
export interface CtfPlatformExecResult extends CtfToolResultBase {
    platform: 'android' | 'multiarch';
    executable: string | null;
    argv: string[];
    output: string | null;
    outputDir?: string | null;
    files?: string[];
}
export declare function profilePeArtifact(file: ResolvedWorkspaceFile, options?: CommandOptions): Promise<CtfPlatformProfileResult>;
export declare function profileAndroidArtifact(file: ResolvedWorkspaceFile, options?: CommandOptions): Promise<CtfPlatformProfileResult>;
export declare function profileMultiarchArtifact(file: ResolvedWorkspaceFile, options?: CommandOptions): Promise<CtfPlatformProfileResult>;
export declare function decompileAndroidArtifact(file: ResolvedWorkspaceFile, options?: CommandOptions): Promise<CtfPlatformExecResult>;
export declare function executeMultiarchArtifact(file: ResolvedWorkspaceFile, args: {
    architecture?: 'arm' | 'aarch64';
    argv?: string[];
}, options?: CommandOptions): Promise<CtfPlatformExecResult>;
//# sourceMappingURL=replatforms.d.ts.map