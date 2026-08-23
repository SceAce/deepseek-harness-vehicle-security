import type { ResolvedWorkspaceFile } from '../paths.js';
import { type CommandOptions } from '../process.js';
import { type ToolInvocationRecord } from './types.js';
export interface CtfArtifactProfile {
    path: string;
    extension: string;
    basename: string;
    sizeBytes: number;
    sha256: string;
    sampleEntropy: number;
    fileType: string | null;
    magic: string;
    textSample: string | null;
}
export interface CtfArtifactProfileResult {
    artifact: CtfArtifactProfile;
    commands: ToolInvocationRecord[];
    observations: string[];
    limitations: string[];
}
export declare function profileCtfArtifact(file: ResolvedWorkspaceFile, options?: CommandOptions): Promise<CtfArtifactProfileResult>;
//# sourceMappingURL=artifact.d.ts.map