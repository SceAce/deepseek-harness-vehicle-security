import { type CtfArtifactProfile } from './artifact.js';
import { type ResolvedWorkspaceFile } from '../paths.js';
import { type CommandOptions } from '../process.js';
import { type CtfToolResultBase } from './types.js';
export interface MiscTriageResult extends CtfToolResultBase {
    artifact: CtfArtifactProfile;
    toolOutputs: Record<string, string | null>;
}
export declare function triageMiscArtifact(file: ResolvedWorkspaceFile, options?: CommandOptions): Promise<MiscTriageResult>;
export declare function profilePcapArtifact(file: ResolvedWorkspaceFile, options?: CommandOptions): Promise<MiscTriageResult>;
//# sourceMappingURL=misc.d.ts.map