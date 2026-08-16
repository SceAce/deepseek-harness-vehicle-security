import { type ResolvedWorkspaceFile } from './paths.js';
import { type CommandOptions } from './process.js';
export interface ArtifactTriageOptions extends CommandOptions {
    enableBinwalk?: boolean;
}
export interface ArtifactTriageResult {
    path: string;
    sizeBytes: number;
    sha256: string;
    sampleEntropy: number;
    fileType: string | null;
    binwalk: {
        ok: boolean;
        exitCode: number | null;
        output: string;
    } | null;
}
export declare function triageArtifact(file: ResolvedWorkspaceFile, options?: ArtifactTriageOptions): Promise<ArtifactTriageResult>;
//# sourceMappingURL=artifact.d.ts.map