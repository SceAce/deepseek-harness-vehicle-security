import { type CtfArtifactProfile } from './artifact.js';
import type { ResolvedWorkspaceFile } from '../paths.js';
import { type CtfToolResultBase } from './types.js';
export interface CryptoProbeResult extends CtfToolResultBase {
    artifact: CtfArtifactProfile | null;
    input: {
        length: number;
        entropy: number;
        sha256: string;
    };
    encodings: Array<{
        type: string;
        confidence: string;
        decodedPreview?: string;
    }>;
    xorCandidates: Array<{
        key: string;
        score: number;
        preview: string;
    }>;
}
export declare function probeCryptoInput(input: {
    file?: ResolvedWorkspaceFile;
    text?: string;
}): Promise<CryptoProbeResult>;
//# sourceMappingURL=crypto.d.ts.map