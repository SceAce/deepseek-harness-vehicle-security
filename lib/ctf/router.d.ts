import type { CtfArtifactProfile } from './artifact.js';
import type { CtfToolAuditResult } from './capabilities.js';
import type { CtfCategory, CtfHumanRequest, CtfNextAction, ResolvedCtfCategory } from './types.js';
export interface CtfStartInput {
    objective?: string;
    category?: CtfCategory;
    path?: string;
    url?: string;
    context?: string;
}
export interface CtfRouteDecision {
    category: ResolvedCtfCategory;
    reasons: string[];
    recommendedTool: string;
    recommendedArgs: Record<string, unknown>;
    nextActions: CtfNextAction[];
    humanRequired: CtfHumanRequest[];
}
export declare function routeCtfStart(input: CtfStartInput, artifact: CtfArtifactProfile | null, audit: CtfToolAuditResult): CtfRouteDecision;
//# sourceMappingURL=router.d.ts.map