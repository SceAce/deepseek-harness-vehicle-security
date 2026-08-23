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
    toolGraph: CtfToolGraph;
    nextActions: CtfNextAction[];
    humanRequired: CtfHumanRequest[];
}
export interface CtfToolGraph {
    category: ResolvedCtfCategory;
    entry: string;
    nodes: Array<{
        tool: string;
        role: string;
        when: string;
    }>;
    edges: Array<{
        from: string;
        to: string;
        condition: string;
    }>;
}
export declare function routeCtfStart(input: CtfStartInput, artifact: CtfArtifactProfile | null, audit: CtfToolAuditResult): CtfRouteDecision;
export declare function toolGraphForCategory(category: ResolvedCtfCategory): CtfToolGraph;
//# sourceMappingURL=router.d.ts.map