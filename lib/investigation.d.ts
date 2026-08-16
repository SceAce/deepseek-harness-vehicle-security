import { type ArtifactTriageResult } from './artifact.js';
import type { ResolvedWorkspaceFile } from './paths.js';
import type { CommandOptions } from './process.js';
export type InvestigationInputKind = 'artifact' | 'prompt' | 'lab';
export type InvestigationLane = 'can-uds' | 'network-protocol' | 'firmware' | 'native-program' | 'android' | 'web-api' | 'hardware-rf' | 'unknown';
export interface InvestigationInput {
    objective: string;
    inputKind?: InvestigationInputKind;
    context?: string;
}
export interface InvestigationPlanOptions extends CommandOptions {
    enableBinwalk?: boolean;
}
export interface LaneCandidate {
    lane: InvestigationLane;
    score: number;
    reasons: string[];
}
export interface InvestigationAction {
    id: string;
    phase: string;
    tool: string;
    purpose: string;
    expectedSignal: string;
    nextIfPositive: string;
    nextIfNegative: string;
}
export interface InvestigationPlan {
    schemaVersion: '1.0';
    caseId: string;
    objective: string;
    inputKind: InvestigationInputKind;
    artifact: ArtifactTriageResult | null;
    selectedLane: InvestigationLane;
    laneCandidates: LaneCandidate[];
    phases: Array<{
        id: string;
        name: string;
        exitCriteria: string[];
    }>;
    firstActions: InvestigationAction[];
    languagePlan: Array<{
        language: string;
        useFor: string;
        avoidFor: string;
    }>;
    dataPlan: {
        directories: string[];
        stateFile: string;
        namingRule: string;
        preservationRule: string;
    };
    evidenceModel: {
        prefixes: Record<string, string>;
        promotionRule: string;
    };
    stopConditions: string[];
    limitations: string[];
}
export declare function planInvestigation(input: InvestigationInput, file?: ResolvedWorkspaceFile | null, options?: InvestigationPlanOptions): Promise<InvestigationPlan>;
//# sourceMappingURL=investigation.d.ts.map