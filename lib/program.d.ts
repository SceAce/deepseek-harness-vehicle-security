import { type ArtifactTriageResult } from './artifact.js';
import { type ResolvedWorkspaceFile } from './paths.js';
import { type CommandOptions } from './process.js';
type Confidence = 'low' | 'medium' | 'high';
type ProtectionState = 'enabled' | 'disabled' | 'partial' | 'full' | 'unknown';
export interface ProgramAnalysisOptions extends CommandOptions {
    focus?: string;
    maxStrings?: number;
    minStringLength?: number;
}
export interface ProgramObservation {
    id: string;
    category: 'identity' | 'platform' | 'protection' | 'import' | 'string';
    statement: string;
    source: string;
    details: string[];
}
export interface ProgramConclusion {
    id: string;
    statement: string;
    confidence: Confidence;
    evidenceIds: string[];
    boundary: string;
}
export interface ProgramHypothesis {
    id: string;
    title: string;
    rationale: string;
    confidence: Confidence;
    evidenceIds: string[];
    validationStepIds: string[];
}
export interface ValidationCommand {
    program: string;
    args: string[];
}
export interface ProgramValidationStep {
    id: string;
    hypothesisIds: string[];
    tool: string;
    purpose: string;
    commands: ValidationCommand[];
    actions: string[];
    successCriteria: string[];
    evidenceToRecord: string[];
}
export interface ElfMetadata {
    class: string | null;
    data: string | null;
    type: string | null;
    machine: string | null;
    entryPoint: string | null;
    interpreter: boolean | null;
    protections: {
        pie: ProtectionState;
        nx: ProtectionState;
        relro: ProtectionState;
        stackCanary: ProtectionState;
        stripped: ProtectionState;
    };
}
export interface InterestingString {
    offset: string;
    value: string;
    tags: string[];
}
export interface ProgramAnalysisResult {
    objective: string;
    artifact: ArtifactTriageResult;
    format: 'elf' | 'pe' | 'macho' | 'script' | 'unknown';
    elf: ElfMetadata | null;
    imports: string[];
    interestingStrings: InterestingString[];
    observations: ProgramObservation[];
    conclusions: ProgramConclusion[];
    hypotheses: ProgramHypothesis[];
    validationSteps: ProgramValidationStep[];
    limitations: string[];
}
export declare function analyzeProgram(file: ResolvedWorkspaceFile, options?: ProgramAnalysisOptions): Promise<ProgramAnalysisResult>;
export declare function parseElfMetadata(header: string, programHeaders: string, dynamic: string, symbols: string, fileType: string | null): ElfMetadata;
export declare function parseUndefinedSymbols(symbols: string): string[];
export declare function classifyStrings(output: string, maxStrings?: number): InterestingString[];
export declare function buildValidationPlan(relativePath: string, imports: string[], strings: InterestingString[], observations: ProgramObservation[]): {
    hypotheses: ProgramHypothesis[];
    validationSteps: ProgramValidationStep[];
};
export {};
//# sourceMappingURL=program.d.ts.map