import { type CtfHumanOperation, type CtfHumanRequest, type CtfHumanReturnType, type CtfToolResultBase } from './types.js';
export interface HumanRequestResult extends CtfToolResultBase {
    requestId: string;
    request: CtfHumanRequest;
}
export declare function createHumanRequest(request: CtfHumanRequest): HumanRequestResult;
export declare function makeHumanRequest(input: Omit<CtfHumanRequest, 'acceptedReturnTypes' | 'returnContract'> & {
    acceptedReturnTypes?: CtfHumanReturnType[];
    returnFields?: Record<string, string>;
}): CtfHumanRequest;
export declare function operationsFromLegacySteps(steps: string[]): CtfHumanOperation[];
//# sourceMappingURL=human.d.ts.map