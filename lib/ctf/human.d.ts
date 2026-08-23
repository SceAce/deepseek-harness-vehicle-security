import { type CtfHumanRequest, type CtfToolResultBase } from './types.js';
export interface HumanRequestResult extends CtfToolResultBase {
    requestId: string;
    request: CtfHumanRequest;
}
export declare function createHumanRequest(request: CtfHumanRequest): HumanRequestResult;
//# sourceMappingURL=human.d.ts.map