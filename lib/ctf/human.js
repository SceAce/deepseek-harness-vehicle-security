import { createHash } from 'node:crypto';
import { emptyResult } from './types.js';
export function createHumanRequest(request) {
    const base = emptyResult('human_required');
    const requestId = `human-${createHash('sha256').update(JSON.stringify(request)).digest('hex').slice(0, 12)}`;
    base.humanRequired.push(request);
    base.observations.push(`human action requested: ${request.title}`);
    return {
        ...base,
        requestId,
        request,
    };
}
//# sourceMappingURL=human.js.map