import { createHash } from 'node:crypto';
import { emptyResult } from './types.js';
export function createHumanRequest(request) {
    const normalized = normalizeHumanRequest(request);
    const base = emptyResult('human_required');
    const requestId = `human-${createHash('sha256').update(JSON.stringify(normalized)).digest('hex').slice(0, 12)}`;
    base.humanRequired.push(normalized);
    base.observations.push(`human action requested: ${normalized.title}`);
    return {
        ...base,
        requestId,
        request: normalized,
    };
}
export function makeHumanRequest(input) {
    const acceptedReturnTypes = input.acceptedReturnTypes ?? ['log', 'screenshot', 'ocr_text'];
    return normalizeHumanRequest({
        ...input,
        acceptedReturnTypes,
        returnContract: {
            onlyReturn: acceptedReturnTypes,
            format: 'plain_text',
            fields: input.returnFields ?? {
                log: 'terminal output or service log text',
                screenshot: 'path or pasted text describing the screenshot',
                ocr_text: 'text recognized from the screenshot or GUI',
            },
        },
    });
}
export function operationsFromLegacySteps(steps) {
    return steps.map((step, index) => ({
        order: index + 1,
        kind: looksLikeCommand(step) ? 'command' : 'instruction',
        title: `Step ${index + 1}`,
        ...(looksLikeCommand(step)
            ? { command: step.replace(/^[$#]\s*/, '') }
            : { instruction: step }),
        expectedSignal: 'Return log, screenshot text, or OCR text that shows the result of this step.',
    }));
}
function normalizeHumanRequest(request) {
    const rawOperations = request.operationOrder.length > 0
        ? request.operationOrder.map((operation, index) => ({
            ...operation,
            order: operation.order > 0 ? operation.order : index + 1,
        }))
        : operationsFromLegacySteps(request.legacySteps ?? []);
    const operationOrder = rawOperations
        .sort((left, right) => left.order - right.order)
        .map((operation, index) => ({ ...operation, order: index + 1 }));
    const acceptedReturnTypes = request.acceptedReturnTypes.length > 0
        ? request.acceptedReturnTypes
        : ['log', 'screenshot', 'ocr_text'];
    for (const returnType of acceptedReturnTypes) {
        if (returnType !== 'log' && returnType !== 'screenshot' && returnType !== 'ocr_text') {
            throw new Error('human return types must be log, screenshot, or ocr_text');
        }
    }
    return {
        ...request,
        operationOrder,
        acceptedReturnTypes,
        returnContract: {
            onlyReturn: acceptedReturnTypes,
            format: request.returnContract.format,
            fields: request.returnContract.fields,
        },
        legacySteps: request.legacySteps ?? operationOrder.map(operation => operation.command ?? operation.instruction ?? operation.title),
    };
}
function looksLikeCommand(step) {
    const normalized = step.trim().replace(/^[$#]\s*/, '');
    return [
        'cd ', 'npm ', 'pnpm ', 'python ', 'python3 ', 'node ', 'docker ', 'make ', 'cargo ', 'go ',
        'curl ', 'nc ', 'ncat ', 'socat ', 'java ', 'bash ', 'sh ', 'python -c', 'python3 -c',
        '/home/source/tools/PyVenv/CTF/bin/python ',
    ].some(prefix => normalized.startsWith(prefix)) || /^[A-Z_]+=/.test(normalized);
}
//# sourceMappingURL=human.js.map