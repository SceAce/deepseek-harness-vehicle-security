import { type CommandOptions } from '../process.js';
import { type CtfToolResultBase } from './types.js';
export interface HttpRequestArgs {
    url: string;
    method?: string;
    headers?: string[];
    body?: string;
    followRedirects?: boolean;
    maxTimeSeconds?: number;
}
export interface HttpRequestResult extends CtfToolResultBase {
    request: HttpRequestArgs;
    response: {
        statusCode: number | null;
        headerBytes: number;
        bodyBytes: number;
        bodySha256: string;
        preview: string;
    } | null;
}
export declare function httpRequest(args: HttpRequestArgs, options?: CommandOptions): Promise<HttpRequestResult>;
export declare function httpDiff(args: {
    urlA: string;
    urlB: string;
    method?: string;
    headers?: string[];
    bodyA?: string;
    bodyB?: string;
}, options?: CommandOptions): Promise<CtfToolResultBase & {
    left: HttpRequestResult;
    right: HttpRequestResult;
    diff: Record<string, unknown>;
}>;
//# sourceMappingURL=web.d.ts.map